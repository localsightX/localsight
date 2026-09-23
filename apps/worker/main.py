"""AI/video worker.

Runs the per-camera pipelines. Each camera gets its own gateway + pipeline in its
own thread, so one camera stalling never takes down the others.

Inbound frames come from the lowest-resolution substream by default (bandwidth/
GPU efficiency). The *main* stream is recorded by a per-camera Recorder into
segmented, seekable clips. Behavior-analytics rules and ANPR (if configured) are
evaluated per frame and turned into point-in-time events, which are then fanned
out to the configured alert channels.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import os
import queue
import signal
import threading
import time
from collections.abc import Callable

from apps.api.bootstrap import build
from apps.api.config import Settings
from packages.ai.anpr import build_anpr
from packages.ai.attributes import build_attribute_tagger
from packages.ai.detectors import build_detector
from packages.ai.face import ReferenceEmbedder, ReferenceFaceDetector
from packages.ai.interfaces import Detector
from packages.ai.matcher import VectorMatcher
from packages.ai.pipeline import CameraPipeline
from packages.ai.rules import rule_engine_from_json
from packages.ai.tracker import IouTracker
from packages.domain import timeutil
from packages.domain.alertcount import count_alerts_today
from packages.domain.lane import (
    DECISION_BARRIER_UNAVAILABLE,
    DECISION_GRANTED,
    GateDecision,
    decide_gate_access,
    pipeline_flag_enabled,
)
from packages.domain.models import (
    PIPELINE_FLAG_LANE_ACCESS,
    AlertRoute,
    AuditLog,
    Camera,
    Event,
    Lane,
    LaneWhitelistEntry,
    PersonEmbedding,
    RefreshToken,
    Snapshot,
    VideoSegment,
)
from packages.notify import (
    Alert,
    Notifier,
    PushNotifier,
    WebhookNotifier,
    build_notifier,
    dispatch,
)
from packages.notify.budget import DailyAlertBudget
from packages.observability import disk
from packages.observability.logging import configure_logging, logging
from packages.observability.metrics import metrics
from packages.security.errors import UnsafeUrlError
from packages.security.ssrf import validate_egress_url
from packages.video.gateway import StreamGateway
from packages.video.recorder import Recorder
from packages.video.sources import FFmpegFrameSource, SyntheticFrameSource

log = logging.getLogger("localsight.worker")


# ── alert routing (reads AlertRoute from the DB) ─────────────────────────────
_route_cache: dict = {"at": 0.0, "routes": []}


class CooldownTracker:
    """Per-route alert suppression to prevent storms.

    A route with ``cooldown_sec > 0`` will not re-fire the same channel for the
    same ``(rule_type, camera_id)`` until the window elapses. Keys are independent
    per (channel, rule_type, camera_id) so two routes that overlap don't share a
    window unless they're configured identically.
    """

    def __init__(self, now: Callable[[], float] = time.time) -> None:
        self._last: dict = {}
        self._now = now

    def is_in_cooldown(self, key: tuple, cooldown_sec: int) -> bool:
        if cooldown_sec <= 0:
            return False
        return (self._now() - self._last.get(key, 0.0)) < cooldown_sec

    def record(self, key: tuple) -> None:
        self._last[key] = self._now()


_cooldown = CooldownTracker()


def _load_routes(rt) -> list:
    """Cache alert routes (plus the env-webhook fallback) for ~30s to avoid a DB
    round-trip on every analytic event."""
    now = time.time()
    if now - _route_cache["at"] < 30 and _route_cache["routes"]:
        return _route_cache["routes"]
    routes: list = []
    try:
        with rt.SessionLocal() as s:
            for r in s.query(AlertRoute).filter_by(enabled=True).all():
                cfg = (r.config_enc and rt.crypto.decrypt_json(r.config_enc)) or {}
                routes.append((r.channel, cfg, r.rule_type, r.camera_id, r.cooldown_sec))
    except Exception as exc:
        log.warning("failed to load alert routes: %s", exc)
    env_webhook = os.environ.get("ALERT_WEBHOOK_URL")
    if env_webhook:
        routes.append(("webhook", {"url": env_webhook}, "*", None, 0))
    _route_cache["routes"] = routes
    _route_cache["at"] = now
    return routes


def _build_notifiers(rt, alert: Alert) -> list:
    """Select notifiers for an alert per configured routes; always capture in-process.

    The reference PushNotifier() (in-process buffer) is only added when no push
    *route* matched — otherwise every push alert would be captured twice. The
    cooldown is recorded only after the notifier was successfully constructed,
    so a config error doesn't silently consume the cooldown window.
    """
    notifiers: list = []
    push_route_matched = False
    for channel, cfg, rule_type, camera_id, cooldown_sec in _load_routes(rt):
        if rule_type not in ("*", alert.rule_type):
            continue
        if camera_id and camera_id != alert.camera_id:
            continue
        cd_key = (channel, rule_type, camera_id)
        if _cooldown.is_in_cooldown(cd_key, cooldown_sec):
            log.debug("suppressed by cooldown: %s %s cam=%s", channel, rule_type, camera_id)
            continue
        built = None
        if channel == "webhook":
            url = cfg.get("url")
            if not url:
                continue
            try:
                validate_egress_url(url, allowlist=rt.settings.ssrf_allowlist_cidrs)
            except UnsafeUrlError:
                log.warning("skipping unvalidated webhook route for %s", alert.rule_type)
                continue
            built = WebhookNotifier(url)
        else:
            try:
                built = build_notifier(channel, cfg)
            except Exception as exc:
                log.warning("skipping %s route: %s", channel, exc)
        if built is None:
            continue
        if channel == "push":
            push_route_matched = True
        notifiers.append(built)
        _cooldown.record(cd_key)
    if not push_route_matched:
        notifiers.append(PushNotifier())  # in-process capture fallback
    return notifiers


_alert_queue: queue.Queue = queue.Queue()


def enqueue_analytic_alerts(analytics, camera_id: str, budget=None,
                            put=_alert_queue.put) -> int:
    """Fan point-in-time analytic events out to the alert queue (R3.6).

    Returns how many alerts were enqueued. The daily budget gates
    *notifications*: once a camera's budget is spent, further alerts are
    suppressed (counted + logged) while the analytic events stay stored —
    evidence is never a budget item.

    Lives outside the frame loop so the gate is unit-testable without running a
    camera: ``put`` is injectable and ``analytics`` is any iterable of events.
    """
    enqueued = 0
    for ae in analytics:
        if budget is not None and not budget.allow(camera_id):
            metrics.inc("alerts_budget_suppressed_total", labels=f'camera="{camera_id}"')
            log.warning("daily alert budget spent for %s (%s/day) - suppressing "
                        "notification; event evidence is still stored",
                        camera_id, budget.limit_per_day)
            continue
        alert = Alert(rule_id=ae.track_id or ae.event_type, rule_type=ae.event_type,
                      camera_id=ae.camera_id, title=ae.event_type,
                      message=str(_safe_alert_detail(ae.detail)),
                      detail=_safe_alert_detail(ae.detail),
                      ts=ae.timestamp_start.isoformat() if ae.timestamp_start else None)
        try:
            put(alert)
            enqueued += 1
        except Exception:
            log.exception("alert enqueue failed for %s", camera_id)
    return enqueued


def _alert_sender(rt, stop: threading.Event) -> None:
    """Drain the alert queue and fan out off the hot frame-processing path."""
    while not stop.is_set():
        try:
            alert = _alert_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            dispatch(alert, _build_notifiers(rt, alert))
        except Exception:
            log.exception("alert dispatch failed")


def _retention_loop(rt, stop: threading.Event) -> None:
    monitor = make_disk_monitor(rt)
    while not stop.is_set():
        try:
            _sweep_retention(rt)
        except Exception as exc:
            log.warning("retention sweep failed: %s", exc)
        # Disk pressure is checked on the same hourly cadence as the sweep that
        # reclaims the space (reliability plan F3). A failing check must never
        # kill the loop — the alarm is the last line of defence, not a
        # replacement for retention.
        try:
            _check_disk_pressure(rt, monitor)
        except Exception as exc:
            log.warning("disk pressure check failed: %s", exc)
        stop.wait(3600)


def make_disk_monitor(rt):
    """Monitor the volume that backs local media storage (None path = remote).

    Object storage (S3) has no local volume to watch, so the monitor reports
    "unknown" and stays silent rather than claiming a healthy disk it cannot
    see. Thresholds come from settings so an operator can tune them per site.
    """
    from packages.observability.disk import DiskPressureMonitor

    settings = rt.settings
    # `local_volume_path` is the volume media actually lands on: the recordings
    # root for local storage, None for object storage. This previously read
    # `getattr(rt.storage, "root", None)`, but LocalFilesystemStorage keeps the
    # path in `_root` — so the attribute never existed, the path was always
    # None, and the monitor reported "no local volume" on the very backend that
    # owns one: disk pressure was unobservable in every shipped deployment.
    path = getattr(rt.storage, "local_volume_path", None) or None
    if path is None:
        log.info("disk pressure monitoring inactive: storage backend has no local volume")
    return DiskPressureMonitor(
        path,
        warn=getattr(settings, "disk_warn_pct", 0.80),
        critical=getattr(settings, "disk_critical_pct", 0.90),
    )


def _check_disk_pressure(rt, monitor, emit: Callable | None = None) -> Alert | None:
    """Sample disk usage; enqueue ONE alert per level change. Returns it too.

    `emit` is injectable so the behaviour (alert-once-per-crossing, severity
    mapping, metric emission) is testable without a live alert sender.
    """
    level, ratio = monitor.poll()
    if ratio is not None:
        metrics.set("disk_used_ratio", ratio)
    metrics.set("disk_pressure_level",
                {disk.OK: 0.0, disk.WARNING: 1.0, disk.CRITICAL: 2.0}.get(level, 0.0))
    changed = monitor.take_alert()
    if changed is None or changed == disk.OK:
        # Recovery is logged, not alerted: an operator told "critical" should
        # hear that it cleared, but a green disk is not an incident.
        if changed == disk.OK:
            log.info("disk pressure cleared (usage %.1f%%)", (ratio or 0.0) * 100.0)
        return None
    pct = (ratio or monitor.last_ratio or 0.0) * 100.0
    alert = Alert(
        rule_id="system.disk",
        rule_type="disk_pressure",
        camera_id="",  # site-level, not camera-scoped
        severity="critical" if changed == disk.CRITICAL else "warning",
        title=f"storage {changed}",
        message=(
            f"media volume is {pct:.0f}% full — retention sweeps will start "
            f"failing to reclaim space; free space or shorten retention"
        ),
        detail={"used_pct": round(pct, 1), "level": changed},
    )
    log.warning("disk pressure %s: %.0f%% full", changed, pct)
    (emit or _alert_queue.put)(alert)
    return alert


def _sweep_retention(rt) -> None:
    """Delete expired data per the configured retention policies.

    Enforces every declared knob (recordings, events, snapshots, enrollment
    embeddings, audit trail) plus expired refresh tokens, in short chunked
    transactions so the sweep never holds long locks on PostgreSQL. Storage
    objects (recordings, snapshots) are removed best-effort before their rows;
    a failed storage delete logs and still drops the row so the DB never
    re-attempts it forever.
    """
    settings = rt.settings
    now = dt.datetime.now(dt.UTC)

    def _ts(days: float) -> dt.datetime:
        return now - dt.timedelta(days=days)

    with rt.SessionLocal() as s:
        # ── recordings (chunked; storage delete best-effort) ──────────────
        rec_cut = _ts(settings.retention_recordings_days)
        while True:
            segs = (
                s.query(VideoSegment)
                .filter(VideoSegment.end_ts < rec_cut)
                .limit(_SWEEP_CHUNK)
                .all()
            )
            if not segs:
                break
            for seg in segs:
                try:
                    rt.storage.delete(seg.storage_key)
                except Exception as exc:
                    log.warning("storage delete failed for %s: %s", seg.storage_key, exc)
                s.delete(seg)
            s.commit()

        # ── events (bulk, chunked) ─────────────────────────────────────────
        # SQLAlchemy 2.0 rejects Query.delete() after .limit(); select the
        # PK chunk first, then delete by primary key (same chunking/locking
        # intent, works on SQLite and PostgreSQL).
        ev_cut = _ts(settings.retention_events_days)
        while True:
            ev_ids = [r[0] for r in s.query(Event.id)
                      .filter(Event.timestamp_end < ev_cut)
                      .limit(_SWEEP_CHUNK).all()]
            if not ev_ids:
                break
            deleted = (s.query(Event)
                       .filter(Event.id.in_(ev_ids))
                       .with_for_update()
                       .delete(synchronize_session=False))
            s.commit()
            if not deleted:
                break

        # ── snapshots (storage delete best-effort, then row) ───────────────
        snap_cut = _ts(settings.retention_snapshots_days)
        while True:
            snaps = (
                s.query(Snapshot)
                .filter(Snapshot.created_at < snap_cut)
                .limit(_SWEEP_CHUNK)
                .all()
            )
            if not snaps:
                break
            for snap in snaps:
                try:
                    rt.storage.delete(rt.crypto.decrypt_str(snap.storage_key_enc))
                except Exception as exc:
                    log.warning("snapshot storage delete failed: %s", exc)
                s.delete(snap)
            s.commit()

        # ── enrollment embeddings (biometric data lifecycle) ───────────────
        emb_cut = _ts(settings.retention_embeddings_days)
        while True:
            emb_ids = [r[0] for r in s.query(PersonEmbedding.id)
                       .filter(PersonEmbedding.created_at < emb_cut)
                       .limit(_SWEEP_CHUNK).all()]
            if not emb_ids:
                break
            deleted = (s.query(PersonEmbedding)
                       .filter(PersonEmbedding.id.in_(emb_ids))
                       .with_for_update()
                       .delete(synchronize_session=False))
            s.commit()
            if not deleted:
                break

        # ── audit trail (bounded per RETENTION_AUDIT_DAYS) ────────────────
        audit_cut = _ts(settings.retention_audit_days)
        while True:
            aud_ids = [r[0] for r in s.query(AuditLog.id)
                       .filter(AuditLog.ts < audit_cut)
                       .limit(_SWEEP_CHUNK).all()]
            if not aud_ids:
                break
            deleted = (s.query(AuditLog)
                       .filter(AuditLog.id.in_(aud_ids))
                       .with_for_update()
                       .delete(synchronize_session=False))
            s.commit()
            if not deleted:
                break

        # ── expired refresh tokens ─────────────────────────────────────────
        while True:
            rt_ids = [r[0] for r in s.query(RefreshToken.id)
                      .filter(RefreshToken.expires_at < now)
                      .limit(_SWEEP_CHUNK).all()]
            if not rt_ids:
                break
            deleted = (s.query(RefreshToken)
                       .filter(RefreshToken.id.in_(rt_ids))
                       .with_for_update()
                       .delete(synchronize_session=False))
            s.commit()
            if not deleted:
                break


# Rows removed per transaction during retention sweeps. Small on purpose:
# each chunk commits and releases locks so concurrent API traffic is never
# blocked behind a full-hour table scan.
_SWEEP_CHUNK = 500


def make_detector(settings: Settings, registry) -> Detector:
    """Build the configured Detector. Fails closed: a misconfigured or integrity-
    failing staged model backend raises instead of silently degrading to a
    non-functional detector, so operators get a clear health signal rather than a
    false sense of safety."""
    return build_detector(settings, registry)


def make_face_chain(settings: Settings, registry):
    """Build the face detection+embedding chain for identity recognition.

    Staged SCRFD+ArcFace models (registry-verified) when present; the
    deterministic reference chain otherwise. Unlike the object detector, a
    missing face model DOWNGRADES (with a log) rather than failing closed:
    identity recognition is an optional capability, and the reference chain
    keeps the enroll→recognize loop exercisable without staged weights.
    """
    if settings.ai_identity_recognition_enabled:
        try:
            from packages.ai.face_onnx import build_face_chain as staged_chain

            return staged_chain(registry)
        except Exception as exc:  # noqa: BLE001 - downgrade, not a crash
            log.warning(
                "identity recognition falling back to reference chain "
                "(staged face models unavailable: %s)", exc,
            )
    return (ReferenceFaceDetector(), ReferenceEmbedder())


def make_anpr(settings: Settings, registry):
    """ANPR chain for a camera pipeline: None when the feature is off; the
    staged ONNX plate-detector+OCR when verified; the reference chain (logged
    downgrade) when enabled but unstaged. Never raises — ANPR is optional."""
    return build_anpr(registry, enabled=settings.ai_anpr_enabled, conf_thr=0.6)


def make_attribute_tagger(settings: Settings, registry):
    """Clothing-attribute tagger (jacket/hi-vis/colors): staged CLIP zero-shot
    encoder + prompt embeddings when verified; deterministic reference tagger
    (logged downgrade) otherwise; None when the feature is off."""
    return build_attribute_tagger(registry, enabled=settings.ai_attributes_enabled)


def build_make_source(camera: Camera, settings: Settings, crypto,
                      allowlist: list[str] | None = None):
    sub_url = camera.substream_url_enc
    if sub_url:
        plain = crypto.decrypt_str(sub_url)

        def make():
            return FFmpegFrameSource(
                plain, width=640, height=360, fps=settings.ai_inference_fps,
                allowlist=allowlist,
            )
        return make
    return lambda: SyntheticFrameSource(fps=settings.ai_inference_fps)


# Detail keys safe to serialize to third-party channels (webhook/email/MQTT).
# Never includes ciphertext (plate_enc) or anything derived from biometrics;
# consumers get the minimal operational context only. `attributes` carries
# non-biometric appearance tags (jacket/color) — operational context, safe.
_ALERT_DETAIL_KEYS = ("direction", "dwell_sec", "count", "zone", "stationary_sec",
                      "attributes")


def _safe_alert_detail(detail: dict | None) -> dict:
    if not detail:
        return {}
    return {k: detail[k] for k in _ALERT_DETAIL_KEYS if k in detail}


# ── gate access (R4.1): plate read → whitelist join → window → barrier ────────
#
# A camera whose `pipeline_flags.lane_access` is on is treated as an access-
# control point: each plate the ANPR stage reads is matched against the lane's
# keyed-HMAC whitelist and, only on a match inside the allow window, exactly one
# barrier OPEN command is issued. Deny-by-default (packages.domain.lane.
# decide_gate_access): a miss / outside-window / disabled lane is recorded as an
# event and NEVER reaches the relay. The barrier is a privileged side effect —
# its destination is envelope-encrypted at rest and re-validated against the SSRF
# policy at send time, and its payload is filtered to the third-party-safe detail
# keys so plate material (ciphertext or digest) never leaves the host.


class GateCooldown:
    """Per-(lane, plate) barrier command idempotency.

    A lane's ``cooldown_sec`` suppresses a second OPEN for the same plate inside
    the window: one command per vehicle passage, not one per re-read of the same
    plate (ANPR re-reads on a throttle). Event timestamps — not wall-clock time
    — drive the window, so suppression is deterministic under a replay/test feed
    and unaffected by a stall in the frame loop.
    """

    def __init__(self) -> None:
        self._last: dict[tuple[str, str], dt.datetime] = {}

    def is_suppressed(self, key: tuple[str, str], ts: dt.datetime, cooldown_sec: int) -> bool:
        if cooldown_sec <= 0:
            return False
        last = self._last.get(key)
        return last is not None and (ts - last).total_seconds() < cooldown_sec

    def record(self, key: tuple[str, str], ts: dt.datetime) -> None:
        self._last[key] = ts


_gate_cooldown = GateCooldown()


def _build_barrier_notifier(channel: str, cfg: dict, allowlist: list[str]) -> Notifier | None:
    """Construct the relay notifier for a barrier command.

    Returns None when the channel cannot be used — the caller treats that as a
    missed open rather than letting a config error open the gate. Webhook
    destinations are re-validated against the SSRF policy here, at send time:
    create-time validation is not trusted on the hot path (mirrors
    _build_notifiers), so a destination re-pointed at an internal address after
    creation still cannot be dialled.
    """
    if channel == "webhook":
        url = (cfg.get("url") or "").strip()
        if not url:
            log.warning("barrier webhook has no url — OPEN suppressed")
            return None
        try:
            validate_egress_url(url, allowlist=allowlist)
        except UnsafeUrlError:
            log.warning("barrier webhook failed SSRF re-validation — OPEN suppressed")
            return None
        return WebhookNotifier(url)
    try:
        return build_notifier(channel, cfg)
    except Exception as exc:
        log.warning("%s barrier channel is unusable: %s", channel, exc)
        return None


def _send_barrier_command(rt, lane: Lane, camera: Camera, ev: Event, detail: dict, *,
                          build=_build_barrier_notifier) -> bool:
    """Dispatch one barrier OPEN command to the lane's relay channel.

    Returns True only when a notifier was actually invoked. The relay
    destination is envelope-encrypted in ``barrier_config_enc`` (exactly like
    alert_routes.config_enc) and decrypted here — the KEK never leaves the host.
    The payload carries only third-party-safe keys: plate_enc (ciphertext) and
    plate_hash (a plate-derived digest) never reach a relay.

    ``build`` is injectable so the dispatch is testable offline.
    """
    if not lane.barrier_config_enc:
        log.warning("lane %s has no barrier config — OPEN suppressed (gate stays closed)", lane.id)
        return False
    try:
        cfg = rt.crypto.decrypt_json(lane.barrier_config_enc)
    except Exception as exc:
        log.warning("lane %s barrier config is undecryptable: %s", lane.id, exc)
        return False
    channel = lane.barrier_channel or "webhook"
    notifier = build(channel, cfg, rt.settings.ssrf_allowlist_cidrs)
    if notifier is None:
        return False
    dispatch(
        Alert(
            rule_id=ev.track_id or "gate",
            rule_type="gate_open",
            camera_id=camera.id,
            severity="info",
            title=f"barrier open · {lane.name or camera.name}",
            message=f"whitelisted plate read on lane '{lane.name or camera.name}'",
            detail=detail,
            ts=timeutil.iso(ev.timestamp_start) if ev.timestamp_start else None,
        ),
        [notifier],
    )
    return True


def _record_gate_outcome(session, camera: Camera, lane: Lane, ev: Event, plate_hash: str, *,
                         event_type: str, reason: str, granted: bool,
                         label: str | None = None) -> None:
    """Persist a gate decision as an Event row (forensic trail / events API) and
    an AuditLog row. R4.1 acceptance: every open/close is audited with the plate
    HASH — never the plaintext plate — and the operator who armed the lane."""
    session.add(Event(
        camera_id=camera.id,
        track_id=ev.track_id,
        identity_status="unknown",
        event_type=event_type,
        timestamp_start=ev.timestamp_start,
        timestamp_end=ev.timestamp_end,
        confidence=ev.confidence,
        bbox=ev.bbox or {},
        detail={
            "lane_id": lane.id,
            "lane": lane.name,
            "reason": reason,
            "entry_label": label,
            # Keyed digest only — plaintext plates are never stored (R2 index).
            "plate_hash": plate_hash,
        },
    ))
    session.add(AuditLog(
        username=lane.armed_by or "system",
        action=event_type,
        resource=f"lanes/{lane.id}",
        result="success" if granted else "failure",
        detail={
            "camera_id": camera.id,
            "lane": lane.name,
            "reason": reason,
            "plate_hash": plate_hash,
        },
    ))


def evaluate_lane_access(session, rt, camera: Camera, anpr_events,
                         *, now: dt.datetime | None = None,
                         send_barrier=_send_barrier_command,
                         cooldown: GateCooldown | None = None) -> list[GateDecision]:
    """Decide gate access for the ANPR plate reads of one frame (R4.1).

    Off unless the camera's ``pipeline_flags.lane_access`` is explicitly on, and
    a no-op when the camera has no lane at all — a stock camera costs one flag
    lookup. For each plate hash the whitelist is joined on the exact keyed-HMAC
    token the ANPR stage wrote to ``Event.detail``, the allow window is
    evaluated, and on a grant exactly one barrier OPEN is dispatched (subject to
    the lane cooldown); a denied read is logged and never reaches the relay.

    ``send_barrier`` is injectable so the whole path is testable offline, the
    same way ``enqueue_analytic_alerts`` takes ``put``. Returns every decision
    evaluated this frame (cooldown-suppressed repeats included).
    """
    if not pipeline_flag_enabled(camera.pipeline_flags, PIPELINE_FLAG_LANE_ACCESS):
        return []
    # Load the lane even when disarmed: a disabled lane still produces a
    # recorded denial (operator-visible), only a camera with no lane at all is
    # a silent no-op — nothing is configured to evaluate.
    lane = session.query(Lane).filter_by(camera_id=camera.id).first()
    if lane is None:
        return []
    cd = cooldown if cooldown is not None else _gate_cooldown
    now_utc = now if now is not None else timeutil.utcnow()
    decisions: list[GateDecision] = []
    for ev in anpr_events:
        detail = ev.detail if isinstance(ev.detail, dict) else {}
        plate_hash = detail.get("plate_hash")
        if not plate_hash:
            continue
        entry = (
            session.query(LaneWhitelistEntry)
            .filter_by(lane_id=lane.id, plate_hash=plate_hash, enabled=True)
            .first()
        )
        decision = decide_gate_access(lane, plate_hash, entry, now_utc,
                                      default_tz=camera.timezone or "UTC")
        ts = ev.timestamp_start or now_utc
        if decision.granted:
            key = (lane.id, plate_hash)
            if cd.is_suppressed(key, ts, lane.cooldown_sec):
                metrics.inc("gate_commands_suppressed_total", labels=f'lane="{lane.id}"')
                log.debug("barrier OPEN for lane %s suppressed by cooldown", lane.id)
                decisions.append(decision)
                continue
            sent = send_barrier(rt, lane, camera, ev, {
                "command": "open",
                "lane": lane.name,
                "reason": decision.reason,
                **_safe_alert_detail(ev.detail),
            })
            if not sent:
                # Policy said open but the relay could not be commanded: record
                # it rather than dropping the read silently, and do NOT consume
                # the cooldown so the next read of the plate can retry.
                _record_gate_outcome(session, camera, lane, ev, plate_hash,
                                     event_type="gate_open", granted=False,
                                     reason=DECISION_BARRIER_UNAVAILABLE,
                                     label=decision.entry_label)
                metrics.inc("gate_opens_failed_total", labels=f'lane="{lane.id}"')
                decisions.append(decision)
                continue
            cd.record(key, ts)
            _record_gate_outcome(session, camera, lane, ev, plate_hash,
                                 event_type="gate_open", granted=True,
                                 reason=DECISION_GRANTED, label=decision.entry_label)
            metrics.inc("gate_opens_total", labels=f'lane="{lane.id}"')
        else:
            _record_gate_outcome(session, camera, lane, ev, plate_hash,
                                 event_type="gate_deny", granted=False,
                                 reason=decision.reason, label=decision.entry_label)
            metrics.inc("gate_denies_total",
                        labels=f'lane="{lane.id}" reason="{decision.reason}"')
        decisions.append(decision)
    return decisions


def persist_camera_status(rt, cid: str, st: str) -> None:
    """Persist a gateway state transition to Camera.status/health/last_seen.

    The dashboard, analytics overview, and capacity views read these columns
    from the DB — before this existed nothing ever wrote them after camera
    creation, so cameras showed OFFLINE forever even while streaming.
    """
    try:
        with rt.SessionLocal() as s:
            cam = s.get(Camera, cid)
            if cam is None:
                return
            cam.status = st
            cam.health = {
                "ONLINE": "streaming",
                "RECONNECTING": "unstable",
                "OFFLINE": "unreachable",
            }.get(st, st.lower())
            if st == "ONLINE":
                cam.last_seen = timeutil.utcnow()
            s.commit()
    except Exception as exc:  # health persistence is best-effort
        log.warning("failed to persist status %s for %s: %s", st, cid, exc)


def heartbeat_camera(rt, cid: str) -> bool:
    """Touch `last_seen` while frames flow. Returns False when the camera row
    is GONE — the caller treats that as "removed from the configuration" and
    stops this camera's pipeline (frame loop + recorder).

    A transient database error returns True (fail-safe): a DB blip must never
    be mistaken for a deletion and kill a healthy camera's ingestion. The
    worker snapshots cameras at startup, so this heartbeat is the ONLY path a
    removal has into a running worker.
    """
    with contextlib.suppress(Exception), rt.SessionLocal() as s:
        cam = s.get(Camera, cid)
        if cam is None:
            return False
        if cam.status == "ONLINE":
            cam.last_seen = timeutil.utcnow()
            s.commit()
    return True


def run_camera(rt, camera: Camera, stop: threading.Event) -> None:
    settings = rt.settings
    try:
        detector = make_detector(settings, rt.registry)
    except Exception as exc:
        log.critical("camera %s not started: detector backend failed to load: %s", camera.id, exc)
        return
    tracker = IouTracker(iou_threshold=settings.ai_iou_threshold)
    face_chain = make_face_chain(settings, rt.registry)
    matcher = VectorMatcher(threshold=settings.ai_similarity_threshold)

    rule_engine = None
    if settings.ai_rules_enabled:
        rule_engine = rule_engine_from_json(camera.id, camera.rules)
    anpr = build_anpr(rt.registry, enabled=settings.ai_anpr_enabled, conf_thr=0.6)
    attribute_tagger = make_attribute_tagger(settings, rt.registry)

    pipeline = CameraPipeline(
        camera.id, detector, tracker, face_chain, matcher, rt.SessionLocal, rt.storage, rt.crypto,
        confidence_threshold=settings.ai_confidence_threshold,
        merge_gap_seconds=10.0,
        recognize_interval_sec=settings.ai_recognize_interval_sec,
        model_version=rt.embedder.model_version,
        identity_recognition_enabled=settings.ai_identity_recognition_enabled,
        rule_engine=rule_engine,
        anpr=anpr,
        attributes=attribute_tagger,
        attribute_interval_sec=settings.ai_attribute_interval_sec,
        privacy_masks=camera.privacy_masks,
        motion_gate_enabled=settings.ai_motion_gate_enabled,
        motion_threshold=settings.ai_motion_threshold,
    )

    # Per-camera stop event: set when this camera is removed from the
    # configuration, so ITS recorder and frame loop wind down without touching
    # sibling cameras. The global `stop` stays the process-wide signal.
    cam_stop = threading.Event()

    def _stopping() -> bool:
        return stop.is_set() or cam_stop.is_set()

    # Main-stream recorder (only when a main URL is configured + recording on).
    recorder: Recorder | None = None
    main_url = camera.stream_url_enc
    if settings.record_enabled and main_url:
        plain_main = rt.crypto.decrypt_str(main_url)
        recorder = Recorder(
            camera.id, rt.storage, rt.crypto,
            seg_seconds=settings.record_segment_seconds,
            allowlist=settings.ssrf_allowlist_cidrs,
        )

        def _record_loop() -> None:
            # Honors both the global stop and this camera's removal: a recorder
            # must not keep cutting segments for a camera that is gone.
            while not _stopping():
                try:
                    recorder.record_url(plain_main, dt_now())  # row tracked internally
                    proc = recorder.last_proc
                    if proc is not None:
                        try:
                            proc.wait()
                        except Exception:
                            pass
                    done = recorder.finalize_last()
                    if done is not None:
                        try:
                            with rt.SessionLocal() as s:
                                s.add(done)
                                s.commit()
                        except Exception as exc:
                            log.warning("failed to persist segment for %s: %s", camera.id, exc)
                except Exception as exc:
                    log.warning("recorder error for %s: %s", camera.id, exc)
                    stop.wait(2.0)

        threading.Thread(target=_record_loop, name=f"rec-{camera.id}", daemon=True).start()

    def make_source():
        return build_make_source(camera, settings, rt.crypto,
                                 allowlist=settings.ssrf_allowlist_cidrs)()

    def _on_status(cid: str, st: str) -> None:
        log.info("camera %s -> %s", cid, st)
        persist_camera_status(rt, cid, st)
        # RECONNECTING/DISCONNECT states are the health signal the capacity
        # planner and alerting depend on; emit as a counter. The gateway's
        # streaming state is named ONLINE (not STREAMING) — the stale metric
        # label never matched it.
        if st in ("RECONNECTING", "DISCONNECTED", "OFFLINE"):
            metrics.inc("camera_disconnects_total", labels=f'camera="{cid}"')
        metrics.set("camera_status", 1.0 if st == "ONLINE" else 0.0,
                    labels=f'camera="{cid}"')

    gateway = StreamGateway(camera.id, make_source, on_status=_on_status)
    log.info("starting pipeline for camera %s (%s)", camera.id, camera.name)

    # R3.6 daily alert budget: cap this camera's alert fan-out per UTC day.
    # Seeded from today's persisted analytic events so a worker restart cannot
    # hand out a fresh budget (and the API shows that same count). 0 = unlimited,
    # which is the pre-R3.6 behavior and the platform default.
    _budget_limit = (camera.alert_budget_per_day
                     if getattr(camera, "alert_budget_per_day", None) is not None
                     else settings.alert_budget_per_camera_per_day)
    _alert_budget = DailyAlertBudget(_budget_limit)
    try:
        with rt.SessionLocal() as _seed_session:
            _alert_budget.seed(camera.id, count_alerts_today(_seed_session, camera.id))
    except Exception as exc:
        log.warning("alert budget seed failed for %s: %s", camera.id, exc)
    if _alert_budget.limit_per_day:
        log.info("camera %s alert budget: %s/UTC-day (used %s)",
                 camera.id, _alert_budget.limit_per_day, _alert_budget.used(camera.id))

    # Rolling fps/latency bookkeeping for observability (declared in metrics.py,
    # previously never emitted — see report D-3).
    _fps_window: list[float] = []
    _last_frame_ts: dt.datetime | None = None
    _last_heartbeat: float = 0.0

    for frame, ts in gateway.iter_frames():
        if _stopping():
            break
        # Bounded DB touch (≤1 per 30 s) so last_seen tracks liveness between
        # status transitions without turning the hot frame path into a
        # per-frame DB write. The same touch is the removal signal: a camera
        # deleted after the worker started reports itself here, and its
        # pipeline winds down within one heartbeat instead of running — and
        # recording — against a row that no longer exists.
        if time.time() - _last_heartbeat > 30.0:
            if not heartbeat_camera(rt, camera.id):
                log.info("camera %s was removed from the configuration — stopping its pipeline",
                         camera.id)
                cam_stop.set()
                break
            _last_heartbeat = time.time()
        t0 = time.perf_counter()
        session = rt.SessionLocal()
        try:
            events = pipeline.process_frame(session, frame, ts)
            session.commit()
            metrics.inc("frames_processed", labels=f'camera="{camera.id}"')
            if getattr(pipeline, "_last_analytic", []):
                metrics.inc("analytic_events_total",
                            amount=len(pipeline._last_analytic),
                            labels=f'camera="{camera.id}"')
            for ev in events:
                log.info("event %s cam=%s identity=%s", ev.id, ev.camera_id, ev.identity_status)
            # R4.1 gate access: plate reads on a lane camera decide barrier open
            # vs deny. Off unless pipeline_flags.lane_access is set and a no-op
            # without an enabled lane, so a stock camera costs one flag lookup.
            # Evaluated in its own try: a barrier failure must never drop the
            # frame or starve the alert path below (the ANPR evidence is already
            # committed).
            anpr_events = [e for e in getattr(pipeline, "_last_analytic", [])
                           if e.event_type == "anpr"]
            if anpr_events:
                try:
                    evaluate_lane_access(session, rt, camera, anpr_events)
                    session.commit()
                except Exception:
                    session.rollback()
                    log.exception("gate access evaluation failed for camera %s", camera.id)
            # Fan out point-in-time analytic events to alert channels (R3.6: the
            # per-camera daily budget gates notifications; evidence is stored
            # regardless). Detail is filtered to the third-party-safe keys (no
            # ciphertext leaves the host).
            analytics = getattr(pipeline, "_last_analytic", [])
            if analytics:
                enqueue_analytic_alerts(analytics, camera.id, _alert_budget)
                metrics.set("alerts_budget_used", float(_alert_budget.used(camera.id)),
                            labels=f'camera="{camera.id}"')
        except Exception:
            session.rollback()
            log.exception("pipeline error for camera %s", camera.id)
            metrics.inc("frames_dropped", labels=f'camera="{camera.id}"')
        finally:
            session.close()
            # Per-frame processing latency and rolling fps.
            metrics.observe("pipeline_latency_ms", (time.perf_counter() - t0) * 1000.0,
                            labels=f'camera="{camera.id}"')
            if _last_frame_ts is not None:
                delta = (ts - _last_frame_ts).total_seconds()
                if delta > 0:
                    _fps_window.append(1.0 / delta)
                    del _fps_window[:-30]  # keep last 30 samples
                    if len(_fps_window) >= 5:
                        metrics.set("camera_fps", sum(_fps_window) / len(_fps_window),
                                    labels=f'camera="{camera.id}"')
            _last_frame_ts = ts
    metrics.set("camera_fps", 0.0, labels=f'camera="{camera.id}"')

    if recorder is not None:
        recorder.stop_all()


def dt_now():
    return timeutil.utcnow()


def main() -> None:
    settings = Settings()
    configure_logging(settings.log_level)
    rt = build(settings)
    stop = threading.Event()

    # Docker `stop` and systemd send SIGTERM; without a handler the daemon
    # threads die mid-frame and ffmpeg children are reparented. Treat SIGTERM
    # exactly like Ctrl-C so recorders flush and processes are reaped.
    def _handle_sigterm(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, _handle_sigterm)

    threads = []
    with rt.SessionLocal() as session:
        cameras = session.query(Camera).all()
    for camera in cameras:
        t = threading.Thread(target=run_camera, args=(rt, camera, stop), daemon=True)
        t.start()
        threads.append(t)
    log.info("worker running for %d camera(s). Ctrl-C to stop.", len(threads))
    # Background services: async alert fan-out + retention sweeper.
    sender = threading.Thread(target=_alert_sender, args=(rt, stop), daemon=True)
    sender.start()
    reaper = threading.Thread(target=_retention_loop, args=(rt, stop), daemon=True)
    reaper.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        for t in threads:
            t.join(timeout=5)
        sender.join(timeout=5)
        reaper.join(timeout=5)


if __name__ == "__main__":
    main()
