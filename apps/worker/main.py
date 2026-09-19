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
from packages.domain.models import (
    AlertRoute,
    AuditLog,
    Camera,
    Event,
    PersonEmbedding,
    RefreshToken,
    Snapshot,
    VideoSegment,
)
from packages.notify import Alert, PushNotifier, WebhookNotifier, build_notifier, dispatch
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
    while not stop.is_set():
        try:
            _sweep_retention(rt)
        except Exception as exc:
            log.warning("retention sweep failed: %s", exc)
        stop.wait(3600)


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
            # Fan out point-in-time analytic events to alert channels. Detail is
            # filtered to the third-party-safe keys (no ciphertext leaves the host).
            for ae in getattr(pipeline, "_last_analytic", []):
                alert = Alert(rule_id=ae.track_id or ae.event_type, rule_type=ae.event_type,
                              camera_id=ae.camera_id, title=ae.event_type,
                              message=str(_safe_alert_detail(ae.detail)),
                              detail=_safe_alert_detail(ae.detail),
                              ts=ae.timestamp_start.isoformat() if ae.timestamp_start else None)
                try:
                    _alert_queue.put(alert)
                except Exception:
                    log.exception("alert enqueue failed for %s", camera.id)
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
