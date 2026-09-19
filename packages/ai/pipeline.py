"""Per-camera AI pipeline orchestrator.

Flow (configurable, per spec):
  RTSP -> decode -> [motion gate] -> frame sampling -> person detection ->
  tracking -> face detection (tracked people only) -> quality filter ->
  embedding -> identity search (throttled per track) -> event aggregation.

The pipeline is the *only* place that owns per-track state and turns a stream of
frames into deduplicated presence events. It is intentionally decoupled from the
transport (FFmpeg/Synthetic) and the models (swappable interfaces).

Recognition is optional and throttled (default every 2s per active track), never
run on every frame. Embeddings are decrypted from the DB only for the matcher and
never logged.
"""
from __future__ import annotations

import datetime as dt
import json

from sqlalchemy import func, select

from packages.ai.anpr import ANPRPipeline
from packages.ai.attributes import AttributeTagger
from packages.ai.interfaces import (
    Detector,
    FaceDetector,
    FaceEmbedder,
    IdentityMatcher,
    Track,
)
from packages.ai.rules import RuleEngine
from packages.domain.models import (
    Detection as DetectionRow,
)
from packages.domain.models import (
    Event as EventRow,
)
from packages.domain.models import (
    PersonEmbedding,
    Snapshot,
)
from packages.domain.models import (
    Track as TrackRow,
)
from packages.security.crypto import CryptoBox
from packages.storage.base import StorageProvider

_ENROLLED_TTL = 30.0  # seconds before re-checking enrolled embeddings

# Max ANPR read frequency per vehicle track. Per-frame OCR on every vehicle is
# unbounded CPU + floods the event/alert store; we re-read at most this often and
# only emit an event when the plate changes (new vehicle / new reading).
_ANPR_INTERVAL_SEC = 5.0

# Clothing-attribute sampling per person track ("jacket", colors, …): same
# rationale as the ANPR throttle — per-frame CLIP on every person is unbounded
# CPU, and clothing changes far slower than position. Re-tagged at most this
# often per track, only when the crop can carry clothing signal.
_ATTR_INTERVAL_SEC = 5.0
_ATTR_MIN_BBOX_H = 0.08   # ≈29 px on a 360 px substream: below this, no signal
# Faces need resolution too: below this bbox height a detected face would be
# under ~24 px — too small for a usable ArcFace embedding. Skip the whole
# SCRFD+embed call (the dominant per-track cost) instead of wasting it.
_FACE_MIN_BBOX_H = 0.06

# Detection rows are written only when the track actually moved (normalized
# bbox delta beyond this epsilon) or when this many seconds elapsed since the
# last stored sample. A stationary object produces ~1 row per interval instead
# of one per frame, cutting hot-path INSERT volume by ~90% at 5 fps.
_DETECTION_MIN_MOVE = 0.01  # normalized units (1% of frame width/height)
_DETECTION_MAX_INTERVAL_SEC = 2.0

# Privacy masks suppress a detection when its center falls inside the mask
# rectangle OR its overlap with the mask covers at least this fraction of the
# detection box (whichever hits first). Configured per camera as normalized
# {x, y, w, h} rectangles.
_MASK_MIN_OVERLAP = 0.5

# Motion gate v2 (roadmap A5). The v1 gate compared a strided grid
# byte-for-byte: ANY single-pixel change (sensor noise, auto-exposure
# breathing, IR cut transitions) counted as motion, so on real cameras it
# almost never skipped anything and paid the gate cost for nothing. v2 scores
# the *mean absolute* frame-to-frame difference over a 64x64 grayscale grid
# (0 = pixel-identical, 1 = black↔white) and skips the detector only when the
# score is below a calibrated threshold. Threshold is per-camera overridable
# (AI_MOTION_THRESHOLD) because a bright noisy outdoor scene and a dim indoor
# corridor have very different noise floors.
_MOTION_GRID = 64
_MOTION_THRESHOLD_DEFAULT = 0.004  # ≈1 intensity level of mean delta (0-255)


def _crop_vehicle(frame, bbox: tuple[float, float, float, float]):
    """Best-effort crop of a normalized bbox from a numpy frame; pass-through otherwise."""
    try:
        import numpy as np
    except Exception:
        return frame
    if not isinstance(frame, np.ndarray):
        return frame
    h, w = frame.shape[:2]
    x, y, bw, bh = bbox
    x1 = max(0, int(x * w))
    y1 = max(0, int(y * h))
    x2 = min(w, int((x + bw) * w))
    y2 = min(h, int((y + bh) * h))
    if x2 <= x1 or y2 <= y1:
        return frame
    return frame[y1:y2, x1:x2]


def _bbox_overlap_fraction(
    bbox: tuple[float, float, float, float],
    mask: tuple[float, float, float, float],
) -> float:
    """Fraction of `bbox` covered by `mask` (both normalized x,y,w,h)."""
    bx, by, bw, bh = bbox
    mx, my, mw, mh = mask
    ix = max(0.0, min(bx + bw, mx + mw) - max(bx, mx))
    iy = max(0.0, min(by + bh, my + mh) - max(by, my))
    area = bw * bh
    return (ix * iy / area) if area > 0 else 0.0


def _parse_mask(m: object) -> tuple[float, float, float, float] | None:
    """Coerce a stored mask spec ({x,y,w,h}) into a validated float tuple."""
    if not isinstance(m, dict):
        return None
    try:
        rect = (float(m["x"]), float(m["y"]), float(m["w"]), float(m["h"]))
    except (KeyError, TypeError, ValueError):
        return None
    if any(v < 0 for v in rect):
        return None
    return rect


class _TrackState:
    __slots__ = (
        "attributes",
        "bbox",
        "confidence",
        "first_seen",
        "last_recognized",
        "last_seen",
        "recognition",
        "seen_this_frame",
        "trajectory",
    )

    def __init__(self, ts, bbox, confidence, trajectory):
        self.first_seen = ts
        self.last_seen = ts
        self.confidence = confidence
        self.bbox = bbox
        self.trajectory = trajectory
        self.seen_this_frame = True
        self.last_recognized: dt.datetime | None = None
        self.recognition: tuple[str | None, float | None, str] | None = None
        self.attributes: dict | None = None


class CameraPipeline:
    def __init__(
        self,
        camera_id: str,
        detector: Detector,
        tracker,
        face_chain: tuple[FaceDetector, FaceEmbedder] | None,
        matcher: IdentityMatcher | None,
        session_factory,
        storage: StorageProvider,
        crypto: CryptoBox,
        *,
        confidence_threshold: float = 0.45,
        merge_gap_seconds: float = 10.0,
        recognize_interval_sec: float = 2.0,
        model_version: str = "ref-v0",
        identity_recognition_enabled: bool = False,
        rule_engine: RuleEngine | None = None,
        anpr: ANPRPipeline | None = None,
        attributes: AttributeTagger | None = None,
        attribute_interval_sec: float = _ATTR_INTERVAL_SEC,
        privacy_masks: list[dict] | None = None,
        motion_gate_enabled: bool = False,
        motion_threshold: float | None = None,
        motion_grid: int = _MOTION_GRID,
    ) -> None:
        self.camera_id = camera_id
        self.detector = detector
        self.tracker = tracker
        self.face_detector, self.embedder = face_chain or (None, None)
        self.matcher = matcher
        self.session_factory = session_factory
        self.storage = storage
        self.crypto = crypto
        self.confidence = confidence_threshold
        self.merge_gap = merge_gap_seconds
        self.recognize_interval = recognize_interval_sec
        self.model_version = model_version
        self.recognition_enabled = bool(identity_recognition_enabled and face_chain and matcher)
        self.rule_engine = rule_engine
        self.anpr = anpr
        self.attributes = attributes
        self.attribute_interval = attribute_interval_sec
        self._masks = [m for m in (_parse_mask(x) for x in (privacy_masks or [])) if m]
        # Motion gate (AI_MOTION_GATE_ENABLED): skip detection on frames whose
        # mean absolute delta is below threshold. Cheap scalar scoring vs.
        # running the full detector on a static scene; meaningful for real
        # ONNX backends at higher fps. Threshold resolution order: explicit
        # argument → AI_MOTION_THRESHOLD env → calibrated default.
        self.motion_gate_enabled = bool(motion_gate_enabled)
        self.motion_grid = max(8, int(motion_grid))
        if motion_threshold is None:
            import os

            motion_threshold = float(
                os.environ.get("AI_MOTION_THRESHOLD", _MOTION_THRESHOLD_DEFAULT)
            )
        self.motion_threshold = float(motion_threshold)
        self._gate_prev: object | None = None
        # Observability for the camera-health surface: how much of the
        # detector budget the gate is actually saving on this scene.
        self.motion_frames = 0
        self.motion_skips = 0
        self.last_motion_score = 0.0
        self._anpr_last: dict[str, tuple[str | None, dt.datetime]] = {}
        self._attrs_last: dict[str, tuple[dt.datetime, dict]] = {}
        self._last_analytic: list[EventRow] = []  # point-in-time events (rules/anpr) for alerting
        # track_id -> ts of last DetectionRow persisted (write gating, F-04)
        self._detection_last_ts: dict[str, dt.datetime] = {}
        self._detection_last_bbox: dict[str, tuple[float, float, float, float]] = {}

        self._active: dict[str, _TrackState] = {}
        self._enrolled: list[tuple[str, list[float], str]] = []
        self._enrolled_at: float = 0.0
        self._enrolled_watermark: dt.datetime | None = None

    # ── privacy masks (F-05) ─────────────────────────────────────────────────
    def _is_masked(self, bbox: tuple[float, float, float, float]) -> bool:
        """True when a detection must be suppressed by a privacy mask.

        Suppress when the detection center lies inside the mask, or when at
        least `_MASK_MIN_OVERLAP` of the detection box is covered by it. Both
        tests operate in normalized [0,1] coordinates, matching rule geometry
        and the UI canvas.
        """
        cx, cy = bbox[0] + bbox[2] / 2, bbox[1] + bbox[3] / 2
        for (mx, my, mw, mh) in self._masks:
            if mx <= cx <= mx + mw and my <= cy <= my + mh:
                return True
            if _bbox_overlap_fraction(bbox, (mx, my, mw, mh)) >= _MASK_MIN_OVERLAP:
                return True
        return False

    # ── motion gate ──────────────────────────────────────────────────────────
    def motion_score(self, frame) -> float | None:
        """Mean absolute frame-to-frame delta over a coarse grayscale grid.

        Returns a score in [0, 1] (0 = pixel-identical, 1 = black↔white), or
        None when pixels cannot be read (None / synthetic / undecodable
        frames) — callers treat None as "always motion" so the gate can never
        stall a pipeline. Pure numpy indexing: ~50 us on 640x360, i.e. orders
        of magnitude cheaper than a single detector call — the whole point.
        """
        if frame is None:
            return None
        try:
            import numpy as np

            img = np.asarray(frame)
            if img.size == 0 or img.ndim < 2:
                return None
            # Downsample on the NATIVE dtype first, then convert: strided
            # slicing on uint8 is a free view, so we touch ~grid^2 pixels
            # instead of the whole frame. Converting the full frame to float32
            # first measured ~1.9 ms on 640x360 — as expensive as a small
            # inference call, which defeats the purpose of the gate.
            sh = max(1, img.shape[0] // self.motion_grid)
            sw = max(1, img.shape[1] // self.motion_grid)
            small_u8 = img[::sh, ::sw][: self.motion_grid, : self.motion_grid]
            if small_u8.size == 0:
                return None
            g = small_u8.astype(np.float32)
            if g.ndim == 3:
                g = g[..., :3].mean(axis=2)  # luma is enough, 3x cheaper
            if g.size and g.max() > 1.0:
                g = g / 255.0
            small = np.ascontiguousarray(g)
            if small.size == 0:
                return None
        except Exception:
            return None
        prev = self._gate_prev
        self._gate_prev = small
        if prev is None or getattr(prev, "shape", None) != small.shape:
            return None  # first frame / geometry change: prime the baseline
        return float(np.abs(small - prev).mean())

    def _frame_has_motion(self, frame) -> bool:
        """True when the frame should be handed to the detector.

        Scored gate (v2): only a mean delta below `motion_threshold` skips
        detection, so sensor noise / auto-exposure breathing no longer defeat
        the gate. Frames without readable pixels always count as motion, so a
        synthetic or byte-oriented source never starves the pipeline.
        """
        score = self.motion_score(frame)
        if score is None:
            return True
        self.last_motion_score = score
        return score >= self.motion_threshold

    # ── enrolled embeddings (decrypted, cached) ─────────────────────────────
    def _refresh_enrolled(self, session) -> None:
        """Refresh the decrypted enrollment cache.

        Cheap watermark check first: if no PersonEmbedding row has a newer
        `created_at` than the one already cached, skip the decrypt pass
        entirely. A 1,000-person site therefore pays one full-table decrypt on
        startup and after each enrollment — not every 30 s per camera.
        """
        latest = session.scalar(
            select(func.max(PersonEmbedding.created_at))
        )
        if (
            self._enrolled
            and latest is not None
            and self._enrolled_watermark is not None
            and latest <= self._enrolled_watermark
        ):
            self._enrolled_at = dt.datetime.now(dt.UTC).timestamp()
            return
        rows = session.query(PersonEmbedding).all()
        enrolled = []
        for r in rows:
            try:
                vec = self.crypto.decrypt_json(r.embedding_enc)
            except Exception:
                continue
            enrolled.append((r.person_id, vec, r.model_version))
        self._enrolled = enrolled
        self._enrolled_watermark = latest
        self._enrolled_at = dt.datetime.now(dt.UTC).timestamp()

    # ── detection stage (single choke point) ────────────────────────────────
    def _detect_tracks(self, frame, ts) -> list:
        """Run the detector and hand masked/low-confidence boxes to the tracker.

        Extracted so the motion gate has exactly one place to bypass, and so
        privacy masks are applied in exactly one place — BEFORE tracking
        (architectural rule 6: masks suppress detections whose center falls
        inside the mask or overlap it ≥50%).
        """
        raw = self.detector.detect(frame, ts)
        detections = [
            d for d in raw
            if d.confidence >= self.confidence and not self._is_masked(d.bbox)
        ]
        return self.tracker.update(self.camera_id, detections, ts)

    # ── core frame processing (testable) ───────────────────────────────────
    def process_frame(self, session, frame, ts: dt.datetime) -> list[EventRow]:
        if dt.datetime.now(dt.UTC).timestamp() - self._enrolled_at > _ENROLLED_TTL:
            self._refresh_enrolled(session)

        for st in self._active.values():
            st.seen_this_frame = False

        if self.motion_gate_enabled:
            self.motion_frames += 1
            if not self._frame_has_motion(frame):
                # Static scene: still age out stale tracks so presence events
                # close on schedule, but skip detection/tracking entirely.
                self.motion_skips += 1
                tracks = []
            else:
                tracks = self._detect_tracks(frame, ts)
        else:
            tracks = self._detect_tracks(frame, ts)
        closed: list[EventRow] = []

        # ── behavior analytics + ANPR (point-in-time events) ───────────────
        self._last_analytic = []
        if self.rule_engine is not None and tracks:
            tracks_input = [(tr.track_id, tr.label, tr.bbox) for tr in tracks]
            for ae in self.rule_engine.evaluate(tracks_input, ts):
                ev = EventRow(
                    camera_id=self.camera_id, track_id=ae.track_id,
                    identity_status="unknown", event_type=ae.rule_type,
                    timestamp_start=ae.ts, timestamp_end=ae.ts,
                    confidence=ae.score, bbox={"x": ae.bbox[0], "y": ae.bbox[1],
                                               "w": ae.bbox[2], "h": ae.bbox[3]},
                    detail=dict(ae.detail),
                )
                session.add(ev)
                self._last_analytic.append(ev)
        if self.anpr is not None:
            for tr in tracks:
                if tr.label != "vehicle":
                    continue
                last_plate, last_ts = self._anpr_last.get(tr.track_id, (None, None))
                if last_ts is not None and (ts - last_ts).total_seconds() < _ANPR_INTERVAL_SEC:
                    continue  # throttle: re-read at most every _ANPR_INTERVAL_SEC per track
                crop = _crop_vehicle(frame, tr.bbox)
                reading = self.anpr.read(crop, ts)
                if not reading:
                    continue
                # Only emit an event on a *new* plate for this track (dedup flooding).
                if last_plate == reading.plate:
                    self._anpr_last[tr.track_id] = (reading.plate, ts)
                    continue
                self._anpr_last[tr.track_id] = (reading.plate, ts)
                ev = EventRow(
                    camera_id=self.camera_id, track_id=tr.track_id,
                    identity_status="unknown", event_type="anpr",
                    timestamp_start=ts, timestamp_end=ts, confidence=reading.confidence,
                    bbox={"x": tr.bbox[0], "y": tr.bbox[1], "w": tr.bbox[2], "h": tr.bbox[3]},
                    detail={
                        "plate_enc": self.crypto.encrypt_str(reading.plate),
                        # Keyed HMAC (CryptoBox.hmac_str), NOT bare SHA-256:
                        # plates are a ~36^8 keyspace — an unkeyed hash is
                        # brute-forceable offline. The master-key-bound token
                        # stays a searchable equality index that an attacker
                        # with a stolen DB cannot invert.
                        "plate_hash": self.crypto.hmac_str(reading.plate),
                    },
                )
                session.add(ev)
                self._last_analytic.append(ev)

        for tr in tracks:
            st = self._active.get(tr.track_id)
            if st is None:
                st = _TrackState(ts, tr.bbox, tr.confidence, list(tr.trajectory))
                self._active[tr.track_id] = st
            st.seen_this_frame = True
            st.last_seen = ts
            st.bbox = tr.bbox
            st.confidence = max(st.confidence, tr.confidence)

            # Clothing attributes (opt-in tagger): sampled per TRACK, only for
            # persons whose crop is large enough to carry clothing signal.
            # Re-tag at most every attribute_interval seconds; last tag wins.
            if (self.attributes is not None and tr.label == "person"
                    and tr.bbox[3] >= _ATTR_MIN_BBOX_H):
                last_ts, _ = self._attrs_last.get(tr.track_id, (None, None))
                if last_ts is None or (ts - last_ts).total_seconds() >= self.attribute_interval:
                    tags = self.attributes.tag(_crop_vehicle(frame, tr.bbox))
                    self._attrs_last[tr.track_id] = (ts, tags)
                    if tags:
                        st.attributes = tags

            # Face recognition: the far-field gate skips the whole
            # SCRFD+embed chain when the person is too small for a usable
            # embedding (~24 px face). last_recognized is NOT advanced, so
            # recognition retries automatically as the person approaches.
            if (self.recognition_enabled and tr.bbox[3] >= _FACE_MIN_BBOX_H
                    and self._should_recognize(st, ts)):
                st.last_recognized = ts
                rec = self._recognize(frame, tr)
                st.recognition = (rec.person_id, rec.similarity, rec.status)

        # persist detections (sampled: only when the track moved meaningfully
        # or the max sample interval elapsed — a stationary object yields ~1
        # row per interval instead of one per frame)
        for tr in tracks:
            last_ts = self._detection_last_ts.get(tr.track_id)
            last_box = self._detection_last_bbox.get(tr.track_id)
            moved = (
                last_box is None
                or abs(tr.bbox[0] - last_box[0]) > _DETECTION_MIN_MOVE
                or abs(tr.bbox[1] - last_box[1]) > _DETECTION_MIN_MOVE
                or abs(tr.bbox[2] - last_box[2]) > _DETECTION_MIN_MOVE
                or abs(tr.bbox[3] - last_box[3]) > _DETECTION_MIN_MOVE
            )
            stale = (
                last_ts is None
                or (ts - last_ts).total_seconds() >= _DETECTION_MAX_INTERVAL_SEC
            )
            if not (moved or stale):
                continue
            self._detection_last_ts[tr.track_id] = ts
            self._detection_last_bbox[tr.track_id] = tr.bbox
            session.add(
                DetectionRow(
                    camera_id=self.camera_id,
                    track_id=tr.track_id,
                    frame_ts=ts,
                    label=tr.label,
                    confidence=tr.confidence,
                    bbox={"x": tr.bbox[0], "y": tr.bbox[1], "w": tr.bbox[2], "h": tr.bbox[3]},
                )
            )
        # Drop gating state for tracks the tracker has aged out so the dict
        # cannot grow without bound on long-running cameras.
        active_ids = {tr.track_id for tr in tracks}
        for tid in list(self._detection_last_ts):
            if tid not in active_ids:
                self._detection_last_ts.pop(tid, None)
                self._detection_last_bbox.pop(tid, None)
        for tid in list(self._attrs_last):
            if tid not in active_ids:
                self._attrs_last.pop(tid, None)
        for tid in list(self._anpr_last):
            if tid not in active_ids:
                self._anpr_last.pop(tid, None)

        # close stale tracks -> events
        for tid, st in list(self._active.items()):
            if st.seen_this_frame:
                continue
            gap = (ts - st.last_seen).total_seconds()
            if gap >= self.merge_gap:
                event = self._finalize(session, tid, st)
                if event:
                    closed.append(event)
                del self._active[tid]

        # upsert active tracks
        self._upsert_tracks(session)
        return closed

    def _should_recognize(self, st: _TrackState, ts: dt.datetime) -> bool:
        if st.last_recognized is None:
            return True
        return (ts - st.last_recognized).total_seconds() >= self.recognize_interval

    def _recognize(self, frame, tr: Track):
        assert self.face_detector and self.embedder and self.matcher
        face = self.face_detector.detect(frame, tr.bbox)
        if not face:
            return type("R", (), {"person_id": None, "similarity": None, "status": "unknown"})()
        vec = self.embedder.embed(frame, face)
        return self.matcher.search(vec, self.model_version, self._enrolled)

    def _finalize(self, session, tid: str, st: _TrackState) -> EventRow | None:
        pid, sim, status = st.recognition or (None, None, "unknown")
        event = EventRow(
            camera_id=self.camera_id,
            track_id=tid,
            identity_id=pid if status == "known" else None,
            identity_status=status,
            event_type="presence",
            timestamp_start=st.first_seen,
            timestamp_end=st.last_seen,
            confidence=st.confidence,
            bbox={"x": st.bbox[0], "y": st.bbox[1], "w": st.bbox[2], "h": st.bbox[3]},
            # Non-biometric appearance context rides with the presence event
            # (search: "person in red jacket"); None when never tagged.
            detail={"attributes": st.attributes} if st.attributes else None,
        )
        session.add(event)
        session.flush()  # populate event.id
        # store an encrypted snapshot reference (no raw face retained by default)
        snap_key = f"snapshots/{self.camera_id}/{event.id}.json"
        payload = json.dumps(
            {"track_id": tid, "identity_status": status, "ts": st.last_seen.isoformat()}
        ).encode()
        self.storage.put(snap_key, payload, "application/json")
        event.snapshot_key_enc = self.crypto.encrypt_str(snap_key)
        session.add(Snapshot(camera_id=self.camera_id, track_id=tid, event_id=event.id,
                             storage_key_enc=self.crypto.encrypt_str(snap_key)))
        return event

    def _upsert_tracks(self, session) -> None:
        for tid, st in self._active.items():
            pid, sim, status = st.recognition or (None, None, "unknown")
            row = session.get(TrackRow, tid)
            if row is None:
                row = TrackRow(id=tid, camera_id=self.camera_id)
                session.add(row)
            row.identity_id = pid if status == "known" else None
            row.identity_status = status
            row.first_seen = st.first_seen
            row.last_seen = st.last_seen
            row.confidence = st.confidence
            row.bbox = {"x": st.bbox[0], "y": st.bbox[1], "w": st.bbox[2], "h": st.bbox[3]}
            row.trajectory = st.trajectory
            row.detail = st.attributes or None
