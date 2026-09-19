"""Detection backends.

LocalSight ships a *swappable* Detector interface (packages.ai.interfaces). This
module provides production-grade backends behind that same interface:

  * ONNXDetector        — runs any ONNX object-detection model via onnxruntime
                          (YOLO/RT-DETR exported to ONNX; INT8-quantized for edge).
  * TensorRTDetector    — NVIDIA Jetson/ dGPU (lazy import of tensorrt).
  * OpenVINODetector    — Intel CPU/iGPU/NPU (lazy import of openvino).
  * TFLiteDetector      — ARM/Coral (lazy import of tflite_runtime).
  * ReferenceMotionDetector — a dependency-light classical fallback (frame
                          differencing) used when no model is staged; keeps the
                          pipeline real and runnable on CPU without downloads.

All heavy runtimes are imported lazily so the API process never pays for them
unless a camera actually selects that backend. Model weights are loaded only from
the approved ModelRegistry (SHA-256 verified) — never from user-supplied URLs.
"""
from __future__ import annotations

import datetime as dt
from typing import List, Optional

from packages.ai.interfaces import Detection, Detector
from packages.ai.registry import ModelRegistry

# Upper bound on candidates handed to NMS per frame (same discipline as the
# `max_det=300` mainstream exports apply in-model). Without it, a dense head
# on a crowded scene makes NMS the dominant per-frame cost — measured at
# ~800 ms/call with ~20k candidates above threshold in the pure-Python path.
# The tracker cannot consume hundreds of objects from one camera anyway, so
# keeping the top scorers changes nothing downstream and bounds the worst case.
MAX_CANDIDATES = 300

# Labels aligned with COCO/ONVIF so downstream behavior rules + event types map
# cleanly across vendors.
DEFAULT_LABELS = [
    "person", "vehicle", "bicycle", "motorcycle", "bus", "truck",
    "animal", "bag", "package",
]


def iou(a, b) -> float:
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    ix = max(0.0, min(ax + aw, bx + bw) - max(ax, bx))
    iy = max(0.0, min(ay + ah, by + bh) - max(ay, by))
    inter = ix * iy
    union = aw * ah + bw * bh - inter
    return inter / union if union > 0 else 0.0


def postprocess_yolo_e2e(
    raw,
    labels: list[str],
    conf_thr: float,
    in_hw: tuple = (640, 640),
    frame_hw: tuple = (360, 640),
) -> list[Detection]:
    """Decode an END-TO-END (NMS-free) YOLO export: (batch, max_det, 6).

    Columns are x1,y1,x2,y2,conf,cls in model-input pixels (the `nms=False`
    export path, e.g. YOLO26 end2end). Boxes are rescaled to normalized frame
    space exactly like `postprocess_yolo` (stride padding is bottom/right
    only, so the model saw the padded in_hw and we scale by frame/in).
    Pure enough to unit-test with tiny synthetic tensors.
    """
    try:
        import numpy as np
    except Exception as exc:  # pragma: no cover - numpy is a runtime dep
        raise RuntimeError("numpy is required for ONNX-style backends") from exc

    arr = np.asarray(raw)
    if arr.ndim != 3 or arr.shape[2] != 6:
        return []
    sx = frame_hw[1] / in_hw[1]
    sy = frame_hw[0] / in_hw[0]
    out: list[Detection] = []
    for row in arr[0]:
        conf = float(row[4])
        if conf < conf_thr:
            continue
        x1, y1, x2, y2 = (float(v) for v in row[:4])
        cls = int(row[5])
        label = labels[cls] if 0 <= cls < len(labels) else "object"
        out.append(Detection(
            label=label,
            confidence=conf,
            bbox=(x1 * sx / frame_hw[1], y1 * sy / frame_hw[0],
                  (x2 - x1) * sx / frame_hw[1], (y2 - y1) * sy / frame_hw[0]),
        ))
    return out


def nms(boxes, scores, iou_thr: float = 0.45) -> List[int]:
    """Non-maximum suppression over normalized (x,y,w,h) boxes.

    Identical greedy semantics either way ("take the best box, drop everything
    it overlaps") — the numpy path only changes *how many* candidates we can
    afford. The pure-Python loop is O(n^2) with an interpreted `iou()` per
    pair; measured at ~800 ms for a dense CPU head (~20k candidates above a
    low confidence threshold). That is a whole frame budget burned on
    de-duplication, so the vectorized implementation is the default whenever
    numpy is importable, and the readable Python loop remains the fallback.
    """
    if not boxes:
        return []
    try:
        import numpy as np
    except Exception:
        np = None  # numpy is optional for the reference paths
    if np is None:
        order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        keep: List[int] = []
        while order:
            i = order.pop(0)
            keep.append(i)
            order = [j for j in order if iou(boxes[i], boxes[j]) <= iou_thr]
        return keep

    b = np.asarray(boxes, dtype=np.float32).reshape(-1, 4)
    s = np.asarray(scores, dtype=np.float32).reshape(-1)
    if b.shape[0] == 0:
        return []
    x1, y1 = b[:, 0], b[:, 1]
    x2, y2 = b[:, 0] + b[:, 2], b[:, 1] + b[:, 3]
    areas = np.clip(b[:, 2], 0, None) * np.clip(b[:, 3], 0, None)
    # Ties keep original order (stable) exactly like the Python sort.
    order = np.argsort(-s, kind="stable")
    keep_np: list[int] = []
    while order.size:
        i = int(order[0])
        keep_np.append(i)
        if order.size == 1:
            break
        rest = order[1:]
        ix = np.clip(np.minimum(x2[i], x2[rest]) - np.maximum(x1[i], x1[rest]), 0, None)
        iy = np.clip(np.minimum(y2[i], y2[rest]) - np.maximum(y1[i], y1[rest]), 0, None)
        inter = ix * iy
        union = areas[i] + areas[rest] - inter
        # union == 0 means two degenerate boxes: IoU is 0 (same as `iou()`).
        overlap = np.where(union > 0, inter / np.where(union > 0, union, 1.0), 0.0)
        order = rest[overlap <= iou_thr]
    return keep_np


def _cap_candidates(boxes: list, scores: list[float], idxs: list[int],
                    max_candidates: int) -> tuple[list, list[float], list[int]]:
    """Keep only the highest-scoring `max_candidates` boxes before NMS.

    A detector head with thousands of low-confidence candidates (crowded
    plaza, lowered confidence threshold) makes NMS the dominant per-frame cost
    for no accuracy benefit — the tracker cannot consume hundreds of objects
    from one camera anyway. Capping is what bounds the worst case, and it is
    the same `max_det` discipline mainstream exports apply in-model.
    """
    if max_candidates <= 0 or len(scores) <= max_candidates:
        return boxes, scores, idxs
    top = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:max_candidates]
    top.sort()  # preserve original order; NMS re-sorts by score internally
    return ([boxes[i] for i in top], [scores[i] for i in top], [idxs[i] for i in top])


def postprocess_yolo(
    raw,
    labels: List[str],
    conf_thr: float,
    iou_thr: float = 0.45,
    in_hw: tuple = (640, 640),
    frame_hw: tuple = (360, 640),
    max_candidates: int = MAX_CANDIDATES,
) -> List[Detection]:
    """Convert a YOLO-style ONNX output to Detections.

    Handles BOTH export layouts (auto-detected by shape):
      * row-major  [N, 5+classes]   — columns x,y,w,h (center, px) + scores
        (legacy v5/v6 exports; what the original implementation assumed)
      * transposed [4+classes, N]    — rows cx,cy,w,h (px) + one row per class
        score, one column per anchor — the layout every ultralytics v8/v11
        detect export actually produces. The old code read this as rows and
        produced garbage bboxes at near-zero confidence, i.e. no detections.
    Boxes are in model input pixel space; rescaled to normalized frame space.
    Pure enough to unit-test with tiny synthetic tensors.
    """
    try:
        import numpy as np
    except Exception as exc:  # pragma: no cover - numpy is a runtime dep for real models
        raise RuntimeError("numpy is required for ONNX/TensorRT/OpenVINO/TFLite backends") from exc

    arr = np.asarray(raw)
    if arr.ndim == 3:
        arr = arr[0]
    if arr.ndim != 2:
        return []

    sx = frame_hw[1] / in_hw[1]
    sy = frame_hw[0] / in_hw[0]

    # ── layout detection ───────────────────────────────────────────────────
    # row-major [N, 5+classes] needs ≥6 columns; transposed [4+classes, N]
    # needs ≥6 rows. When both could parse, real exports put thousands of
    # anchors on the LONG axis (shape[1] >> shape[0]) — anchors outnumber
    # 4+80 classes by an order of magnitude, so long-axis wins.
    if arr.shape[1] < 6:
        transposed = True
    elif arr.shape[0] < 6:
        transposed = False
    else:
        transposed = arr.shape[1] > arr.shape[0]

    # ── layout: [4+classes, N] transposed (ultralytics v8/v11) ──────────
    if transposed:
        boxes_px = arr[:4, :]                      # (4, N) cx,cy,w,h
        cls_scores = arr[4:, :]                    # (classes, N)
        best = np.argmax(cls_scores, axis=0)       # (N,)
        conf = cls_scores[best, np.arange(arr.shape[1])]
        keep = conf >= conf_thr
        xs, ys, ws, hs = boxes_px[0], boxes_px[1], boxes_px[2], boxes_px[3]
        boxes_n, scores_n, idxs = [], [], []
        for j in np.nonzero(keep)[0]:
            x1 = (xs[j] - ws[j] / 2) * sx
            y1 = (ys[j] - hs[j] / 2) * sy
            boxes_n.append((float(x1 / frame_hw[1]), float(y1 / frame_hw[0]),
                            float((ws[j] * sx) / frame_hw[1]), float((hs[j] * sy) / frame_hw[0])))
            scores_n.append(float(conf[j]))
            idxs.append(int(best[j]))
    # ── layout: [N, 5+classes] row-major (legacy) ─────────────────────────
    else:
        boxes_px = arr[:, :4]
        cls_scores = arr[:, 4:]
        boxes_n, scores_n, idxs = [], [], []
        for row in range(arr.shape[0]):
            label_idx = int(np.argmax(cls_scores[row]))
            row_conf = float(cls_scores[row][label_idx])
            if row_conf < conf_thr:
                continue
            x, y, w, h = boxes_px[row]
            x1 = (x - w / 2) * sx
            y1 = (y - h / 2) * sy
            boxes_n.append((float(x1 / frame_hw[1]), float(y1 / frame_hw[0]),
                            float((w * sx) / frame_hw[1]), float((h * sy) / frame_hw[0])))
            scores_n.append(row_conf)
            idxs.append(label_idx)

    detections: List[Detection] = []
    boxes_n, scores_n, idxs = _cap_candidates(boxes_n, scores_n, idxs, max_candidates)
    for i in nms(boxes_n, scores_n, iou_thr):
        label = labels[idxs[i]] if idxs[i] < len(labels) else f"class_{idxs[i]}"
        detections.append(Detection(label=label, confidence=float(scores_n[i]), bbox=tuple(boxes_n[i])))  # type: ignore[arg-type]
    return detections


class _RuntimeDetector(Detector):
    """Shared base for ONNX/TensorRT/OpenVINO/TFLite: same preprocessing + NMS."""

    model_version: str = "onnx-v0"
    dimension: int = 0

    def __init__(
        self,
        model_path: str,
        labels: List[str] | None = None,
        conf_thr: float = 0.45,
        iou_thr: float = 0.45,
        in_hw: tuple = (640, 640),
        frame_hw: tuple = (360, 640),
    ) -> None:
        self.model_path = model_path
        # Default to the COCO vocabulary: every mainstream detect export
        # (YOLOv5/v8/v11, RT-DETR) is COCO-trained. The platform vocabulary
        # (person/vehicle/bicycle/animal/bag/…) is applied by the
        # _LabelMappedDetector wrapper at the build_detector boundary.
        self.labels = labels if labels is not None else _COCO_LABELS
        self.conf_thr = conf_thr
        self.iou_thr = iou_thr
        self.in_hw = in_hw
        self.frame_hw = frame_hw
        self._session = None
        # Inference watchdog (reliability plan F6): a wedged accelerator shows
        # up as runaway single-call latency. Overridable for slow hosts.
        import os

        self.watchdog_sec = float(os.environ.get("AI_INFERENCE_WATCHDOG_SEC", "15"))
        self._slow_streak = 0
        # Circuit breaker (reliability plan F1): a detector whose session is
        # permanently broken (corrupt CUDA context, unloaded plugin) would
        # otherwise burn a full inference attempt — and an exception log line —
        # on every sampled frame for the lifetime of the worker, starving the
        # other cameras on the box. After this many consecutive failures the
        # breaker opens for a cooldown window and the detector fails *open*
        # (returns no detections) instead of thrashing.
        self.circuit_threshold = int(os.environ.get("AI_DETECTOR_CIRCUIT_FAILURES", "5"))
        self.circuit_cooldown_sec = float(os.environ.get("AI_DETECTOR_CIRCUIT_COOLDOWN_SEC", "30"))
        self._error_streak = 0
        self._open_until = 0.0
        # Last single-call latency (ms) — read by the bench harness and the
        # camera-health surface; cheap, no histogram machinery. Written via
        # the _latency_ms property so __new__-built instances (tests construct
        # detectors without __init__) read 0.0 instead of raising.
        self._latency_ms = 0.0

    @property
    def last_inference_ms(self) -> float:
        return float(getattr(self, "_latency_ms", 0.0))

    @last_inference_ms.setter
    def last_inference_ms(self, value: float) -> None:
        self._latency_ms = float(value)

    def _ensure_session(self):
        raise NotImplementedError

    # ── circuit breaker state (defensive: __new__-built instances in tests) ──
    @property
    def breaker_open(self) -> bool:
        """True while inference is short-circuited after repeated failures."""
        import time as _time

        return float(getattr(self, "_open_until", 0.0)) > _time.monotonic()

    def _watched_infer(self, img):
        """Time one session.run; two consecutive over-watchdog calls rebuild
        the session so the next frame gets a fresh runtime instead of
        retrying into a wedged one. Detection-only: TensorRT/OpenVINO/TFLite
        subclasses inherit this through detect()."""
        import logging
        import time as _time

        t0 = _time.monotonic()
        out = self._infer(img)
        took = _time.monotonic() - t0
        self.last_inference_ms = took * 1000.0
        if took > self.watchdog_sec:
            self._slow_streak += 1
            if self._slow_streak >= 2:
                self._slow_streak = 0
                self._session = None  # rebuilt lazily by _ensure_session()
                logging.getLogger("localsight.detector").warning(
                    "inference watchdog: %s call took %.1fs (>%.0fs x2) — "
                    "session will be rebuilt", type(self).__name__, took,
                    self.watchdog_sec,
                )
        else:
            self._slow_streak = 0
        return out

    def _on_inference_error(self, exc: Exception) -> bool:
        """Record a failed inference; True once the breaker has just opened.

        Returns True only on the transition, so the caller can fail open
        without error-logging every subsequent frame during the cooldown.
        """
        import logging

        self._error_streak = int(getattr(self, "_error_streak", 0)) + 1
        if self._error_streak < int(getattr(self, "circuit_threshold", 5)):
            return False
        import time as _time

        self._error_streak = 0
        self._open_until = _time.monotonic() + float(
            getattr(self, "circuit_cooldown_sec", 30.0)
        )
        self._session = None  # a rebuilt session is the recovery path
        logging.getLogger("localsight.detector").error(
            "detector circuit breaker OPEN for %.0fs after %d consecutive "
            "%s failures (last: %s) — returning empty detections until the "
            "cooldown expires",
            getattr(self, "circuit_cooldown_sec", 30.0),
            int(getattr(self, "circuit_threshold", 5)),
            type(self).__name__, exc,
        )
        return True

    def detect(self, frame: object, ts) -> List[Detection]:
        if self.breaker_open:
            # Fail open: the pipeline keeps ticking (tracks age out, presence
            # events still close) while a broken runtime recovers. Half-open on
            # expiry — the next call gets one attempt with a fresh session.
            return []
        self._open_until = 0.0
        self._ensure_session()
        import numpy as np

        img = self._preprocess(np.asarray(frame) if not isinstance(frame, bytes) else self._decode(frame))
        try:
            out = self._watched_infer(img)
        except Exception as exc:  # breaker decision, re-raised below
            if self._on_inference_error(exc):
                return []  # breaker just opened: this frame yields no detections
            raise
        self._error_streak = 0
        arr = np.asarray(out)
        # END-TO-END (NMS-free) export: (batch, max_det, 6) — decode directly;
        # the classic transposed/row-major layouts fall through to the shared
        # postprocess_yolo decoder.
        if arr.ndim == 3 and arr.shape[2] == 6 and 0 < arr.shape[1] <= 1000:
            _, _, model_h, model_w = img.shape
            return postprocess_yolo_e2e(
                arr, self.labels, self.conf_thr,
                in_hw=(model_h, model_w), frame_hw=self.frame_hw,
            )
        # The padded input dims drive box scaling: _preprocess pads to a
        # stride multiple, so the model saw (padded_w, padded_h), and boxes
        # must map back through that geometry — not the nominal in_hw.
        _, _, model_h, model_w = img.shape
        return postprocess_yolo(
            out, self.labels, self.conf_thr, self.iou_thr,
            in_hw=(model_h, model_w), frame_hw=self.frame_hw,
        )

    def _decode(self, raw_rgb24: bytes):
        # rawvideo rgb24 -> HxWx3 uint8; frame_hw must match the configured size.
        import numpy as np

        h, w = self.frame_hw
        return np.frombuffer(raw_rgb24[: h * w * 3], dtype=np.uint8).reshape(h, w, 3)

    def _preprocess(self, img):
        import numpy as np

        # YOLO-family exports require input H/W divisible by the stride (32):
        # e.g. a 640x360 frame is rejected at inference ("concat axis
        # mismatch"). Pad the shorter side (letterbox, bottom/right) to the
        # next multiple of 32 and remember the scale+pad so boxes map back.
        arr = np.asarray(img).astype(np.float32) / 255.0
        if arr.ndim == 3:
            arr = arr.transpose(2, 0, 1)  # HWC → CHW
        _, h, w = arr.shape
        target_h = ((h + 31) // 32) * 32
        target_w = ((w + 31) // 32) * 32
        if (target_h, target_w) != (h, w):
            padded = np.zeros((arr.shape[0], target_h, target_w), dtype=np.float32)
            padded[:, :h, :w] = arr
            arr = padded
        return np.expand_dims(arr, 0)

    def _preprocess_ctx(self, frame_hw):
        """Scale (frame→model) implied by the stride-padding in _preprocess."""
        return 1.0

    def _infer(self, img):  # pragma: no cover - runtime specific
        raise NotImplementedError


class ONNXDetector(_RuntimeDetector):
    """ONNX Runtime detector with an env-tunable execution plan (roadmap A1).

    Three knobs decide whether an INT8/edge deployment actually hits its
    latency budget, and all three are deployment-specific — so they are env
    overrides rather than hard-coded choices:

      AI_DETECTOR_PROVIDER   explicit EP preference list, comma-separated
                             (e.g. "TensorrtExecutionProvider,CUDAExecutionProvider").
                             Unset = auto: CUDA → CoreML → CPU.
      AI_ORT_INTRA_THREADS   intra-op thread pool size. Default 0 = ORT's own
                             heuristic, which over-subscribes on a box running
                             one worker thread per camera — pinning this is the
                             single biggest win for 6+ camera CPU deployments.
      AI_ORT_GRAPH_OPT       disable | basic | extended | all (default all).
    """

    def _ensure_session(self):
        if self._session is not None:
            return
        try:
            import onnxruntime as ort
        except Exception as exc:
            raise RuntimeError("onnxruntime is not installed (pip install onnxruntime)") from exc
        import os

        # Providers not installed on this host are dropped (CoreML on macOS,
        # CUDA on non-NVIDIA) so onnxruntime doesn't warn on every session build.
        available = set(ort.get_available_providers())
        override = os.environ.get("AI_DETECTOR_PROVIDER", "").strip()
        if override:
            wanted = [p.strip() for p in override.split(",") if p.strip()]
            missing = [p for p in wanted if p not in available]
            if missing:
                raise RuntimeError(
                    f"AI_DETECTOR_PROVIDER names unavailable provider(s) {missing} "
                    f"(available: {sorted(available)})"
                )
            preferred = wanted
        else:
            preferred = [p for p in ("CUDAExecutionProvider", "CoreMLExecutionProvider",
                                     "CPUExecutionProvider") if p in available]

        opts = ort.SessionOptions()
        opts.graph_optimization_level = {
            "disable": ort.GraphOptimizationLevel.ORT_DISABLE_ALL,
            "basic": ort.GraphOptimizationLevel.ORT_ENABLE_BASIC,
            "extended": ort.GraphOptimizationLevel.ORT_ENABLE_EXTENDED,
            "all": ort.GraphOptimizationLevel.ORT_ENABLE_ALL,
        }.get(
            os.environ.get("AI_ORT_GRAPH_OPT", "all").strip().lower(),
            ort.GraphOptimizationLevel.ORT_ENABLE_ALL,
        )
        threads = int(os.environ.get("AI_ORT_INTRA_THREADS", "0") or 0)
        if threads > 0:
            opts.intra_op_num_threads = threads
            opts.inter_op_num_threads = 1
        opts.enable_mem_pattern = True  # stable shapes (letterboxed input)
        self._session = ort.InferenceSession(self.model_path, sess_options=opts,
                                             providers=preferred)
        self._input_name = self._session.get_inputs()[0].name

    def _infer(self, img):
        return self._session.run(None, {self._input_name: img})[0]


class TensorRTDetector(_RuntimeDetector):
    def _ensure_session(self):
        if self._session is not None:
            return
        try:
            import tensorrt as trt  # noqa: F401
        except Exception as exc:
            raise RuntimeError("tensorrt is not installed (NVIDIA Jetson / dGPU required)") from exc
        # Engine loading is site-specific; the registry guarantees the .engine file.
        self._session = self.model_path  # placeholder; real load in deploy docs

    def _infer(self, img):  # pragma: no cover - requires GPU engine
        raise NotImplementedError("TensorRT engine execution requires the staged .engine file")


class OpenVINODetector(_RuntimeDetector):
    def _ensure_session(self):
        if self._session is not None:
            return
        try:
            from openvino import runtime as ov
        except Exception as exc:
            raise RuntimeError("openvino is not installed (Intel tier required)") from exc
        core = ov.Core()
        self._session = core.compile_model(self.model_path, "AUTO")

    def _infer(self, img):
        return list(self._session(img).values())[0]


class TFLiteDetector(_RuntimeDetector):
    def _ensure_session(self):
        if self._session is not None:
            return
        try:
            import tflite_runtime.interpreter as tfl
        except Exception as exc:
            raise RuntimeError("tflite_runtime is not installed (Edge TPU / ARM)") from exc
        self._session = tfl.Interpreter(model_path=self.model_path)
        self._session.allocate_tensors()

    def _infer(self, img):
        self._session.set_tensor(self._session.get_input_details()[0]["index"], img)
        self._session.invoke()
        return self._session.get_tensor(self._session.get_output_details()[0]["index"])


class ReferenceMotionDetector(Detector):
    """Classical frame-differencing person/vehicle proxy.

    Runs without any model download. It is *not* a substitute for a real detector
    (higher false-negative rate), but it makes the full pipeline genuinely
    functional on CPU and is what the default deployment uses until an operator
    stages an ONNX model via the registry. Bboxes are coarse (full foreground blob).
    """

    model_version = "ref-motion-v0"

    def __init__(self, conf_thr: float = 0.5, min_area: float = 0.01) -> None:
        self.conf_thr = conf_thr
        self.min_area = min_area
        self._prev = None

    def detect(self, frame: object, ts) -> List[Detection]:
        try:
            import numpy as np
        except Exception:
            return []  # no numpy -> no detection (pipeline falls back to synthetic elsewhere)
        if isinstance(frame, bytes):
            # caller should pass decoded frames; if bytes, skip to avoid guessing size
            return []
        img = np.asarray(frame).astype(np.float32)
        if img.ndim == 3:
            gray = img.mean(axis=2)
        else:
            gray = img
        if self._prev is None:
            self._prev = gray
            return []
        diff = np.abs(gray - self._prev)
        self._prev = gray
        mask = (diff > 25.0).astype(np.float32)
        area = mask.sum() / max(1, mask.size)
        if area < self.min_area:
            return []
        ys, xs = np.where(mask > 0)
        if len(xs) == 0:
            return []
        h, w = mask.shape
        x1, y1, x2, y2 = xs.min() / w, ys.min() / h, xs.max() / w, ys.max() / h
        return [Detection(label="person", confidence=float(min(1.0, 0.5 + area * 5)),
                          bbox=(float(x1), float(y1), float(x2 - x1), float(y2 - y1)))]


_BACKENDS = {
    "onnx": ONNXDetector,
    "tensorrt": TensorRTDetector,
    "openvino": OpenVINODetector,
    "tflite": TFLiteDetector,
    "reference": ReferenceMotionDetector,
}

# COCO (80-class) → LocalSight label vocabulary. DEFAULT_LABELS is the
# platform's operator-facing set; staged COCO models emit COCO names, and
# rules/tracks/alerts key off LocalSight labels — map at the boundary.
_COCO_TO_LOCALSIGHT = {
    "person": "person",
    "bicycle": "bicycle",
    "car": "vehicle", "motorcycle": "motorcycle", "bus": "bus",
    "truck": "truck", "train": "vehicle", "airplane": "vehicle", "boat": "vehicle",
    "bird": "animal", "cat": "animal", "dog": "animal", "horse": "animal",
    "sheep": "animal", "cow": "animal", "elephant": "animal", "bear": "animal",
    "zebra": "animal", "giraffe": "animal",
    "backpack": "bag", "handbag": "bag", "suitcase": "bag",
    "cell phone": "package", "laptop": "package", "tv": "package",
}

_COCO_LABELS = [
    "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck",
    "boat", "traffic light", "fire hydrant", "stop sign", "parking meter", "bench",
    "bird", "cat", "dog", "horse", "sheep", "cow", "elephant", "bear", "zebra",
    "giraffe", "backpack", "umbrella", "handbag", "tie", "suitcase", "frisbee",
    "skis", "snowboard", "sports ball", "kite", "baseball bat", "baseball glove",
    "skateboard", "surfboard", "tennis racket", "bottle", "wine glass", "cup",
    "fork", "knife", "spoon", "bowl", "banana", "apple", "sandwich", "orange",
    "broccoli", "carrot", "hot dog", "pizza", "donut", "cake", "chair", "couch",
    "potted plant", "bed", "dining table", "toilet", "tv", "laptop", "mouse",
    "remote", "keyboard", "cell phone", "microwave", "oven", "toaster", "sink",
    "refrigerator", "book", "clock", "vase", "scissors", "teddy bear",
    "hair drier", "toothbrush",
]


class _LabelMappedDetector(Detector):
    """Wrap a staged COCO detector, remapping class names into the LocalSight
    vocabulary (person/vehicle/bicycle/animal/bag/…) and dropping classes with
    no platform meaning (rules, alerts, and analytics key on our labels)."""

    def __init__(self, inner: Detector) -> None:
        self._inner = inner
        self.model_version = inner.model_version

    def detect(self, frame, ts) -> List[Detection]:
        out: List[Detection] = []
        for d in self._inner.detect(frame, ts):
            mapped = _COCO_TO_LOCALSIGHT.get(d.label)
            if mapped is None:
                continue
            out.append(Detection(label=mapped, confidence=d.confidence, bbox=d.bbox))
        return out


def build_detector(
    settings,
    registry: ModelRegistry,
    backend: str | None = None,
):
    """Construct a Detector from configuration.

    backend "reference" (default / no model staged) returns the classical fallback.
    Any model-backed backend loads & verifies the staged artifact from the registry
    (fail-closed on hash mismatch). Staged COCO models are wrapped so the
    platform's label vocabulary (person/vehicle/bicycle/animal/bag/…) is what
    rules, tracks, and alerts see — COCO-only classes are dropped.
    """
    backend = backend or settings.ai_detector
    if backend in ("reference", "synthetic"):
        return ReferenceMotionDetector(conf_thr=settings.ai_confidence_threshold)
    if backend not in _BACKENDS:
        raise RuntimeError(f"unknown AI_DETECTOR backend: {backend}")
    model_name = getattr(settings, "ai_model_name", "detector")
    version = getattr(settings, "ai_model_version", "latest")
    rec = registry.get(model_name, version)
    if not registry.verify(model_name, version):
        raise RuntimeError(f"model {model_name}@{version} failed integrity check")
    inner = _BACKENDS[backend](rec.path, conf_thr=settings.ai_confidence_threshold)
    return _LabelMappedDetector(inner)
