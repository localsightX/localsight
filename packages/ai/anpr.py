"""License Plate Recognition (ANPR/LPR) module.

Privacy note: plates are *identifiers*, not biometrics, but they are still
personal data under GDPR. Plates are stored encrypted (only the match result and
an anonymized hash are kept by default), and watchlist matching is opt-in.

The module defines a pluggable pipeline:
  PlateDetector  -> locate a plate rectangle in a tracked vehicle crop
  PlateOCR       -> recognize the plate string from the rectangle
  ANPRPipeline   -> ties detection + OCR + optional watchlist into events.

A deterministic ReferenceANPR is provided so the pipeline is exercisable without a
staged OCR model; production swaps in a real plate detector + OCR (OpenALPR-class)
behind the same interfaces.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Normalized plate rectangle is (x,y,w,h); crop is an opaque pixel object.
PlateRect = tuple[float, float, float, float]


class PlateDetector:
    def detect(self, crop, ts) -> PlateRect | None:  # pragma: no cover - interface
        raise NotImplementedError


class PlateOCR:
    def recognize(self, crop, rect: PlateRect, ts) -> str | None:  # pragma: no cover
        raise NotImplementedError


_PLATE_RE = re.compile(r"^[A-Z0-9][A-Z0-9\- ]{2,11}[A-Z0-9]$")


@dataclass
class PlateReading:
    plate: str
    confidence: float
    rect: PlateRect
    country: str | None = None


class ReferencePlateDetector(PlateDetector):
    """Reference: assumes the plate occupies the lower-center of a vehicle crop."""

    def detect(self, crop, ts) -> PlateRect | None:
        return (0.25, 0.55, 0.5, 0.25)


class ReferencePlateOCR(PlateOCR):
    """Reference: deterministic plate derived from the crop bytes (no real OCR)."""

    def __init__(self, seed_plate: str = "ABC123") -> None:
        self.seed = seed_plate

    def recognize(self, crop, rect: PlateRect, ts) -> str | None:
        if isinstance(crop, (bytes, bytearray)):
            import hashlib

            h = hashlib.sha256(bytes(crop)).hexdigest()[:6].upper()
            return f"REF-{h}"
        return self.seed


class ANPRPipeline:
    def __init__(
        self,
        detector: PlateDetector,
        ocr: PlateOCR,
        watchlist: set | None = None,
        conf_thr: float = 0.6,
    ) -> None:
        self.detector = detector
        self.ocr = ocr
        self.watchlist = watchlist or set()
        self.conf_thr = conf_thr

    @staticmethod
    def normalize(plate: str) -> str:
        return re.sub(r"[^A-Z0-9]", "", plate.upper())

    def read(self, crop, ts) -> PlateReading | None:
        rect = self.detector.detect(crop, ts)
        if not rect:
            return None
        raw = self.ocr.recognize(crop, rect, ts)
        if not raw:
            return None
        norm = self.normalize(raw)
        if not _PLATE_RE.match(norm):
            return None
        return PlateReading(plate=norm, confidence=0.9, rect=rect)

    def match_watchlist(self, reading: PlateReading) -> str | None:
        if reading is None:
            return None
        if reading.plate in self.watchlist:
            return reading.plate
        return None


# ── staged-model chain (production) ─────────────────────────────────────────
#
# Real ANPR = two operator-staged, hash-verified ONNX models behind the SAME
# PlateDetector/PlateOCR interfaces (rule 9: swap implementations, never fetch
# at runtime):
#
#   plate_detector  — single-class YOLO-style detect export ("plate"), consumed
#                     through the exact same layout-flexible decoder as the
#                     main object detector (row-major v5 AND transposed
#                     v8/v11/26 exports both work).
#   plate_ocr       — CTC (CRNN/SVTR-style) recognizer. Defaults follow the
#                     PaddleOCR PP-OCRv4 rec convention (h=48, width ≤320,
#                     (x/255-0.5)/0.5, BGR order) so a `paddleocr` export is a
#                     drop-in; a differently-trained CRNN overrides via ctor.
#   plate_charset   — optional staged charset file (one char per line); absent
#                     → alphanumeric default.

DEFAULT_OCR_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_OCR_MEAN = 0.5
_OCR_STD = 0.5


def ctc_greedy_decode(idx_seq, charset: list[str], blank: int = 0) -> str:
    """Greedy CTC: drop blanks, collapse repeats, map index→charset.

    Pure Python over argmax indices so it is unit-testable without numpy.
    Index `i>blank` maps to `charset[i-1]` (index 0 is reserved for blank).
    """
    out: list[str] = []
    prev = blank
    for i in idx_seq:
        i = int(i)
        if i != prev and i != blank:
            j = i - 1
            if 0 <= j < len(charset):
                out.append(charset[j])
        prev = i
    return "".join(out)


def ctc_from_logits(logits, charset: list[str], blank: int = 0) -> str:
    """Argmax over a (T, C) (or (1, T, C)) logits tensor, then CTC decode."""
    import numpy as np

    arr = np.asarray(logits)
    if arr.ndim == 3:
        arr = arr[0]
    if arr.ndim != 2:
        return ""
    return ctc_greedy_decode(arr.argmax(axis=-1), charset, blank=blank)


class OnnxPlateDetector(PlateDetector):
    """Single-class YOLO plate detector over a vehicle crop.

    Wraps the production `ONNXDetector` (letterbox preprocessing, both export
    layouts, GPU-when-available session) with `labels=["plate"]` and returns
    the best-confidence box as a normalized PlateRect within the crop.
    """

    def __init__(self, model_path: str, conf_thr: float = 0.35) -> None:
        from packages.ai.detectors import ONNXDetector

        self._impl = ONNXDetector(model_path, labels=["plate"], conf_thr=conf_thr)

    def detect(self, crop, ts) -> PlateRect | None:
        import numpy as np

        arr = np.asarray(crop)
        if arr.ndim != 3 or arr.shape[0] < 8 or arr.shape[1] < 8:
            return None
        # The wrapper normalizes boxes against frame_hw; a crop's dims vary
        # per vehicle, so retarget before decoding (session stays cached).
        self._impl.frame_hw = (arr.shape[0], arr.shape[1])
        try:
            dets = self._impl.detect(arr, ts)
        except Exception:
            return None
        if not dets:
            return None
        best = max(dets, key=lambda d: d.confidence)
        return tuple(best.bbox)  # type: ignore[return-value]


class OnnxPlateOCR(PlateOCR):
    """CTC OCR over the detected plate rectangle (staged ONNX)."""

    def __init__(
        self,
        model_path: str,
        charset: list[str] | None = None,
        *,
        img_h: int = 48,
        img_w: int = 320,
        bgr: bool = True,
        mean: float = _OCR_MEAN,
        std: float = _OCR_STD,
    ) -> None:
        self.model_path = model_path
        self.charset = list(charset) if charset else list(DEFAULT_OCR_CHARSET)
        self.img_h = img_h
        self.img_w = img_w
        self.bgr = bgr
        self.mean = mean
        self.std = std
        self._sess = None
        self._name: str = ""

    def _ensure_session(self) -> None:
        if self._sess is not None:
            return
        import onnxruntime as ort

        available = set(ort.get_available_providers())
        preferred = [p for p in ("CUDAExecutionProvider", "CoreMLExecutionProvider",
                                 "CPUExecutionProvider") if p in available]
        self._sess = ort.InferenceSession(self.model_path, providers=preferred)
        self._name = self._sess.get_inputs()[0].name

    @staticmethod
    def _resize_nn(arr, h: int, w: int):
        """Nearest-neighbour resize (HWC) — no OpenCV dependency."""
        import numpy as np

        ys = (np.arange(h) * arr.shape[0] // h)
        xs = (np.arange(w) * arr.shape[1] // w)
        return arr[ys][:, xs]

    def recognize(self, crop, rect: PlateRect, ts) -> str | None:
        import numpy as np

        arr = np.asarray(crop)
        if arr.ndim != 3 or arr.shape[0] < 4 or arr.shape[1] < 4:
            return None
        h, w = arr.shape[:2]
        x, y, bw, bh = rect
        x1 = max(0, int(x * w))
        y1 = max(0, int(y * h))
        x2 = min(w, int((x + bw) * w))
        y2 = min(h, int((y + bh) * h))
        if x2 - x1 < 4 or y2 - y1 < 4:
            return None
        patch = arr[y1:y2, x1:x2]
        # Fixed input height, aspect-preserving width (clipped to img_w).
        rh = self.img_h
        rw = max(4, min(self.img_w, int(patch.shape[1] * rh / patch.shape[0])))
        patch = self._resize_nn(patch, rh, rw)
        canvas = np.zeros((rh, self.img_w, 3), dtype=patch.dtype)
        canvas[:, :rw] = patch
        if self.bgr:
            canvas = canvas[:, :, ::-1]  # RGB frames → BGR models (PP-OCR)
        xx = canvas.astype(np.float32) / 255.0
        xx = (xx - self.mean) / self.std
        blob = xx.transpose(2, 0, 1)[None]  # HWC → 1CHW

        self._ensure_session()
        try:
            logits = self._sess.run(None, {self._name: blob})[0]
        except Exception:
            return None
        return ctc_from_logits(logits, self.charset) or None


def build_anpr(registry, *, enabled: bool, conf_thr: float = 0.6,
               det_conf_thr: float = 0.35) -> ANPRPipeline | None:
    """ANPR chain factory (optional capability — never fatal).

    Disabled → None (pipeline skips the ANPR stage). Enabled but the staged
    models are missing/unverified → logged downgrade to the reference chain,
    exactly like the face chain: ANPR must degrade loudly, not crash cameras.
    """
    import logging

    log = logging.getLogger("localsight.anpr")
    if not enabled:
        return None
    try:
        det_rec = registry.get("plate_detector", "latest")
        ocr_rec = registry.get("plate_ocr", "latest")
        if not (registry.verify("plate_detector", "latest")
                and registry.verify("plate_ocr", "latest")):
            raise RuntimeError("staged ANPR models failed integrity check")
        charset: list[str] = list(DEFAULT_OCR_CHARSET)
        try:
            cs = registry.get("plate_charset", "latest")
            if registry.verify("plate_charset", "latest"):
                with open(cs.path, encoding="utf-8") as fh:
                    charset = [ln.rstrip("\r\n") for ln in fh if ln.strip()]
        except KeyError:
            pass  # optional: alphanumeric default stands in
        log.info("ANPR: staged ONNX plate detector + OCR loaded")
        return ANPRPipeline(
            OnnxPlateDetector(det_rec.path, conf_thr=det_conf_thr),
            OnnxPlateOCR(ocr_rec.path, charset),
            conf_thr=conf_thr,
        )
    except Exception as exc:
        log.warning(
            "ANPR falling back to the reference chain "
            "(staged plate models unavailable: %s)", exc,
        )
        return ANPRPipeline(
            ReferencePlateDetector(), ReferencePlateOCR(), conf_thr=conf_thr,
        )
