"""Appearance-attribute tagging (clothing): "jacket", hi-vis, colors, bags.

Zero-shot via a staged CLIP image encoder: person-track crops are embedded and
compared against precomputed text-prompt vectors, so NEW attributes (a jacket
classifier, vest colors, backpack/hat) are an operator vocabulary edit — no
retraining, no new model. The prompt vectors are generated ONCE at stage time
from the SAME CLIP checkpoint (procedure in docs/operations/onnx-detector.md)
and staged as `attribute_prompts` beside the `attribute_encoder` ONNX; the
loader refuses a checkpoint/embedding mismatch (staged-artifact integrity).

Privacy posture: clothing tags are non-biometric operational context (search:
"person in red jacket"). They are sampled per TRACK (never per frame), stored
in Track/Event JSON detail (covered by the retention sweep), and are safe for
alert fan-out (no ciphertext, no biometric).
"""
from __future__ import annotations

# CLIP ViT-B/32 canonical normalization (OpenAI reference values).
_CLIP_MEAN = (0.48145466, 0.4578275, 0.40821073)
_CLIP_STD = (0.26862954, 0.26130258, 0.27577711)
_CLIP_INPUT = 224
# CLIP's learned logit scale (temperature⁻¹) — softmax sharpness for
# prompt-group distributions; 100 is the trained checkpoint's value.
_CLIP_LOGIT_SCALE = 100.0


class AttributeTagger:
    """Interface: tag a person crop with flat JSON-safe attributes."""

    model_version: str = "attr-ref-v0"

    def tag(self, crop) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class ReferenceAttributeTagger(AttributeTagger):
    """Deterministic placeholder (no staged model): brightness/aspect
    heuristics over the crop produce a stable, honestly-labeled tag set.
    Exists so the sampling + persistence path is exercisable end-to-end and
    the downgrade is visible, not silent."""

    model_version = "attr-ref-v0"

    def tag(self, crop) -> dict:
        try:
            import numpy as np

            arr = np.asarray(crop)
            if arr.ndim != 3 or arr.size == 0:
                return {}
            gray = arr.astype(np.float32).mean(axis=2)
            upper = float(gray[: gray.shape[0] // 2].mean())
            lower = float(gray[gray.shape[0] // 2 :].mean())
            return {
                "jacket": bool(upper < lower),  # darker torso reads "jacketed"
                "jacket_conf": 0.5,  # reference: no real confidence
                "source": "reference",
            }
        except Exception:
            return {}


class ClipAttributeTagger(AttributeTagger):
    """CLIP zero-shot attribute tagging from staged, verified artifacts."""

    model_version = "attr-clip-v1"

    def __init__(self, model_path: str, prompts_path: str) -> None:
        import json

        with open(prompts_path, encoding="utf-8") as fh:
            spec = json.load(fh)
        declared = str(spec.get("image_encoder_sha256", ""))
        if not declared:
            raise RuntimeError("attribute_prompts missing image_encoder_sha256")
        from packages.ai.registry import ModelRegistry

        actual = ModelRegistry._sha256(model_path)
        if actual != declared:
            raise RuntimeError(
                "attribute_prompts text embeddings were generated from a "
                "different CLIP checkpoint than the staged image encoder "
                f"({declared[:12]}… != {actual[:12]}…) — refusing to mix "
                "embedding spaces"
            )
        rows: list[list[float]] = []
        self._groups: list[dict] = []
        for group in spec.get("groups", []):
            items = group.get("items", [])
            if len(items) < 2:
                continue
            vecs = [list(map(float, it["vector"])) for it in items]
            dim = len(vecs[0])
            if any(len(v) != dim for v in vecs):
                raise RuntimeError(f"ragged vectors in group {group.get('group')!r}")
            rows.extend(vecs)
            self._groups.append({
                "name": group["group"],
                "labels": [it.get("label", it.get("text", "")) for it in items],
                "start": len(rows) - len(vecs),
            })
        if not rows:
            raise RuntimeError("attribute_prompts carries no usable groups")
        import numpy as np

        mat = np.asarray(rows, dtype=np.float32)
        self._mat = mat / (np.linalg.norm(mat, axis=1, keepdims=True) + 1e-9)

        import onnxruntime as ort

        available = set(ort.get_available_providers())
        preferred = [p for p in ("CUDAExecutionProvider", "CoreMLExecutionProvider",
                                 "CPUExecutionProvider") if p in available]
        self._sess = ort.InferenceSession(model_path, providers=preferred)
        self._name = self._sess.get_inputs()[0].name

    @staticmethod
    def _resize_nn(arr, size: int):
        import numpy as np

        ys = (np.arange(size) * arr.shape[0] // size)
        xs = (np.arange(size) * arr.shape[1] // size)
        return arr[ys][:, xs]

    def tag(self, crop) -> dict:
        import numpy as np

        arr = np.asarray(crop)
        if arr.ndim != 3 or arr.shape[0] < 8 or arr.shape[1] < 8:
            return {}
        small = self._resize_nn(arr[:, :, :3], _CLIP_INPUT).astype(np.float32) / 255.0
        mean = np.asarray(_CLIP_MEAN, dtype=np.float32)
        std = np.asarray(_CLIP_STD, dtype=np.float32)
        small = (small - mean) / std
        blob = small.transpose(2, 0, 1)[None]  # HWC → 1CHW
        try:
            vec = self._sess.run(None, {self._name: blob})[0][0].astype(np.float32)
        except Exception:
            return {}
        vec = vec / (np.linalg.norm(vec) + 1e-9)
        sims = self._mat @ vec

        tags: dict = {}
        for g in self._groups:
            seg = sims[g["start"] : g["start"] + len(g["labels"])]
            # softmax at CLIP's logit scale over the group's prompt sims
            e = np.exp((seg - seg.max()) * _CLIP_LOGIT_SCALE)
            probs = e / e.sum()
            k = int(np.argmax(probs))
            tags[g["name"]] = g["labels"][k]
            tags[f"{g['name']}_conf"] = round(float(probs[k]), 3)
        return tags


def build_attribute_tagger(registry, *, enabled: bool) -> AttributeTagger | None:
    """Attribute-tagger factory (optional capability — never fatal).

    Disabled → None. Enabled but artifacts missing/unverified/mismatched →
    logged downgrade to the deterministic reference tagger.
    """
    import logging

    log = logging.getLogger("localsight.attributes")
    if not enabled:
        return None
    try:
        enc = registry.get("attribute_encoder", "latest")
        pr = registry.get("attribute_prompts", "latest")
        if not (registry.verify("attribute_encoder", "latest")
                and registry.verify("attribute_prompts", "latest")):
            raise RuntimeError("staged attribute artifacts failed integrity check")
        tagger = ClipAttributeTagger(enc.path, pr.path)
        log.info("attributes: staged CLIP encoder + prompt embeddings loaded")
        return tagger
    except Exception as exc:
        log.warning(
            "attribute tagging falling back to the reference tagger "
            "(staged attribute models unavailable: %s)", exc,
        )
        return ReferenceAttributeTagger()
