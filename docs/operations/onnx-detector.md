# Multi-Class Object Detection (ONNX)

LocalSight's `Detector` interface is pluggable; the production-ready backend
is `ONNXDetector`, which runs any ONNX-exported YOLO/RT-DETR model via
`onnxruntime`. A `ReferenceMotionDetector` fallback ensures the full pipeline
runs on CPU without a model.

## Available backends

| Backend | Runtime | GPU | Model file needed | Code |
|---------|---------|-----|-------------------|------|
| `reference` | CPU (no GPU) | No | None (frame-differencing) | `ReferenceMotionDetector` |
| `onnx` | onnxruntime | CUDA when available | `.onnx` | `ONNXDetector` |
| `tensorrt` | TensorRT | NVIDIA only | `.engine` | `TensorRTDetector` (stub) |
| `openvino` | OpenVINO | Intel iGPU/NPU | `.xml` + `.bin` | `OpenVINODetector` (stub) |
| `tflite` | TFLite | ARM / Coral | `.tflite` | `TFLiteDetector` (stub) |

All backends are selected via the `AI_DETECTOR` env var. The factory in
`packages/ai/detectors.py:build_detector` looks up the model in the
`ModelRegistry`, verifies the SHA-256, and instantiates the backend.

## Class labels

The default label set is COCO-aligned and supports the common surveillance
classes:

```python
DEFAULT_LABELS = [
    "person", "vehicle", "bicycle", "motorcycle", "bus", "truck",
    "animal", "bag", "package",
]
```

These flow into:
- The `Detection.label` field of every detected object
- The `Event.event_type` taxonomy in the DB
- The behavior rules (e.g. line-crossing works for any label, not just "person")
- The `event_type_breakdown` analytics endpoint

## Quick start: enabling the ONNX detector

### 1. Stage a model

The ONNX detector requires a model file staged at a known path. LocalSight
**never downloads models from user-supplied URLs** — operators stage them
directly into the `models/` directory.

```bash
# 1. Create the registry config (one-time)
cat > models/registry.json <<EOF
{
  "models": [
    {
      "name": "yolo11n",
      "version": "v1.0.0",
      "path": "models/yolo11n.onnx",
      "hash_sha256": "<SHA-256 of the .onnx file>",
      "source": "Ultralytics YOLO11 (exported to ONNX)",
      "license": "AGPL-3.0"
    }
  ]
}
EOF

# 2. Copy the model file
cp /path/to/yolo11n.onnx models/yolo11n.onnx

# 3. Compute the hash and update the registry
sha256sum models/yolo11n.onnx
# Update the hash_sha256 field with the output
```

The hash verification happens in `ModelRegistry.verify()` (line 53-56). If the
on-disk hash doesn't match the registry, `build_detector()` raises a
`RuntimeError` and the worker fails to start the camera — this is by design.

### 2. Configure the worker

Set the following env vars in `.env`:

```bash
# Use the ONNX backend
AI_DETECTOR=onnx

# Point at the staged model
AI_MODEL_NAME=yolo11n
AI_MODEL_VERSION=v1.0.0

# Inference cadence (frames per second on the substream)
AI_INFERENCE_FPS=5

# Min confidence (0.0–1.0)
AI_CONFIDENCE_THRESHOLD=0.45

# Min IOU for the tracker
AI_IOU_THRESHOLD=0.50
```

### 3. Restart the worker

```bash
python -m apps.worker
```

On first frame, you'll see `ONNXDetector` initialize the inference session:

```
INFO  localsight.worker  starting pipeline for camera cam1 (Lobby)
```

### 4. Verify detection is working

Within a few seconds, the timeline should populate with new events. Check:

```bash
# Recent events for the camera
curl "http://localhost:8000/api/events?camera_id=$CAM&limit=10" \
  -H "Authorization: Bearer $TOKEN"
# => {"items": [{"event_type": "presence", "confidence": 0.87, ...}], ...}

# Event-type breakdown (multi-class proof)
curl "http://localhost:8000/api/analytics/breakdown" \
  -H "Authorization: Bearer $TOKEN"
# => {"rows": [
#       {"event_type": "presence", "count": 412},
#       {"event_type": "intrusion", "count": 23},
#       {"event_type": "line_cross", "count": 156}
#     ]}
```

## GPU acceleration

`ONNXDetector` automatically uses GPU when `onnxruntime-gpu` is installed and
a CUDA-capable GPU is present. The session is created with
`providers=("CUDAExecutionProvider", "CPUExecutionProvider")` so onnxruntime
selects CUDA first, falling back to CPU if the GPU is unavailable.

To enable GPU:

```bash
pip install onnxruntime-gpu
```

Verify the GPU is visible:

```bash
python -c "import onnxruntime as ort; print(ort.get_available_providers())"
# => ['CUDAExecutionProvider', 'CPUExecutionProvider']
```

CPU inference works on the same code path — there's no separate config knob.

## Use cases

### Use case 1: Person + vehicle counting at a parking entrance

A logistics yard needs to count cars entering and exiting. The default COCO
labels cover "car" → mapped to "vehicle" via the alias table. The behavior
rule engine emits a `line_cross` event for every car crossing the gate line.

```bash
# 1. Configure the line-cross rule on the entrance camera
curl -X PUT http://localhost:8000/api/cameras/$CAM/rules \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"rules": [
    {"type": "line_cross", "rule_id": "entrance-line",
     "a": [0.5, 0.0], "b": [0.5, 1.0], "direction": 1}
  ]}'

# 2. Query the count
curl "http://localhost:8000/api/analytics/people-count?camera_id=$CAM&start=...&end=..." \
  -H "Authorization: Bearer $TOKEN"
```

### Use case 2: Loitering detection at a retail doorway

A retail store wants to know how long customers linger near the entrance.
Loitering is a built-in rule that fires when an object stays inside a
polygon for `dwell_sec` seconds.

```json
{
  "rules": [
    {
      "type": "loitering",
      "rule_id": "entryway-loiter",
      "zone": [[0.0, 0.0], [1.0, 0.0], [1.0, 0.5], [0.0, 0.5]],
      "dwell_sec": 30
    }
  ]
}
```

### Use case 3: Intrusion in a no-go zone

A server room has a restricted zone. A multi-class detector can distinguish
"person" (genuine intrusion) from "animal" (a cat) to reduce false alerts.

```json
{
  "rules": [
    {
      "type": "intrusion",
      "rule_id": "server-room-zone",
      "zone": [[0.2, 0.2], [0.8, 0.2], [0.8, 0.8], [0.2, 0.8]]
    }
  ]
}
```

The alert route filters on `event_type == "intrusion"` to avoid cat-triggered
pages.

## Architectural details

### Preprocessing pipeline

`_RuntimeDetector._preprocess` performs letterbox-free resize + CHW float
conversion. The default expects:
- Input shape `(H, W, 3)` in RGB uint8
- Output shape `(1, 3, H', W')` in float32, normalized to [0, 1]

For YOLO models, the input resolution is `in_hw=(640, 640)` by default and
can be tuned via the `ONNXDetector.__init__` args.

### Output postprocessing

`postprocess_yolo()` (in `packages/ai/detectors.py:56-101`) converts the
raw YOLO output tensor (shape `[1, N, 5 + num_classes]`) into a list of
`Detection` objects:

1. **Per-class argmax + threshold**: for each row, pick the class with the
   highest score; drop rows below `conf_thr`.
2. **Coordinate conversion**: model-pixel `x, y, w, h` (center) → frame-normalized
   `(x, y, w, h)` (top-left).
3. **NMS**: pure-Python non-maximum suppression with `iou_thr=0.45` (tunable).

Bounding boxes in the output are **normalized [0, 1]**: `(x, y, w, h)` where
`(x, y)` is the top-left corner. This matches the rest of the pipeline.

### Pure-logic testability

The detector is split into pure functions (`iou`, `nms`, `postprocess_yolo`,
`_preprocess`, `_decode`) and side-effect-bearing methods (`_ensure_session`,
`_infer`). The pure functions are covered by 8 dedicated tests in
`tests/test_surveillance.py`:

- `test_iou_and_nms` — IoU math + NMS suppression
- `test_postprocess_yolo_synthetic` — full YOLO-output → Detection roundtrip
- `test_postprocess_yolo_rejects_low_conf` — confidence thresholding
- `test_postprocess_yolo_nms_removes_overlap` — NMS in action
- `test_onnx_detector_lazy_session` — `onnxruntime` import is deferred
- `test_runtime_detector_preprocess_and_decode` — preprocessing + RGB24 decode
- `test_build_detector_unknown_backend` — error handling
- `test_build_detector_tensorrt_not_installed` — runtime-not-installed path

Tests run without `onnxruntime` or `numpy` installed in the venv; they mock
the imports at the `sys.modules` level.

## Operational guidance

### Choosing a model

| Model | Size | Speed (RTX 3060) | mAP@50-95 | Recommended for |
|-------|------|------------------|-----------|-----------------|
| YOLOv8n (640) | 12 MB | 8 ms/frame | 37.3 | Edge / Jetson |
| YOLOv8s (640) | 22 MB | 12 ms/frame | 44.9 | Balance |
| YOLOv8m (640) | 52 MB | 25 ms/frame | 50.2 | Accuracy |
| YOLOv11n (640) | 5 MB | 5 ms/frame | 39.5 | Newest edge |
| RT-DETR-R50 (640) | 85 MB | 35 ms/frame | 53.1 | High accuracy |

For surveillance, **YOLOv8s** or **YOLOv11n** are good starting points.

### INT8 quantization for edge

For Jetson / Coral deployment, convert the ONNX model to INT8 using
`onnxruntime.quantization.quantize_dynamic`:

```python
from onnxruntime.quantization import quantize_dynamic, QuantType
quantize_dynamic(
    "models/yolo11n.onnx",
    "models/yolo11n_int8.onnx",
    weight_type=QuantType.QInt8,
)
```

Typically 2-2.5x speedup with < 1% mAP drop. Update the registry entry with
the new file path and hash.

Record the artifact as quantized so the bench report and the registry are
self-describing (never infer quantization from a filename):

```bash
python scripts/stage_model.py --name detector_int8 \
    --path models/staged/yolo11n_int8.onnx \
    --source "operator INT8 export of yolo11n-detect.onnx" \
    --license "AGPL-3.0 (Ultralytics YOLO11n, COCO-pretrained)" \
    --quantized
```

Then select it with `AI_MODEL_NAME=detector_int8`. For static-shape INT8,
export with a fixed 1x3x384x640 input (`onnxruntime.quantization.
quantize_static` + a small calibration set of frames from the target cameras)
— dynamic quantization is the pragmatic default, static is the fastest.

### Choosing between YOLO11n and YOLO26n

Both are staged the same way; only the upstream export differs.

```bash
# Operator-side export (their AGPL duty, their choice of runner), then:
python scripts/stage_model.py --name detector_yolo26 \
    --path models/staged/yolo26n.onnx \
    --source "https://github.com/ultralytics/assets (yolo26n export)" \
    --license "AGPL-3.0 (Ultralytics YOLO26n, COCO-pretrained)"
# AI_MODEL_NAME=detector_yolo26
```

Notes that matter in this codebase:

- **Export `nms=False`** (YOLO26's end-to-end head). The decoder in
  `packages/ai/detectors.py` detects the `(batch, max_det, 6)` layout and uses
  `postprocess_yolo_e2e` (no NMS pass, FP32-safe class ids) — measurably the
  cheapest decode we measure (`e2e_decode_ms` in the bench report).
- A classic `nms=True` export still works: both the row-major and the
  transposed v8/v11/v26 heads are auto-detected and decoded by
  `postprocess_yolo`.
- YOLO26n is the better default for CPU-only edge boxes (reported ~40 % faster
  CPU latency than YOLO11n at equal or better COCO mAP) and its STAL label
  assignment improves small/far-field objects — the long-corridor case where a
  640×360 substream is weakest.
- Model weights are **not** committed to this repository: they are
  operator-staged and hash-verified (AGPL-3.0 covered — see the license table
  at the top of this document).

### Reverting to the reference detector

If the ONNX model is misbehaving or you want to test without GPU, set:

```bash
AI_DETECTOR=reference
```

The `ReferenceMotionDetector` runs without any model download and uses pure
NumPy frame-differencing. It's intentionally less accurate — use it as a
sanity check, not production.

### Failure modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `RuntimeError: model detector@latest failed integrity check` | Hash mismatch in registry | Recompute `sha256sum` on the model file |
| `RuntimeError: onnxruntime is not installed` | Missing dep | `pip install onnxruntime` (or `onnxruntime-gpu`) |
| `RuntimeError: unknown AI_DETECTOR backend` | Typo in `AI_DETECTOR` | Use `reference`, `onnx`, `tensorrt`, `openvino`, or `tflite` |
| Camera `OFFLINE` after switching to ONNX | Worker can't init session | Check worker logs; verify `models/` is mounted in Docker |

## Staging the ANPR chain (plate_detector + plate_ocr)

ANPR is opt-in (`AI_ANPR_ENABLED=1`). With no staged models the pipeline logs a
downgrade and uses the reference chain (honest placeholder). The production
chain is two operator-staged, hash-verified ONNX models:

| Registry name | Artifact | Suggested source | License class |
|---|---|---|---|
| `plate_detector` | single-class YOLO detect export ("plate") | operator fine-tune (e.g. CCPD/Open-Images-derived) | verify per artifact |
| `plate_ocr` | CTC (CRNN/SVTR) recognizer, input `1×3×48×W` | PaddleOCR PP-OCRv4 rec export (convention built in: /255 → (x−0.5)/0.5, BGR, h=48, width ≤320 pad-right) | **Apache-2.0** |
| `plate_charset` (optional) | text file, one char per line, blank at CTC index 0 | from the OCR training dict | — |

```bash
python scripts/stage_model.py --name plate_detector --path models/staged/plate-det.onnx \
    --source "operator-trained YOLO plate detector" --license "see artifact"
python scripts/stage_model.py --name plate_ocr --path models/staged/ppocr-rec.onnx \
    --source "PaddleOCR PP-OCRv4 rec (ONNX export)" --license "Apache-2.0"
```

Both must verify (hash match) or the factory downgrades. CTC decode is greedy
over the argmax sequence (blank=0, repeats collapsed). Privacy: plate text is
envelope-encrypted (`plate_enc`); the searchable index is an **HMAC-SHA256
bound to the master key** (`plate_hash`) — never a bare SHA-256, which a
stolen DB could brute-force over the tiny plate keyspace.

## Staging the attribute chain (attribute_encoder + attribute_prompts)

Clothing attributes ("jacket", hi-vis, colors, backpack, hat) are CLIP
zero-shot: person-track crops are embedded by a staged CLIP image-encoder ONNX
and compared against prompt vectors generated **once** from the same
checkpoint (MIT-licensed OpenAI CLIP ViT-B/32 is a known-good source). The
vocabulary is an operator-editable JSON — new attributes need no retraining.

| Registry name | Artifact | Notes |
|---|---|---|
| `attribute_encoder` | CLIP image encoder, ONNX, 224×224 input | normalization baked to CLIP means/std |
| `attribute_prompts` | `{"image_encoder_sha256": …, "groups": [{"group": "jacket", "items": [{"text", "label", "vector"}]}]}` | vectors L2-normalized at load; the loader **refuses a checkpoint/embedding mismatch** |

Generate the prompt vectors once, operator-side (the AGPL/MS-licensing of the
training environment is the operator's choice, LocalSight ships neither code
nor weights):

```python
from PIL import Image
import torch, open_clip   # example: open_clip (Apache-2.0)
model, _, _ = open_clip.create_model_and_transforms("ViT-B-32", pretrained="openai")
tokenizer = open_clip.get_tokenizer("ViT-B-32")
texts = ["a photo of a person wearing a jacket", ...]  # keep groups aligned
with torch.no_grad():
    v = model.encode_text(tokenizer(texts))
    v = (v / v.norm(dim=-1, keepdim=True)).tolist()
```

```bash
python scripts/stage_model.py --name attribute_encoder --path models/staged/clip-image-enc.onnx \
    --source "CLIP ViT-B/32 image encoder" --license "MIT"
python scripts/stage_model.py --name attribute_prompts --path models/staged/attribute_prompts.json \
    --source "prompt embeddings from the same checkpoint" --license "MIT"
```

## Performance gates (per-camera frame budget at `AI_INFERENCE_FPS=5`)

| Stage | When | Cost control |
|---|---|---|
| Object detect | every sampled frame | motion gate (`AI_MOTION_GATE_ENABLED`), substream only |
| Face chain (SCRFD+ArcFace) | per person track ≤ every 2 s | **far-field gate**: bbox height < 0.06 skips the whole chain |
| ANPR (det+OCR) | per vehicle track ≤ every 5 s | vehicle-only, event emitted on plate change |
| Attribute tagging | per person track ≤ every 5 s | person-only, bbox height ≥ 0.08 |

All chains log a downgrade (reference fallback) instead of failing the camera
— optional capabilities degrade loudly, the object detector fails closed.

## Durability notes

- SQLite (dev): WAL + `synchronous=NORMAL` — API reads never block behind
  worker commits; commits survive app crashes. PostgreSQL is the prod answer.
- `tracks.detail` (attribute tags) is additive via `bootstrap._ensure_columns`
  and lives in JSON — swept with tracks/events by the retention sweep.
- `plate_hash` tokens are master-key-bound; rotating
  `MASTER_ENCRYPTION_KEY` invalidates existing hashes (re-index event).

## Security

The ModelRegistry verifies SHA-256 of every model before load. This prevents:
- **Tampering**: an attacker replacing the model file with a backdoored variant
- **Supply-chain attacks**: an unauthorized model being silently swapped in

A `trivy image` scan in CI also catches vulnerable Python packages in the
container image that the ONNX runtime depends on.

## Future: ONNX Profile M compliance

LocalSight's `Event` shape and `Detector` output are ONVIF Profile M
compatible (normalized bboxes, typed events with confidence + duration). The
profile compliance doc is forthcoming under `docs/integrations/onvif-m.md`.
