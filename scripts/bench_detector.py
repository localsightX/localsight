#!/usr/bin/env python3
"""Detector latency bench — the R1 "fastest frame" measurement tool.

Measures the two things that decide whether a camera keeps up on real
hardware, and reports them against the published budgets in
`packages.ai.bench.BUDGETS`:

  1. **Gate cost** — the scored motion gate on a 640x360 frame. This is paid on
     every sampled frame, so it must stay orders of magnitude below one
     inference call or the gate is a net loss.
  2. **Inference latency** — either the staged ONNX detector from the registry
     (`--backend onnx`) or a synthetic stand-in, reported as P50/P95/P99.

Post-processing is timed too (NMS over a full 8400-candidate head is the
hidden cost of a CPU deployment).

Examples:
    # Pure hot paths, no model needed.
    python scripts/bench_detector.py --iterations 200

    # Real staged model (needs onnxruntime + models/registry.json):
    python scripts/bench_detector.py --backend onnx --warmup 5 --iterations 50

    # Machine-readable for CI/jq:
    python scripts/bench_detector.py --json

Exit code is 0 when every budgeted metric passes, 1 otherwise — so it works
directly as a gate (`python scripts/local_cctv_rig.py bench`).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.ai import bench


def time_motion_gate(iterations: int, h: int = 360, w: int = 640) -> tuple[list[float], float]:
    """Time `CameraPipeline.motion_score` per call (us). Returns (samples, score)."""
    import numpy as np

    from packages.ai.pipeline import CameraPipeline

    pipe = CameraPipeline.__new__(CameraPipeline)
    pipe.motion_grid = 64
    pipe._gate_prev = None

    # Two frames with real, moving structure so we time the scoring path (not
    # the baseline-priming shortcut).
    a = np.zeros((h, w, 3), dtype=np.uint8)
    a[: h // 2] = 60
    b = a.copy()
    b[h // 2 : h // 2 + 20] = 200

    samples: list[float] = []
    for _ in range(iterations):
        pipe.motion_score(a)
        t0 = time.perf_counter()
        score = pipe.motion_score(b)
        samples.append((time.perf_counter() - t0) * 1e6)
    return samples, float(score or 0.0)


def time_postprocess(iterations: int, boxes: int = 8400) -> list[float]:
    """Time YOLO post-processing (decode + NMS) over a full candidate head."""
    import numpy as np

    from packages.ai.detectors import postprocess_yolo

    rng = np.random.default_rng(7)
    # Transposed v8/v11 head: (1, 4 + 80, N).
    raw = np.zeros((1, 84, boxes), dtype=np.float32)
    raw[0, :4] = rng.random((4, boxes)) * 0.9
    raw[0, 4:14] = rng.random((10, boxes)) * 0.6  # a few confident persons
    labels = [f"c{i}" for i in range(80)]
    labels[0] = "person"

    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        postprocess_yolo(raw, labels, conf_thr=0.45, iou_thr=0.5,
                         in_hw=(384, 640), frame_hw=(360, 640))
        samples.append((time.perf_counter() - t0) * 1e3)
    return samples


def time_e2e_decode(iterations: int, heads: int = 300) -> list[float]:
    """Time the NMS-free (YOLO26-style) head decode: (1, N, 6)."""
    import numpy as np

    from packages.ai.detectors import postprocess_yolo_e2e

    rng = np.random.default_rng(11)
    raw = np.zeros((1, heads, 6), dtype=np.float32)
    raw[0, :, :4] = rng.random((heads, 4)) * 100.0
    raw[0, :, 4] = rng.random(heads) * 0.9
    raw[0, :, 5] = 0.0
    labels = ["person"] + [f"c{i}" for i in range(1, 80)]

    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        postprocess_yolo_e2e(raw, labels, 0.45, in_hw=(384, 640), frame_hw=(360, 640))
        samples.append((time.perf_counter() - t0) * 1e3)
    return samples


def time_onnx_detector(iterations: int, warmup: int, backend: str,
                       model_name: str) -> list[float]:
    """Time a real staged detector end-to-end (preprocess + run + decode)."""
    import datetime as dt

    import numpy as np

    from apps.api.config import Settings
    from packages.ai.detectors import build_detector
    from packages.ai.registry import ModelRegistry

    settings = Settings()
    settings.ai_detector = backend
    settings.ai_model_name = model_name
    settings.ai_motion_gate_enabled = False
    detector = build_detector(settings, ModelRegistry())

    frame = np.zeros((360, 640, 3), dtype=np.uint8)
    frame[100:300, 200:400] = 180  # something to detect
    ts = dt.datetime.now(dt.UTC)
    for _ in range(warmup):
        detector.detect(frame, ts)

    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        detector.detect(frame, ts)
        samples.append((time.perf_counter() - t0) * 1e3)
    return samples


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="none",
                    choices=["none", "onnx", "openvino", "tensorrt"],
                    help="none = pure hot paths only (no model needed)")
    ap.add_argument("--model-name", default="detector")
    ap.add_argument("--iterations", type=int, default=100)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--json", action="store_true", help="emit the raw report as JSON")
    args = ap.parse_args()

    measurements: dict[str, list[float]] = {}
    measurements["motion_gate_us"], score = time_motion_gate(args.iterations)
    # Post-process timings stay bounded so the harness is seconds long, not
    # minutes: NMS is the expensive one and 20 samples already pin its P95.
    pp_iters = max(1, min(args.iterations, 20))
    measurements["postprocess_ms"] = time_postprocess(pp_iters)
    measurements["e2e_decode_ms"] = time_e2e_decode(pp_iters * 10)
    if args.backend != "none":
        measurements["cpu_frame_ms"] = time_onnx_detector(
            args.iterations, args.warmup, args.backend, args.model_name)

    rep = bench.report(measurements)
    if args.json:
        print(json.dumps({**rep, "motion_score_sample": score}, indent=2))
    else:
        print(bench.format_report(rep))
        print(f"  (gate sample score on synthetic motion: {score:.4f})")
    return 0 if rep["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
