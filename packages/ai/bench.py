"""Latency-budget core for the "fastest frame" contract (roadmap R1).

Dependency-free and side-effect-free on purpose: CI asserts the *budget math*
and the pure hot paths (motion gate, NMS-free decode, YOLO post-process)
without a GPU, a staged model, or a camera. The CLI driver is
`scripts/bench_detector.py`; `python scripts/local_cctv_rig.py bench` runs it
against a real box with the staged ONNX detector.

Budgets are the published R1 targets (docs/roadmap 03-performance-benchmarks),
not aspirational numbers — a failing verdict here is the exact signal the
roadmap's exit criteria use, so a regression that trades latency for features
is caught in review rather than in a customer's control room.
"""
from __future__ import annotations

import math

# metric key -> (budget, unit, direction) with direction "max" (lower is better).
# "min" exists so throughput-style metrics can share the reporter.
BUDGETS: dict[str, tuple[float, str, str]] = {
    # Pure hot paths (measured in CI — no model required).
    "motion_gate_us": (500.0, "us/call", "max"),   # 640x360 scored gate
    "postprocess_ms": (80.0, "ms/call", "max"),    # 8400 candidates, CPU NMS
    "e2e_decode_ms": (5.0, "ms/call", "max"),      # 300x6 NMS-free head
    # End-to-end targets (measured on a rig with a staged model).
    "cpu_frame_ms": (120.0, "ms/frame", "max"),    # R1 CPU INT8 budget
    "e2e_p50_ms": (250.0, "ms", "max"),            # detect -> event P50
    "e2e_p99_ms": (800.0, "ms", "max"),            # detect -> event P99
}


def percentile(samples: list[float], q: float) -> float:
    """Nearest-rank percentile — deliberately not interpolated.

    Latency percentiles are read as "the worst call you'd see at this rate",
    so returning an actual observed sample (never a value between two samples)
    is both the honest answer and the reproducible one across numpy versions.
    """
    if not samples:
        return 0.0
    ordered = sorted(float(s) for s in samples)
    if q <= 0:
        return ordered[0]
    if q >= 100:
        return ordered[-1]
    rank = math.ceil(q / 100.0 * len(ordered)) - 1
    return ordered[min(max(rank, 0), len(ordered) - 1)]


def summarize(samples: list[float]) -> dict:
    """count/min/mean/p50/p95/p99/max for one metric's samples."""
    if not samples:
        return {"count": 0, "min": 0.0, "mean": 0.0, "p50": 0.0,
                "p95": 0.0, "p99": 0.0, "max": 0.0}
    vals = [float(s) for s in samples]
    return {
        "count": len(vals),
        "min": min(vals),
        "mean": sum(vals) / len(vals),
        "p50": percentile(vals, 50),
        "p95": percentile(vals, 95),
        "p99": percentile(vals, 99),
        "max": max(vals),
    }


def verdict(metric: str, value: float) -> bool | None:
    """True when `value` meets the metric's budget; None when unbudgeted.

    Unbudgeted metrics are informational (a bench may time anything), and
    informational numbers must never fail a gate — only declared targets do.
    """
    budget = BUDGETS.get(metric)
    if budget is None:
        return None
    limit, _unit, direction = budget
    return value <= limit if direction == "max" else value >= limit


def report(measurements: dict[str, list[float]]) -> dict:
    """Build the bench report: per-metric summary + budget verdict + pass flag.

    `measurements` maps a budget key (or any informational name) to its raw
    samples. `pass` is True only when every *budgeted* metric is within budget,
    so an unknown metric can never mask a failing target.
    """
    metrics: dict[str, dict] = {}
    passed = True
    for name, samples in sorted(measurements.items()):
        summary = summarize(samples)
        budget = BUDGETS.get(name)
        within = verdict(name, summary["p95"] if summary["count"] else 0.0)
        metrics[name] = {
            **summary,
            "budget": budget[0] if budget else None,
            "unit": budget[1] if budget else "",
            # Percentiles, not the mean: a p95 regression is what an operator
            # actually experiences, so the gate is decided on p95.
            "judged_on": "p95" if summary["count"] else "n/a",
            "within_budget": within,
        }
        if within is False:
            passed = False
    return {"pass": passed, "metrics": metrics}


def format_report(rep: dict) -> str:
    """Human-readable one-screen rendering of `report()`."""
    lines = ["bench report:"]
    for name, m in rep["metrics"].items():
        if m["budget"] is None:
            lines.append(f"  {name:<16} {m['p95']:>8.3f} {m['unit']:<9} (info, n={m['count']})")
            continue
        mark = "PASS" if m["within_budget"] else "FAIL"
        lines.append(
            f"  {mark}  {name:<16} {m['p95']:>8.3f} {m['unit']:<9} "
            f"budget {m['budget']:.3f}  (p99 {m['p99']:.3f}, n={m['count']})"
        )
    lines.append(f"  overall: {'PASS' if rep['pass'] else 'FAIL'}")
    return "\n".join(lines)
