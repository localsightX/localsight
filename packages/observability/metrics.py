"""In-process metrics registry exposing the Prometheus text format.

No external dependency: we render `# TYPE`/`# HELP` lines and
`name{labels="..."} value` ourselves. For high-cardinality or multi-process
deployments, ship these to Prometheus via the /metrics endpoint (already wired in
the API) or a Pushgateway.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, Tuple


class Metrics:
    _HELP = {
        "camera_fps": "Decoded frames per second per camera",
        "frames_processed": "Total frames processed",
        "frames_dropped": "Total frames dropped under load",
        "detections_per_minute": "Person detections per minute per camera",
        "recognition_requests": "Identity recognition requests",
        "recognition_latency_ms": "Recognition latency in ms",
        "gpu_utilization": "GPU utilization percent",
        "gpu_memory_mb": "GPU memory used in MB",
        "cpu_utilization": "CPU utilization percent",
        "ram_used_mb": "RAM used in MB",
        "storage_usage_percent": "Storage used percent",
        "disk_used_ratio": "Fraction of the media volume in use (0-1)",
        "disk_pressure_level": "Disk pressure level (0=ok, 1=warning, 2=critical)",
        "database_latency_ms": "Database query latency in ms",
        "api_latency_ms": "API request latency in ms",
        "queue_depth": "Inference queue depth",
        "camera_disconnects_total": "Camera disconnect events",
        "pipeline_latency_ms": "Per-frame pipeline processing latency in ms",
        "analytic_events_total": "Point-in-time analytic events (rules/ANPR)",
        "camera_status": "1 when camera gateway reports STREAMING, else 0",
        "gate_opens_total": "R4.1 barrier OPEN commands actually dispatched",
        "gate_opens_failed_total": "R4.1 granted opens that could not reach the relay",
        "gate_denies_total": "R4.1 plate reads denied (by reason)",
        "gate_commands_suppressed_total": "R4.1 OPENs suppressed by the per-plate cooldown",
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[Tuple[str, str], float] = {}
        self._gauges: Dict[Tuple[str, str], float] = {}

    def inc(self, name: str, amount: float = 1.0, labels: str = "") -> None:
        with self._lock:
            key = (name, labels)
            self._counters[key] = self._counters.get(key, 0.0) + amount

    def set(self, name: str, value: float, labels: str = "") -> None:
        with self._lock:
            self._gauges[(name, labels)] = value

    def observe(self, name: str, value: float, labels: str = "") -> None:
        # treat as a gauge sample (latencies); counters stay separate
        self.set(name, value, labels)

    def render(self) -> str:
        out: list[str] = []
        with self._lock:
            for (name, labels), val in self._counters.items():
                self._emit(out, name, "counter", labels, val)
            for (name, labels), val in self._gauges.items():
                self._emit(out, name, "gauge", labels, val)
        return "\n".join(out) + "\n"

    def _emit(self, out: list[str], name: str, kind: str, labels: str, val: float) -> None:
        if name in self._HELP:
            out.append(f"# HELP {name} {self._HELP[name]}")
            out.append(f"# TYPE {name} {kind}")
        suffix = f"{{{labels}}}" if labels else ""
        out.append(f"{name}{suffix} {val:g}")


metrics = Metrics()
