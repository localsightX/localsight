"""Per-camera daily alert budget (R3.6).

Fan-out units are deliberately not persisted (see packages/notify/__init__.py),
so an alert *budget* is enforced where alerts are emitted — the worker's fan-out
path — and counted per camera per UTC day. Evidence is never affected: the
pipeline persists the analytic event (row, clip, snapshot) regardless, so a
suppressed alert still leaves a searchable event; only the notification is
withheld.

Deliberate properties:

* ``seed()`` adopts a durable day total (the persisted analytic-event count), so
  a worker restart cannot hand out a fresh budget, and the API displays the same
  number from the same source.
* suppression is counted, never silent: callers log and emit
  ``alerts_budget_suppressed_total`` so "quiet because healthy" stays
  distinguishable from "quiet because budget".
* ``limit_per_day <= 0`` means unlimited — the pre-R3.6 default, so an upgrade
  changes nothing until an operator sets a budget.
"""
from __future__ import annotations

import datetime as dt
import threading
from collections.abc import Callable


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class DailyAlertBudget:
    """Thread-safe per-camera, per-UTC-day alert counter."""

    def __init__(self, limit_per_day: int = 0,
                 clock: Callable[[], dt.datetime] | None = None) -> None:
        self.limit_per_day = max(0, int(limit_per_day or 0))
        self._clock = clock or _utcnow
        self._lock = threading.Lock()
        self._day: dt.date | None = None
        self._used: dict[str, int] = {}
        self._suppressed: dict[str, int] = {}

    def _roll(self) -> None:
        """Reset counters when the UTC day changes (callers hold the lock)."""
        now = self._clock()
        today = (now.astimezone(dt.UTC) if now.tzinfo else now.replace(tzinfo=dt.UTC)).date()
        if self._day != today:
            self._day = today
            self._used = {}
            self._suppressed = {}

    def seed(self, camera_id: str, used: int) -> None:
        """Adopt an externally counted day total (never lowers the current count)."""
        with self._lock:
            self._roll()
            self._used[camera_id] = max(self._used.get(camera_id, 0), max(0, int(used)))

    def allow(self, camera_id: str) -> bool:
        """True when this alert may be emitted; False when the budget is spent.

        Consumes a slot on True, counts a suppression on False."""
        with self._lock:
            self._roll()
            used = self._used.get(camera_id, 0)
            if self.limit_per_day > 0 and used >= self.limit_per_day:
                self._suppressed[camera_id] = self._suppressed.get(camera_id, 0) + 1
                return False
            self._used[camera_id] = used + 1
            return True

    def used(self, camera_id: str) -> int:
        with self._lock:
            self._roll()
            return self._used.get(camera_id, 0)

    def suppressed(self, camera_id: str) -> int:
        with self._lock:
            self._roll()
            return self._suppressed.get(camera_id, 0)

    def snapshot(self) -> dict:
        with self._lock:
            self._roll()
            return {"limit_per_day": self.limit_per_day, "day": str(self._day),
                    "used": dict(self._used), "suppressed": dict(self._suppressed)}
