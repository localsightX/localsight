"""Storage-pressure monitoring (reliability plan F3 — "disk full").

Disk full is the failure mode that quietly destroys an NVR: retention sweeps
cannot delete, the DB cannot commit, and recordings die mid-segment — the
evidence an operator needs is exactly what gets lost. The mitigation is to
*see it coming*: warn at 80 %, critical at 90 %, with hysteresis so a sweep
that reclaims space re-arms the alarm instead of flapping every hour.

Pure logic lives here (no filesystem access in `observe`), so the threshold
and hysteresis behaviour is unit-testable without filling a real disk; the
worker owns the polling and the alert dispatch.
"""
from __future__ import annotations

WARN_RATIO = 0.80
CRITICAL_RATIO = 0.90
# A fired level is only cleared once usage drops this far below its threshold.
# Without the band, a retention sweep that lands at 79.9 % would immediately
# re-fire on the next 80.1 % sample, training operators to ignore the alarm.
REARM_BAND = 0.05

OK = "ok"
WARNING = "warning"
CRITICAL = "critical"


def usage_ratio(path: str | None) -> float | None:
    """Fraction of the volume holding `path` that is in use, or None.

    None means "unknown" (path missing, unreadable, or remote storage) and is
    never treated as healthy by callers — an unknown disk state must not
    silently suppress the alarm path.
    """
    if not path:
        return None
    try:
        import shutil

        total, _used, free = shutil.disk_usage(path)
    except Exception:
        return None
    if total <= 0:
        return None
    used = total - free
    return max(0.0, min(1.0, used / total))


def pressure_level(ratio: float, warn: float = WARN_RATIO,
                   critical: float = CRITICAL_RATIO) -> str:
    """Map a usage ratio onto ok/warning/critical. Pure."""
    if ratio >= critical:
        return CRITICAL
    if ratio >= warn:
        return WARNING
    return OK


class DiskPressureMonitor:
    """Stateful threshold tracker with hysteresis; one instance per worker.

    `observe()` returns the *effective* level after hysteresis, so a caller can
    alert on level changes alone (`if level != monitor.alerted`). Levels only
    escalate immediately; de-escalation requires dropping a full `rearm_band`
    below the threshold that fired, which is what stops hourly flap.
    """

    def __init__(self, path: str | None = None, warn: float = WARN_RATIO,
                 critical: float = CRITICAL_RATIO, rearm_band: float = REARM_BAND) -> None:
        self.path = path
        self.warn = float(warn)
        self.critical = float(critical)
        self.rearm_band = float(rearm_band)
        self.level = OK          # effective (hysteretic) level
        self.alerted = OK        # level the operator was last told about
        self.last_ratio: float | None = None
        self.unknown_polls = 0

    def observe(self, ratio: float | None) -> str:
        """Fold one usage sample into the effective level and return it.

        Escalation is immediate; de-escalation requires crossing a full
        `rearm_band` below the line that fired, so a sweep that lands just
        under a threshold does not re-trigger it on the next sample.
        """
        if ratio is None:
            self.unknown_polls += 1
            self.last_ratio = None
            return self.level  # unknown: hold the last known verdict
        self.last_ratio = ratio
        raw = pressure_level(ratio, self.warn, self.critical)

        if raw == CRITICAL:
            level = CRITICAL
        elif self.level == CRITICAL:
            # Hold critical until usage drops a full band below the line.
            if ratio < self.warn - self.rearm_band:
                level = OK
            elif ratio < self.critical - self.rearm_band:
                level = WARNING
            else:
                level = CRITICAL
        elif raw == WARNING or (
            self.level == WARNING and ratio >= self.warn - self.rearm_band
        ):
            level = WARNING
        else:
            level = OK
        self.level = level
        return level

    def poll(self) -> tuple[str, float | None]:
        """Sample the configured path and return (effective_level, ratio)."""
        ratio = usage_ratio(self.path)
        return self.observe(ratio), ratio

    def take_alert(self) -> str | None:
        """Return a level to alert on *once*, or None when nothing changed.

        Caller: `if (lvl := monitor.take_alert()): emit(lvl)`. Recording the
        alerted level here (rather than in the caller) keeps the "don't repeat
        yourself" guarantee in one place.
        """
        if self.level != self.alerted:
            self.alerted = self.level
            return self.level
        return None
