"""Gate-access lane logic (R4.1): allow-window evaluation and per-camera
analytic switches.

Kept pure and unit-tested like packages.domain.events. Two responsibilities:

1. Allow-window evaluation — is a given moment inside a lane/whitelist
   schedule? Windows fail CLOSED: an unparseable window denies access, never
   grants it — deny-by-default is the R4.1 security posture, so a config typo
   must never open a barrier.
2. Per-camera analytic switches — the "off unless the operator enabled it"
   rule (roadmap definition-of-done 8), defined once here so the worker and
   the API cannot drift apart.
"""
from __future__ import annotations

import datetime as dt
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def pipeline_flag_enabled(flags: dict | None, name: str) -> bool:
    """Per-camera analytic switch: OFF unless explicitly enabled.

    A null column (camera never configured), a missing key, or any non-true
    value all resolve to off — an analytic never runs on a camera the operator
    did not explicitly turn it on for. Strict `is True` so a stray string or
    integer in the JSON cannot silently arm an analytic.
    """
    if not flags:
        return False
    return flags.get(name) is True


def is_within_window(now_utc: dt.datetime, window: dict | None, default_tz: str = "UTC") -> bool:
    """True if `now_utc` falls inside a lane allow-window.

    Window shape::

        {"start": "09:00", "end": "17:00", "days": [1, 2, 3, 4, 5], "tz": "UTC"}

    - ``start``/``end`` are ``HH:MM`` (inclusive start, exclusive end).
    - ``end <= start`` means an overnight window (wraps past midnight).
    - ``days`` are ISO weekday ints (1=Mon .. 7=Sun); absent/empty = every day.
    - ``tz`` is an IANA name applied to ``now_utc`` before the time/weekday
      test; absent = ``default_tz`` (callers pass the camera's timezone).
    - ``window`` None = no schedule restriction (always allowed).
    - a malformed window returns False: the gate stays shut rather than opening
      on a typo. Callers audit-log the misconfiguration.
    """
    if window is None:
        return True
    try:
        start = _parse_hhmm(window["start"])
        end = _parse_hhmm(window["end"])
    except (KeyError, TypeError, ValueError):
        return False
    try:
        local = now_utc.astimezone(ZoneInfo(window.get("tz") or default_tz))
    except (ZoneInfoNotFoundError, ValueError):
        return False  # unknown timezone must not open the gate
    days = window.get("days")
    if days:
        try:
            if local.isoweekday() not in {int(d) for d in days}:
                return False
        except (TypeError, ValueError):
            return False
    t = local.time()
    if end > start:
        return start <= t < end
    # Overnight window (e.g. 17:00 -> 07:00): allowed after start OR before end.
    return t >= start or t < end


def _parse_hhmm(value: object) -> dt.time:
    text = str(value).strip()
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            return dt.datetime.strptime(text, fmt).time()
        except ValueError:
            continue
    raise ValueError(f"expected HH:MM, got {value!r}")
