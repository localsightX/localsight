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
from dataclasses import dataclass
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

if TYPE_CHECKING:
    from packages.domain.models import Lane, LaneWhitelistEntry


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


def validate_window(window: dict | None) -> None:
    """Structural check for a lane / whitelist allow-window.

    Raises ``ValueError`` (message safe to return to an operator) when a window
    is malformed; returns silently when it is well-formed or ``None``.

    The write path (the lane API) REJECTS a malformed window instead of
    persisting it. ``is_within_window`` fails closed at read time, so a window
    that merely *looks* right would deny every read silently — an operator
    could arm a lane that never opens and have no signal why. Failing the write
    names the problem at configure time instead. Read-time fail-closed stays
    the authority for rows already stored (and for hand-edited DB rows).
    """
    if window is None:
        return
    if not isinstance(window, dict):
        raise ValueError("allow_window must be an object")
    try:
        _parse_hhmm(window["start"])
        _parse_hhmm(window["end"])
    except KeyError as exc:
        raise ValueError("allow_window requires 'start' and 'end' as HH:MM") from exc
    except ValueError as exc:
        raise ValueError(f"allow_window start/end: {exc}") from exc
    tz = window.get("tz")
    if tz is not None:
        if not isinstance(tz, str):
            raise ValueError("allow_window 'tz' must be an IANA name string")
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"allow_window 'tz' is not a known timezone: {tz!r}") from exc
    days = window.get("days")
    if days is not None:
        if not isinstance(days, list) or not days:
            raise ValueError(
                "allow_window 'days' must be a non-empty list of weekday ints (1=Mon..7=Sun)"
            )
        try:
            parsed = [int(d) for d in days]
        except (TypeError, ValueError) as exc:
            raise ValueError("allow_window 'days' must be weekday ints") from exc
        if any(d < 1 or d > 7 for d in parsed):
            raise ValueError("allow_window 'days' must be in 1..7")


# ── gate-access decision (R4.1) ───────────────────────────────────────────────
#
# The deny-by-default decision for one plate read on a lane camera. Pure: takes
# the lane and the whitelist row matched by the exact keyed-HMAC plate token, no
# session or network. The worker drives it (packages → apps stays one-way) and
# the reasons double as the audit detail + Prometheus labels, so a denial is
# always explainable to the operator who armed the lane.

DECISION_GRANTED = "granted"
DECISION_LANE_DISABLED = "lane_disabled"
DECISION_NOT_WHITELISTED = "not_whitelisted"
DECISION_OUTSIDE_WINDOW = "outside_window"
# Policy granted the open but the relay itself could not be commanded (missing
# or undecryptable barrier config, an SSRF-rejected destination, an unusable
# channel). Reported on a gate_open row with granted=False so a missed open is
# visible instead of silently dropped; the worker deliberately does NOT consume
# the cooldown, so the next read of the plate can retry the relay.
DECISION_BARRIER_UNAVAILABLE = "barrier_unavailable"


@dataclass(frozen=True)
class GateDecision:
    """The outcome of matching one plate read against a lane policy.

    ``reason`` is one of the DECISION_* constants — a granted decision is
    always ``DECISION_GRANTED``; every other reason denies and the barrier
    must stay closed. ``entry_label`` is the operator note on the matched
    whitelist row (never the plaintext plate) for audit context.
    """

    granted: bool
    reason: str
    lane_id: str
    camera_id: str
    plate_hash: str
    entry_label: str | None = None


def decide_gate_access(
    lane: Lane,
    plate_hash: str,
    entry: LaneWhitelistEntry | None,
    now_utc: dt.datetime,
    *,
    default_tz: str = "UTC",
) -> GateDecision:
    """Evaluate the R4.1 gate decision for one plate read.

    Deny-by-default, evaluated in the strictest-first order so no later, weaker
    check can resurrect an earlier deny:

    1. the lane must be ``enabled`` (an operator disarming a lane must stop
       access immediately, even though the whitelist rows still exist);
    2. a matching, enabled whitelist row must exist — a plate that is not
       enrolled is denied and only ever logged;
    3. the read must fall inside the allow window. A per-plate ``allow_window``
       overrides the lane window when set (a delivery pass valid 09:00-13:00 on
       an otherwise 24/7 lane); either being malformed denies — fail closed.

    ``now_utc`` is the event timestamp (the pipeline already has it).
    ``default_tz`` is the lane camera's timezone, applied when a window does
    not name its own — pass ``camera.timezone`` from the worker.
    """
    if not lane.enabled:
        return GateDecision(False, DECISION_LANE_DISABLED, lane.id, lane.camera_id, plate_hash)
    if entry is None or not entry.enabled:
        return GateDecision(False, DECISION_NOT_WHITELISTED, lane.id, lane.camera_id, plate_hash)
    window = entry.allow_window if entry.allow_window is not None else lane.allow_window
    if not is_within_window(now_utc, window, default_tz):
        return GateDecision(False, DECISION_OUTSIDE_WINDOW, lane.id, lane.camera_id,
                            plate_hash, entry.label)
    return GateDecision(True, DECISION_GRANTED, lane.id, lane.camera_id, plate_hash, entry.label)
