"""Durable alert accounting (R3.6).

Fan-out units (``packages.notify.Alert``) are in-process and never persisted, so
"how many alerts has this camera emitted today?" is answered from the durable
evidence instead: the analytic events the pipeline stored. The worker seeds its
budget with that number and the API shows it, from one query — so enforcement
and the UI can never disagree.

The analytic set mirrors the EVENT_* constants in ``packages.ai.rules``; the
dependency direction forbids domain -> ai, so the literals are duplicated and
``tests/test_alert_budget.py`` asserts the two sets stay identical.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from packages.domain.models import Event

ANALYTIC_EVENT_TYPES = frozenset({
    "line_cross", "intrusion", "loitering", "object_left", "object_removed",
    "crowd", "stopped_vehicle",
})


def day_start(now: dt.datetime | None = None) -> dt.datetime:
    """UTC midnight of the current day.

    Budget windows are UTC, not camera-local: a local-midnight window would let
    a camera straddle two budgets (and an operator comparing two cameras in
    different timezones could not reason about the cap at all)."""
    now = now or dt.datetime.now(dt.UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.UTC)
    return now.astimezone(dt.UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def count_alerts_today(session: Session, camera_id: str | None = None,
                       now: dt.datetime | None = None) -> int:
    """Analytic events since UTC midnight — the durable "alerts today" count.

    Scoped to one camera when ``camera_id`` is given (worker seed, per-camera
    API row); camera-wide when it is None."""
    stmt = (select(func.count()).select_from(Event)
            .where(Event.event_type.in_(ANALYTIC_EVENT_TYPES),
                   Event.timestamp_start >= day_start(now)))
    if camera_id is not None:
        stmt = stmt.where(Event.camera_id == camera_id)
    return int(session.execute(stmt).scalar() or 0)
