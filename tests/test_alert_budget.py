"""R3.6 — per-camera daily alert budget.

The counter (packages/notify/budget.py) is pure and clock-injectable; the
durable day total (packages/domain/alertcount.py) is one query shared by the
worker's seed and the API's display, with a drift guard against the engine's
event vocabulary. The fan-out gate (apps.worker.main.enqueue_analytic_alerts)
is exercised without running a camera.
"""
import datetime as dt

import pytest

from packages.domain import alertcount
from packages.domain.models import Camera, Event
from packages.notify.budget import DailyAlertBudget


@pytest.fixture()
def rt(app):
    return app.state.runtime


T0 = dt.datetime(2026, 5, 4, 12, 0, tzinfo=dt.UTC)


class _Ev:
    def __init__(self, tid="t1", etype="intrusion", detail=None, ts=None):
        self.track_id = tid
        self.event_type = etype
        self.camera_id = "cam-b"
        self.detail = detail or {}
        self.timestamp_start = ts


def _row(session, cam_id, etype, ts):
    return Event(camera_id=cam_id, track_id="t", identity_status="unknown",
                 event_type=etype, timestamp_start=ts, timestamp_end=ts,
                 confidence=0.9, bbox={})


def test_daily_budget_allows_up_to_limit_then_suppresses():
    b = DailyAlertBudget(2, clock=lambda: T0)
    assert [b.allow("cam-b") for _ in range(3)] == [True, True, False]
    assert b.used("cam-b") == 2 and b.suppressed("cam-b") == 1
    assert b.used("other") == 0  # per-camera isolation


def test_unlimited_default_and_day_rollover():
    b = DailyAlertBudget(0, clock=lambda: T0)
    assert [b.allow("cam-b") for _ in range(10)] == [True] * 10
    b = DailyAlertBudget(1, clock=lambda: T0)
    assert b.allow("cam-b") is True and b.allow("cam-b") is False
    b._clock = lambda: T0 + dt.timedelta(days=1)  # next UTC day rolls the counters
    assert b.allow("cam-b") is True and b.used("cam-b") == 1


def test_seed_adopts_durable_count_but_never_lowers():
    b = DailyAlertBudget(3, clock=lambda: T0)
    b.seed("cam-b", 2)
    assert b.used("cam-b") == 2 and b.allow("cam-b") is True   # third fits
    assert b.allow("cam-b") is False                            # fourth is over
    b.seed("cam-b", 0)                                          # stale seed is ignored
    assert b.used("cam-b") == 3


def test_snapshot_shape():
    b = DailyAlertBudget(5, clock=lambda: T0)
    b.allow("cam-b")
    snap = b.snapshot()
    assert (snap["limit_per_day"], snap["used"], snap["suppressed"]) == (5, {"cam-b": 1}, {})


def test_enqueue_gate_counts_and_suppresses():
    from apps.worker.main import enqueue_analytic_alerts

    budget = DailyAlertBudget(1, clock=lambda: T0)
    sent = []
    analytics = [_Ev(), _Ev(), _Ev()]
    assert enqueue_analytic_alerts(analytics, "cam-b", budget, put=sent.append) == 1
    assert len(sent) == 1 and budget.suppressed("cam-b") == 2
    # no budget (None) = unlimited, and a throwing sink does not consume twice
    assert enqueue_analytic_alerts(analytics, "cam-b", None, put=sent.append) == 4 - 1


def test_event_vocabulary_matches_engine():
    from packages.ai import rules as engine_rules

    engine_types = {v for k, v in vars(engine_rules).items() if k.startswith("EVENT_")}
    assert engine_types == alertcount.ANALYTIC_EVENT_TYPES


def test_count_alerts_today_scopes_to_camera_and_analytic_types(rt, app):
    now = dt.datetime.now(dt.UTC)
    old = now - dt.timedelta(days=1, hours=1)
    with rt.SessionLocal() as s:
        cam = Camera(name="budget-cam")
        other_cam = Camera(name="budget-other-cam")
        s.add_all([cam, other_cam])
        s.commit()
        cam_id, other_id = cam.id, other_cam.id
        s.add_all([_row(s, cam_id, "intrusion", now), _row(s, cam_id, "object_removed", now),
                   _row(s, cam_id, "presence", now), _row(s, other_id, "intrusion", now),
                   _row(s, cam_id, "crowd", old)])
        s.commit()
    with rt.SessionLocal() as s:
        assert alertcount.count_alerts_today(s, cam_id) == 2
        assert alertcount.count_alerts_today(s, other_id) == 1
        assert alertcount.count_alerts_today(s) == 3
