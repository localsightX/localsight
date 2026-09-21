"""R3.4 — abandoned object (ownership) + stopped vehicle.

Pinned empirically against the real engine before these assertions were
written: an attended bag is silent, a drop fires 3 s after the owner leaves,
the opt-out keeps the pre-R3.4 stationarity behavior, a parked car fires only
inside the no-stopping zone, and movement re-arms the stopped timer.
"""
import datetime as dt

from packages.ai.rules import RuleEngine, bboxes_attached, rule_from_dict

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
ZONE = [[0.4, 0.4], [0.6, 0.4], [0.6, 0.6], [0.4, 0.6]]
BAG = ("bag1", "bag", (0.48, 0.48, 0.05, 0.05))
HOLDING = ("p1", "person", (0.44, 0.30, 0.14, 0.30))  # box contains the bag center
AWAY = ("p1", "person", (0.10, 0.10, 0.08, 0.16))
LEFT = {"type": "object_left", "rule_id": "abandon", "zone": ZONE,
        "stationary_sec": 3, "labels": ["bag"]}
STOP = {"type": "stopped_vehicle", "rule_id": "nostop", "zone": ZONE,
        "stopped_sec": 3, "max_speed": 0.02, "labels": ["vehicle"]}


def _fires(spec, frames, rtype):
    engine = RuleEngine("cam")
    engine.add(rule_from_dict("cam", spec))
    return [i for i, tracks in enumerate(frames)
            for ev in engine.evaluate(tracks, T0 + dt.timedelta(seconds=i))
            if ev.rule_type == rtype]


def _car(xs):
    return [[("v1", "vehicle", (x, 0.45, 0.10, 0.10))] for x in xs]


def test_bboxes_attached_semantics():
    cand = (0.48, 0.48, 0.05, 0.05)  # center (0.505, 0.505); area 0.0025
    assert bboxes_attached(cand, (0.44, 0.30, 0.14, 0.30)) is True   # center covered
    assert bboxes_attached(cand, (0.48, 0.48, 0.05, 0.02)) is True   # 40% of area
    assert bboxes_attached(cand, (0.10, 0.10, 0.08, 0.16)) is False  # disjoint
    assert bboxes_attached(cand, (0.48, 0.48, 0.05, 0.004)) is False  # 8% sliver


def test_attended_candidate_is_not_abandoned():
    frames = [[BAG, HOLDING]] * 7
    assert _fires(LEFT, frames, "object_left") == []
    # opt-out keeps the pre-R3.4 behavior (fires purely on stationarity)
    assert _fires(dict(LEFT, require_unattended=False), frames, "object_left") == [3]


def test_drop_fires_only_after_the_owner_leaves():
    frames = [[BAG, HOLDING]] * 2 + [[BAG, AWAY]] * 5
    assert _fires(LEFT, frames, "object_left") == [5]


def test_stopped_vehicle_fires_inside_the_zone_only():
    inside = _car([0.42, 0.46, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50])
    assert _fires(STOP, inside, "stopped_vehicle") == [7]
    outside = _car([0.10, 0.14, 0.18, 0.18, 0.18, 0.18, 0.18])
    assert _fires(STOP, outside, "stopped_vehicle") == []


def test_moving_vehicle_is_silent():
    moving = _car([0.42, 0.46, 0.50, 0.54, 0.58, 0.62, 0.66, 0.70])
    assert _fires(STOP, moving, "stopped_vehicle") == []


def test_stop_move_stop_rearms():
    frames = _car([0.42, 0.46, 0.50, 0.50, 0.50, 0.50, 0.50, 0.50,
                   0.42, 0.40, 0.40, 0.40, 0.40, 0.40, 0.40])
    assert _fires(STOP, frames, "stopped_vehicle") == [7, 14]
