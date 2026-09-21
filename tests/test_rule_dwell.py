"""R3.2 — loitering/dwell hardening.

Zone hits adopt the privacy-mask semantics (center inside OR >=50% of the bbox
covered, mirroring CameraPipeline._is_masked), and tracker ID switches inside a
zone can inherit dwell state via the id_switch_grace_sec knob so a re-assigned
track neither resets its dwell clock nor double-fires. Expected values here are
empirically pinned against the real engine (see the R3.2 probe in the PR).
"""
import datetime as dt

from packages.ai.rules import (
    RuleEngine,
    bbox_zone_overlap_fraction,
    point_in_polygon,
    rule_from_dict,
)

L_ZONE = [[0, 0], [1, 0], [1, 0.6], [0.6, 0.6], [0.6, 1], [0, 1]]  # square minus notch
SQUARE = [[0.4, 0.4], [0.6, 0.4], [0.6, 0.6], [0.4, 0.6]]
T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
IN1 = [("t1", "person", (0.48, 0.48, 0.04, 0.08))]   # center (0.50, 0.52)
IN2 = [("t2", "person", (0.48, 0.48, 0.04, 0.08))]   # same spot, switched id
FAR2 = [("t2", "person", (0.40, 0.38, 0.04, 0.08))]  # center (0.42, 0.42), d=0.128 > reach


def _engine(spec):
    e = RuleEngine("cam")
    e.add(rule_from_dict("cam", spec))
    return e


def _fire_secs(engine, frames, rtype):
    return [s for s, tr in frames
            for ev in engine.evaluate(tr, T0 + dt.timedelta(seconds=s))
            if ev.rule_type == rtype]


LOITER_FRAMES = [  # t1 present 0-4 (fires at 4), departs, t2 same spot from 6
    (0, IN1), (1, IN1), (2, IN1), (3, IN1), (4, IN1), (5, []),
    (6, IN2), (7, IN2), (8, IN2), (9, IN2), (10, IN2),
]


def test_overlap_geometry_matches_mask_semantics():
    assert 0.55 <= bbox_zone_overlap_fraction((0.5, 0.5, 0.3, 0.3), L_ZONE) <= 0.56
    assert bbox_zone_overlap_fraction((0.62, 0.62, 0.15, 0.15), L_ZONE) == 0.0
    assert point_in_polygon((0.65, 0.65), L_ZONE) is False  # center sits in the notch
    assert bbox_zone_overlap_fraction((0.5, 0.5, 0.0, 0.1), L_ZONE) == 0.0  # no ZeroDivision


def test_zone_hit_overlap_closes_r31_gap():
    """Center outside the zone but >=50% of the bbox covered -> the rule fires."""
    assert _fire_secs(
        _engine({"type": "intrusion", "rule_id": "z", "zone": L_ZONE}),
        [(0, [("t1", "person", (0.5, 0.5, 0.3, 0.3))])], "intrusion") == [0]
    assert _fire_secs(
        _engine({"type": "intrusion", "rule_id": "z", "zone": L_ZONE}),
        [(0, [("t1", "person", (0.62, 0.62, 0.15, 0.15))])], "intrusion") == []


def test_zone_hit_center_wins_below_overlap_floor():
    """OR semantics like masks: center-in fires even when coverage < 50%."""
    assert _fire_secs(
        _engine({"type": "intrusion", "rule_id": "z", "zone": SQUARE}),
        [(0, [("t1", "person", (0.49, 0.49, 0.2, 0.2))])], "intrusion") == [0]
    # center (0.59, 0.59) inside the zone; bbox coverage is only ~0.30


def test_id_switch_same_spot_fires_once_with_grace():
    spec = {"type": "loitering", "rule_id": "l", "zone": SQUARE, "dwell_sec": 4,
            "id_switch_grace_sec": 3}
    assert _fire_secs(_engine(spec), LOITER_FRAMES, "loitering") == [4]
    # without the knob the switched id restarts dwell and double-fires (old behavior)
    bare = {k: v for k, v in spec.items() if k != "id_switch_grace_sec"}
    assert _fire_secs(_engine(bare), LOITER_FRAMES, "loitering") == [4, 10]


def test_id_switch_resumes_partial_dwell():
    """3 s of presence, ID switch after a 1 s gap -> fires 1 s after the switch."""
    spec = {"type": "loitering", "rule_id": "l", "zone": SQUARE, "dwell_sec": 4,
            "id_switch_grace_sec": 3}
    frames = [(0, IN1), (1, IN1), (2, IN1), (3, IN1), (4, []), (5, IN2), (6, IN2)]
    assert _fire_secs(_engine(spec), frames, "loitering") == [5]


def test_id_switch_requires_proximity():
    """A genuinely different track far away starts its own dwell (own alert)."""
    spec = {"type": "loitering", "rule_id": "l", "zone": SQUARE, "dwell_sec": 4,
            "id_switch_grace_sec": 3}
    frames = [(0, IN1), (1, IN1), (2, IN1), (3, IN1), (4, IN1), (5, []),
              (6, FAR2), (7, FAR2), (8, FAR2), (9, FAR2), (10, FAR2)]
    assert _fire_secs(_engine(spec), frames, "loitering") == [4, 10]


def test_grace_off_leaves_no_tombstones():
    engine = _engine({"type": "loitering", "rule_id": "l", "zone": SQUARE, "dwell_sec": 4})
    engine.evaluate(IN1, T0)
    engine.evaluate([], T0 + dt.timedelta(seconds=1))
    assert engine._departed == {}
