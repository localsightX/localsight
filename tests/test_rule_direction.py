"""R3.3 — wrong-way/direction: crossing direction from a >=3-sample window.

Pinned empirically before the change: the single-segment logic false-fired on a
right-to-left travel that had one noisy frame (reported direction -1), while
the window logic compares earliest-vs-latest side and stays silent. Early
frames (history not yet built) keep the crossing-segment fallback.
"""
import datetime as dt

from packages.ai.rules import RuleEngine, crossing_direction_window, rule_from_dict

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
A = (0.5, 0.0)
B = (0.5, 1.0)
LINE = {"type": "line_cross", "rule_id": "w", "a": [0.5, 0.0], "b": [0.5, 1.0],
        "direction": -1}


def _run(xs, spec=None):
    """Feed bbox x positions (y/w/h fixed); returns [(frame, event)] hits."""
    engine = RuleEngine("cam")
    engine.add(rule_from_dict("cam", dict(spec or LINE)))
    hits = []
    for i, x in enumerate(xs):
        for ev in engine.evaluate([("t1", "person", (x, 0.45, 0.04, 0.08))],
                                  T0 + dt.timedelta(seconds=i)):
            hits.append((i, ev))
    return hits


def test_window_direction_needs_three_samples():
    assert crossing_direction_window([(0.3, 0.5), (0.4, 0.5)], A, B) is None
    assert crossing_direction_window([(0.3, 0.5), (0.4, 0.5), (0.6, 0.5)], A, B) == -1.0
    assert crossing_direction_window([(0.6, 0.5), (0.4, 0.5), (0.3, 0.5)], A, B) == 1.0
    # identical first/last side = ambiguous -> None (caller uses the segment)
    assert crossing_direction_window([(0.3, 0.5), (0.6, 0.5), (0.3, 0.5)], A, B) is None


def test_jitter_entry_still_fires_once():
    """A mid-trajectory backward jitter must not break the true crossing."""
    hits = _run([0.30, 0.38, 0.34, 0.44, 0.55, 0.63])
    assert [(i, ev.detail["direction"]) for i, ev in hits] == [(4, -1.0)]
    assert hits[0][1].detail["window"] == 4


def test_wrong_way_flicker_does_not_false_fire():
    """Single-sample flicker across the line used to report the wrong direction."""
    assert _run([0.63, 0.55, 0.44, 0.56, 0.46, 0.30]) == []
    # smooth wrong-way travel stays silent with the window too
    assert _run([0.63, 0.55, 0.46, 0.40, 0.30]) == []


def test_directionless_line_fires_both_ways():
    spec = {k: v for k, v in LINE.items() if k != "direction"}
    assert len(_run([0.30, 0.38, 0.46, 0.55, 0.63], spec)) == 1
    assert len(_run([0.63, 0.55, 0.46, 0.40, 0.30], spec)) == 1


def test_early_frames_use_segment_fallback():
    """With < 3 samples the crossing segment still decides (no silent drop)."""
    hits = _run([0.30, 0.55, 0.63])
    assert [(i, ev.detail["window"]) for i, ev in hits] == [(1, 2)]


def test_id_inheritance_clears_trajectory():
    """Grace-inherited ids start a fresh history (no borrowed direction)."""
    engine = RuleEngine("cam")
    engine.add(rule_from_dict("cam", {"type": "intrusion", "rule_id": "z",
                                      "zone": [[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 1.0]],
                                      "id_switch_grace_sec": 3}))
    engine.add(rule_from_dict("cam", dict(LINE)))
    frames = [(0, "t1", 0.30), (1, "t1", 0.38), (2, "t1", 0.42), (3, None, None),
              (4, "t2", 0.40), (5, "t2", 0.55)]
    hits = []
    for sec, tid, x in frames:
        tracks = [] if tid is None else [(tid, "person", (x, 0.45, 0.04, 0.08))]
        for ev in engine.evaluate(tracks, T0 + dt.timedelta(seconds=sec)):
            hits.append((sec, ev.rule_id, ev.detail))
    # t2 inherits the departed t1 state: the crossing fires on the segment
    # fallback (window 2), proving the inherited history was cleared.
    assert [(s, rid) for s, rid, _ in hits if rid == "w"] == [(5, "w")]
    assert [d["window"] for _, rid, d in hits if rid == "w"] == [2]
