"""Unit tests for the R3.5 replay core (packages.ai.replay) + engine trace."""
import subprocess
import sys
from pathlib import Path

from packages.ai.replay import check_expect, run_replay, validate_frames

SQUARE = [[0.4, 0.4], [0.6, 0.4], [0.6, 0.6], [0.4, 0.6]]
RULES = [{"type": "intrusion", "rule_id": "z", "zone": SQUARE, "cooldown_sec": 5}]
FRAMES = [
    {"t": 0, "tracks": [["t1", "person", [0.48, 0.48, 0.04, 0.08]]]},
    {"t": 1, "tracks": [["t1", "person", [0.10, 0.10, 0.04, 0.08]]]},
    {"t": 2, "tracks": [["t1", "person", [0.48, 0.48, 0.04, 0.08]]]},
]


def test_validate_frames_field_paths():
    assert validate_frames("nope") == ["frames: must be a JSON array of {t, tracks} objects"]
    errs = validate_frames([{"t": -1, "tracks": [["t1", "person", [2, 0, 0, 0]]]}])
    assert any("frames[0].t" in e for e in errs)
    assert any("frames[0].tracks[0][2]" in e for e in errs)
    assert validate_frames([FRAMES[0]]) == []


def test_run_replay_timeline_decisions():
    result = run_replay("cam", RULES, FRAMES)
    decisions = [(e["frame"], e["decision"]) for e in result["timeline"] if e["rule_id"] == "z"]
    assert (0, "fired") in decisions
    assert (1, "no_zone_hit") in decisions
    assert (2, "cooldown_blocked") in decisions  # re-entry inside the 5 s cooldown
    assert result["summary"]["total_events"] == 1
    assert result["truncated"] is False


def test_run_replay_expect_verdict():
    ok = run_replay("cam", RULES, FRAMES,
                    expect=[{"rule_type": "intrusion", "rule_id": "z", "at_frame": 0}])
    assert ok["pass"] is True and ok["expect_errors"] == []
    bad = run_replay("cam", RULES, FRAMES,
                     expect=[{"rule_type": "intrusion", "rule_id": "z", "never_fires": True}])
    assert bad["pass"] is False and bad["expect_errors"]


def test_check_expect_semantics():
    fired = [(1, "intrusion", "z"), (4, "intrusion", "z")]
    assert check_expect([{"rule_type": "intrusion", "rule_id": "z", "at_frame": 1}], fired) == []
    errs = check_expect([
        {"rule_type": "intrusion", "rule_id": "z", "at_frame": 2},
        {"rule_type": "intrusion", "rule_id": "z", "not_at_frames": [4]},
        {"rule_type": "intrusion", "rule_id": "z", "never_fires": True},
        {"rule_type": 3, "rule_id": "z"},
    ], fired)
    assert len(errs) == 4


def test_grace_visible_in_trace():
    """R3.2 ID-switch grace shows up as inherited state, not a double fire."""
    rules = [{"type": "loitering", "rule_id": "l", "zone": SQUARE, "dwell_sec": 2,
              "id_switch_grace_sec": 3}]
    frames = [
        {"t": 0, "tracks": [["t1", "person", [0.48, 0.48, 0.04, 0.08]]]},
        {"t": 1, "tracks": [["t1", "person", [0.48, 0.48, 0.04, 0.08]]]},
        {"t": 2, "tracks": [["t1", "person", [0.48, 0.48, 0.04, 0.08]]]},  # fires (dwell 2)
        {"t": 3, "tracks": []},
        {"t": 4, "tracks": [["t2", "person", [0.48, 0.48, 0.04, 0.08]]]},  # inherits
    ]
    result = run_replay("cam", rules, frames)
    fired = [(e["frame"], e["rule_type"], e["rule_id"]) for e in result["events"]]
    assert fired == [(2, "loitering", "l")]
    late = [e for e in result["timeline"] if e["frame"] == 4]
    assert any(e["decision"] == "already_fired" for e in late)


def test_cli_replays_bundled_fixtures():
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "rule_replay.py"), "--quiet",
         str(root / "tests" / "replays" / "intrusion_fire_once.json")],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "pass=True" in proc.stdout
