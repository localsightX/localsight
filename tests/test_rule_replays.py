"""Golden-replay harness (R3.5 seed): rules replayed over recorded tracks.

Each tests/replays/*.json fixture is a deterministic track recording that the
engine is driven over exactly as the worker drives it (same constructor, same
evaluate() call), so a fixture proves operator-visible behavior, not internals.
See tests/replays/README.md for the fixture format and provenance.
"""
import datetime as dt
import json
from pathlib import Path

import pytest

from packages.ai.rules import rule_engine_from_json

REPLAYS = sorted((Path(__file__).resolve().parent / "replays").glob("*.json"))
EPOCH = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def test_replay_fixtures_exist():
    assert REPLAYS, "no replay fixtures found under tests/replays/"


@pytest.mark.parametrize("path", REPLAYS, ids=lambda p: p.stem)
def test_replay(path):
    fx = json.loads(path.read_text())
    engine = rule_engine_from_json(fx["camera_id"], fx["rules"])
    fired = []  # (frame_index, rule_type, rule_id)
    for i, frame in enumerate(fx["frames"]):
        ts = EPOCH + dt.timedelta(seconds=float(frame["t"]))
        tracks = [(tr[0], tr[1], tuple(tr[2])) for tr in frame["tracks"]]
        for ev in engine.evaluate(tracks, ts):
            fired.append((i, ev.rule_type, ev.rule_id))
    for exp in fx["expect"]:
        rt, rid = exp["rule_type"], exp["rule_id"]
        hits = [f for f in fired if f[1] == rt and f[2] == rid]
        if "at_frame" in exp:
            assert (exp["at_frame"], rt, rid) in hits, f"fired={fired}"
        for bad in exp.get("not_at_frames", []):
            assert (bad, rt, rid) not in hits, f"fired unexpectedly at {bad}: fired={fired}"
        if exp.get("never_fires"):
            assert not hits, f"expected no fires: fired={fired}"
