"""Golden-replay harness (R3.5): fixtures replayed via packages.ai.replay.

The same core (run_replay + check_expect) backs the pytest runner, the CLI
(scripts/rule_replay.py) and the dry-run API (POST /api/rules/test) — a
fixture proves identical behavior in all three. See tests/replays/README.md
for the fixture format and provenance.
"""
import json
from pathlib import Path

import pytest

from packages.ai.replay import check_expect, run_replay

REPLAYS = sorted((Path(__file__).resolve().parent / "replays").glob("*.json"))


def test_replay_fixtures_exist():
    assert REPLAYS, "no replay fixtures found under tests/replays/"


@pytest.mark.parametrize("path", REPLAYS, ids=lambda p: p.stem)
def test_replay(path):
    fx = json.loads(path.read_text())
    result = run_replay(fx["camera_id"], fx["rules"], fx["frames"])
    fired = [(e["frame"], e["rule_type"], e["rule_id"]) for e in result["events"]]
    errs = check_expect(fx["expect"], fired)
    assert not errs, errs
