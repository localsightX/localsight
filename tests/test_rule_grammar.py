"""R3 S1 — rule grammar v1: validation, normalization, and engine knobs.

Covers the field-path error contract (packages.ai.rulegrammar), the
normalize-round-trip stability the API relies on, and the two engine knobs v1
introduces (cooldown_sec / min_size) exercised through the real RuleEngine.
"""
import datetime as dt

import pytest

from packages.ai import rulegrammar as rg
from packages.ai.rules import RuleEngine, rule_engine_from_json, rule_from_dict

ZONE = [[0.4, 0.4], [0.6, 0.4], [0.6, 0.6], [0.4, 0.6]]


def test_valid_payload_has_no_errors():
    rules = [
        {"type": "line_cross", "rule_id": "door", "a": [0.5, 0.0], "b": [0.5, 1.0],
         "direction": 1, "cooldown_sec": 5, "labels": ["person"]},
        {"type": "intrusion", "rule_id": "vault", "zone": ZONE, "min_dwell_sec": 2},
        {"type": "loitering", "rule_id": "wait", "zone": ZONE, "dwell_sec": 30,
         "id_switch_grace_sec": 2},
        {"type": "object_left", "rule_id": "bag", "zone": ZONE, "stationary_sec": 45},
        {"type": "crowd", "rule_id": "queue", "zone": ZONE, "threshold": 5},
    ]
    assert rg.validate_rules(rules) == []


@pytest.mark.parametrize("payload,frag", [
    ("nope", "must be a JSON array"),
    ([{"type": "bogus"}], "unknown rule type"),
    ([{"type": "line_cross", "rule_id": "x", "a": [2, 0], "b": [0.5, 1]}], "within [0, 1]"),
    ([{"type": "line_cross", "rule_id": "x", "a": [0, 0]}], "expected [x, y] numbers"),
    ([{"type": "intrusion", "rule_id": "x", "zone": [[0, 0], [1, 1]]}], "expected 3.."),
    ([{"type": "intrusion", "rule_id": "x", "zone": ZONE, "min_dwell_sec": -1}], "min_dwell_sec"),
    ([{"type": "loitering", "rule_id": "x", "zone": ZONE, "dwell_sec": 9999}], "within [0.5, 3600.0]"),
    ([{"type": "object_left", "rule_id": "x", "zone": ZONE, "stationary_sec": "soon"}], "must be a number"),
    ([{"type": "crowd", "rule_id": "x", "zone": ZONE, "threshold": 0}], "within [1, 500]"),
    ([{"type": "crowd", "rule_id": "x", "zone": ZONE, "threshold": 2.5}], "must be an integer"),
    ([{"type": "line_cross", "rule_id": "x", "a": [0, 0], "b": [1, 1], "direction": 2}], "must be 1 or -1"),
    ([{"type": "line_cross", "rule_id": "x", "a": [0, 0], "b": [1, 1], "direction": True}], "must be 1 or -1"),
    ([{"type": "intrusion", "rule_id": "x", "zone": ZONE, "labels": ["car"]}], "unknown label"),
    ([{"type": "intrusion", "rule_id": "x", "zone": ZONE, "labels": "person"}], "must be a list of strings"),
    ([{"type": "intrusion", "rule_id": "x", "zone": ZONE},
      {"type": "intrusion", "rule_id": "x", "zone": ZONE}], "duplicate id"),
    ([{"type": "intrusion", "zone": ZONE}, {"type": "intrusion", "zone": ZONE}], "duplicate id"),
    ([{"type": "intrusion", "rule_id": "bad id!", "zone": ZONE}], "rule_id"),
    ([{"type": "intrusion", "rule_id": "x", "zone": ZONE, "cooldown_sec": -1}], "cooldown_sec"),
    ([{"type": "intrusion", "rule_id": "x", "zone": ZONE, "min_size": 0.9}], "min_size"),
    ([{"type": "loitering", "rule_id": "x", "zone": ZONE, "id_switch_grace_sec": -1}],
     "id_switch_grace_sec"),
    ([{"type": "loitering", "rule_id": "x", "zone": ZONE, "id_switch_grace_sec": 61}],
     "id_switch_grace_sec"),
    ([{"type": "line_cross", "rule_id": "x", "a": [0, 0], "b": [1, 1],
      "id_switch_grace_sec": 2}], "only supported for zone rules"),
])
def test_invalid_payloads_report_field_paths(payload, frag):
    errs = rg.validate_rules(payload)
    assert errs and any(frag in e for e in errs), errs


def test_normalize_roundtrip_is_stable_and_type_coerces():
    rules = [{"type": "line_cross", "rule_id": "d", "a": [0.5, 0], "b": [0.5, 1.0],
              "direction": 1, "cooldown_sec": 5},
             {"type": "loitering", "rule_id": "w", "zone": ZONE, "dwell_sec": 30,
              "id_switch_grace_sec": 3}]
    norm = rg.normalize_rules(rules)
    assert norm[0]["a"] == [0.5, 0.0] and isinstance(norm[0]["a"][1], float)
    assert norm[0]["direction"] == 1 and norm[0]["cooldown_sec"] == 5.0
    assert norm[1]["id_switch_grace_sec"] == 3.0
    assert all(set(n) == set(r) for n, r in zip(norm, rules, strict=True))  # no key injection
    assert rg.normalize_rules(norm) == norm  # already-normalized payload is a fixed point


def test_normalize_rejects_what_validate_rejects():
    with pytest.raises(rg.RuleGrammarError) as exc:
        rg.normalize_rules([{"type": "bogus"}])
    assert exc.value.errors and "unknown rule type" in exc.value.errors[0]


def test_factory_and_engine_accept_new_knobs():
    spec = {"type": "intrusion", "rule_id": "v", "zone": ZONE, "cooldown_sec": 5, "min_size": 0.001}
    rule = rule_from_dict("cam1", spec)
    assert rule.cooldown_sec == 5 and rule.min_size == 0.001
    # malformed specs are still skipped by the loader (worker guard unchanged)
    assert len(rule_engine_from_json("cam1", [spec, {"type": "bogus"}]).rules) == 1


def _T(tid, x, y=0.5, w=0.04, h=0.08):
    return (tid, "person", (x, y, w, h))


def test_cooldown_suppresses_repeat_zone_fires():
    t0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    step = dt.timedelta(seconds=1)
    # enter -> leave -> re-enter within cooldown -> leave -> re-enter after cooldown
    frames = [(0, _T("t1", 0.5)), (1, _T("t1", 0.1)), (2, _T("t1", 0.5)),
              (3, _T("t1", 0.5)), (6, _T("t1", 0.1)), (10, _T("t1", 0.5))]

    engine = RuleEngine("cam1")
    engine.add(rule_from_dict("cam1", {"type": "intrusion", "rule_id": "v",
                                       "zone": ZONE, "cooldown_sec": 5}))
    fired = [sec for sec, tr in frames
             if any(e.rule_type == "intrusion" for e in engine.evaluate([tr], t0 + sec * step))]
    assert fired == [0, 10]  # the t=2 re-entry is suppressed by the 5 s cooldown

    engine = RuleEngine("cam1")  # cooldown 0 (default): every entry fires
    engine.add(rule_from_dict("cam1", {"type": "intrusion", "rule_id": "v", "zone": ZONE}))
    fired = [sec for sec, tr in frames
             if any(e.rule_type == "intrusion" for e in engine.evaluate([tr], t0 + sec * step))]
    assert fired == [0, 2, 10]  # three zone entries, no throttle


def test_min_size_filters_tiny_tracks():
    engine = RuleEngine("cam1")
    engine.add(rule_from_dict("cam1", {
        "type": "intrusion", "rule_id": "v",
        "zone": [[0, 0], [1, 0], [1, 1], [0, 1]], "min_size": 0.01}))
    t0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    big = engine.evaluate([_T("t1", 0.5, w=0.2, h=0.2)], t0)  # bbox area 0.04 >= 0.01
    tiny = engine.evaluate([_T("t2", 0.5, w=0.05, h=0.05)], t0 + dt.timedelta(seconds=1))
    assert any(e.rule_type == "intrusion" for e in big)
    assert not any(e.rule_type == "intrusion" for e in tiny)
