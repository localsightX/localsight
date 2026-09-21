"""Replay-tester core (R3.5): one implementation shared by pytest, CLI, API.

Drives the real ``RuleEngine`` over a deterministic frame recording and
produces a verdict timeline — per frame, per rule: what the engine decided
and why. Decisions come from the engine's own optional trace (single source
of truth), never a shadow simulation. Dry-run contract: no persistence, no
alert fan-out, no camera access.
"""
from __future__ import annotations

import datetime as dt

from packages.ai.rules import rule_engine_from_json

EPOCH = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
MAX_FRAMES = 2048
MAX_TRACKS_PER_FRAME = 128
TRACE_CAP = 10000  # must match rules._TRACE_MAX


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def validate_frames(frames) -> list[str]:
    """Shape/bounds check for replay frames. Field-path error strings, same
    contract as rulegrammar.validate_rules (empty list = valid)."""
    errors: list[str] = []
    if not isinstance(frames, list):
        return ["frames: must be a JSON array of {t, tracks} objects"]
    if len(frames) > MAX_FRAMES:
        errors.append(f"frames: at most {MAX_FRAMES} frames (got {len(frames)})")
    for i, frame in enumerate(frames):
        p = f"frames[{i}]"
        if not isinstance(frame, dict):
            errors.append(f"{p}: must be an object")
            continue
        t = frame.get("t")
        if not isinstance(t, (int, float)) or isinstance(t, bool) or float(t) < 0:
            errors.append(f"{p}.t: must be a non-negative number of seconds")
        tracks = frame.get("tracks")
        if not isinstance(tracks, list):
            errors.append(f"{p}.tracks: must be an array")
            continue
        if len(tracks) > MAX_TRACKS_PER_FRAME:
            errors.append(f"{p}.tracks: at most {MAX_TRACKS_PER_FRAME} per frame "
                          f"(got {len(tracks)})")
            continue
        for j, tr in enumerate(tracks):
            q = f"{p}.tracks[{j}]"
            if not isinstance(tr, (list, tuple)) or len(tr) != 3:
                errors.append(f"{q}: expected [track_id, label, [x, y, w, h]]")
                continue
            tid, label, bbox = tr
            if not isinstance(tid, str) or not tid:
                errors.append(f"{q}[0]: track_id must be a non-empty string")
            if not isinstance(label, str) or not label:
                errors.append(f"{q}[1]: label must be a non-empty string")
            if (not isinstance(bbox, (list, tuple)) or len(bbox) != 4
                    or not all(_num(c) and 0.0 <= float(c) <= 1.0 for c in bbox)):
                errors.append(f"{q}[2]: expected [x, y, w, h] numbers within [0, 1]")
    return errors


def run_replay(camera_id: str, rules: list[dict], frames: list[dict],
               expect: list[dict] | None = None) -> dict:
    """Replay ``frames`` through the real engine with draft ``rules``.

    Returns {"camera_id", "frames", "timeline", "events", "summary",
    "truncated"} and, when ``expect`` is given, "pass" + "expect_errors" (the
    golden-replay verdict). Invalid rule specs are skipped by the engine
    factory (mirrors the worker's tolerant loader) — callers gate payloads
    with rulegrammar.validate_rules first."""
    engine = rule_engine_from_json(camera_id, rules)
    timeline: list[dict] = []
    events: list[dict] = []
    fired_by_rule: dict[str, int] = {}
    for i, frame in enumerate(frames):
        ts = EPOCH + dt.timedelta(seconds=float(frame["t"]))
        tracks: list[tuple[str, str, tuple[float, float, float, float]]] = []
        for tr in frame["tracks"]:
            bx, by, bw, bh = (float(c) for c in tr[2])
            tracks.append((tr[0], tr[1], (bx, by, bw, bh)))
        trace: list = []
        for ev in engine.evaluate(tracks, ts, trace=trace):
            events.append({"frame": i, "t": float(frame["t"]), "rule_id": ev.rule_id,
                           "rule_type": ev.rule_type, "track_id": ev.track_id,
                           "detail": ev.detail})
            fired_by_rule[ev.rule_id] = fired_by_rule.get(ev.rule_id, 0) + 1
        for entry in trace:
            entry["frame"] = i
        timeline.extend(trace)
    result: dict = {
        "camera_id": camera_id,
        "frames": len(frames),
        "timeline": timeline,
        "events": events,
        "summary": {"fired_by_rule": fired_by_rule, "total_events": len(events)},
        "truncated": len(timeline) >= TRACE_CAP,
    }
    if expect is not None:
        fired = [(e["frame"], e["rule_type"], e["rule_id"]) for e in events]
        errs = check_expect(expect, fired)
        result["pass"] = not errs
        result["expect_errors"] = errs
    return result


def check_expect(expect: list[dict], fired: list[tuple[int, str, str]]) -> list[str]:
    """Evaluate a fixture's ``expect`` entries against (frame, type, id) fires.

    The one semantics for pytest, the CLI and POST /api/rules/test:
    ``at_frame`` (int), ``not_at_frames`` (list) and ``never_fires`` (bool)."""
    errors: list[str] = []
    shown = str(fired[:20]) + ("..." if len(fired) > 20 else "")
    for k, exp in enumerate(expect):
        rt, rid = exp.get("rule_type"), exp.get("rule_id")
        if not isinstance(rt, str) or not isinstance(rid, str):
            errors.append(f"expect[{k}]: rule_type and rule_id are required strings")
            continue
        hits = [f for f in fired if f[1] == rt and f[2] == rid]
        if "at_frame" in exp and (exp["at_frame"], rt, rid) not in hits:
            errors.append(f"expect[{k}]: {rt}/{rid} did not fire at frame "
                          f"{exp['at_frame']} (fired={shown})")
        for bad in exp.get("not_at_frames", []):
            if (bad, rt, rid) in hits:
                errors.append(f"expect[{k}]: {rt}/{rid} fired unexpectedly at "
                              f"frame {bad} (fired={shown})")
        if exp.get("never_fires") and hits:
            errors.append(f"expect[{k}]: {rt}/{rid} should never fire (fired={shown})")
    return errors
