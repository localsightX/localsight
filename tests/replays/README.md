# Golden replays (R3.5 seed)

Deterministic rule fixtures replayed by `tests/test_rule_replays.py` through the
**real** worker path — `rule_engine_from_json` + `RuleEngine.evaluate` — with no
mocks and no test-only code paths. A fixture proves operator-visible behavior.

## Fixture format (grammar v1)

```json
{
  "camera_id": "cam-replay",
  "description": "what behavior this proves",
  "rules":  ["...grammar v1 rule specs..."],
  "frames": [{"t": 0.0, "tracks": [["track-id", "person", [0.1, 0.2, 0.04, 0.08]]]}],
  "expect": [
    {"rule_type": "intrusion",  "rule_id": "v", "at_frame": 3},
    {"rule_type": "intrusion",  "rule_id": "v", "not_at_frames": [1, 2]},
    {"rule_type": "line_cross", "rule_id": "d", "never_fires": true}
  ]
}
```

- `t` is seconds since an arbitrary epoch; frames are fed in order via
  `evaluate(tracks, ts)` exactly as the worker does — all tracks of a frame in
  one call (tracks absent from a frame are forgotten by the engine).
- Coordinates are normalized `[0,1]` bboxes `(x, y, w, h)`; bbox centers drive
  zone/line geometry.
- Expectations are exhaustive per rule id: where fires must happen, where they
  must not, and that absent behavior stays absent.

## Adding a replay

1. Capture or hand-author the track frames (rig clips → a `scripts/rule_replay.py`
   exporter is planned for R3.5; hand-authored frames are fine today).
2. Write the fixture, run `pytest tests/test_rule_replays.py -q`, and calibrate
   frame indexes from the `fired=...` assertion messages.
3. The suite collects every `tests/replays/*.json` automatically — the runner
   fails loudly if the directory ever goes empty.
