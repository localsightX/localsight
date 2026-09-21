"""Versioned rule grammar (v1) for per-camera behavior rules.

Pure validation/normalization for the JSON stored on ``Camera.rules`` and
consumed by ``packages.ai.rules.RuleEngine``. Stdlib-only so the worker can
import it without FastAPI/pydantic.

Contract:

* The stored payload is a bare JSON array of rule specs — that shape IS
  schema version 1. ``SCHEMA_VERSION`` records the contract; a future v2 may
  introduce a ``{"version": .., "rules": []}`` envelope (never silently).
* ``validate_rules`` returns human-readable field-path error strings (never
  raises) so the API can answer 400 with the exact offending paths.
* ``normalize_rules`` type-coerces a validated payload (floats for geometry,
  ints for direction/threshold) WITHOUT injecting or removing keys, so an
  already-valid payload round-trips byte-stable through ``GET /api/cameras``.
* v1 defines: ids, geometry (normalized points in [0, 1]), direction,
  dwell/stationary/min-dwell/threshold, label vocabulary, ``cooldown_sec``,
  ``min_size`` and the R3.2 ``id_switch_grace_sec`` (zone rules only — all
  consumed by ``RuleEngine``). Schedule / hysteresis-window / min-confidence
  knobs arrive with the epics that consume them (R3.6+); versioning makes
  that addition non-breaking.
"""
from __future__ import annotations

import math

SCHEMA_VERSION = 1
MAX_RULES_PER_CAMERA = 64
_MAX_ID = 64
_MAX_ZONE_POINTS = 32
_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
PLATFORM_LABELS = frozenset({
    "person", "vehicle", "bicycle", "motorcycle", "bus", "truck",
    "animal", "bag", "package",
})
RULE_TYPES = ("line_cross", "intrusion", "loitering", "object_left", "crowd")


class RuleGrammarError(ValueError):
    """Raised by ``normalize_rules`` when ``validate_rules`` found problems."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors) or "invalid rules payload")


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(float(v))


def _check_point(v, path: str, errors: list[str]) -> None:
    if not isinstance(v, (list, tuple)) or len(v) != 2 or not all(_is_num(c) for c in v):
        errors.append(f"{path}: expected [x, y] numbers")
        return
    x, y = (float(c) for c in v)
    if not (0.0 <= x <= 1.0 and 0.0 <= y <= 1.0):
        errors.append(f"{path}: coordinates must be within [0, 1]")


def _check_num(v, path: str, lo: float, hi: float, errors: list[str],
               integral: bool = False) -> None:
    if not _is_num(v):
        errors.append(f"{path}: must be a number")
    elif integral and float(v) != int(v):
        errors.append(f"{path}: must be an integer")
    elif not lo <= float(v) <= hi:
        errors.append(f"{path}: must be within [{lo}, {hi}]")


def _check_id(spec: dict, i: int, seen: dict[str, int], errors: list[str]) -> None:
    """Validate ``rule_id`` (optional; the engine factory defaults it to the type).

    Uniqueness is enforced over the *effective* id, so two id-less rules of the
    same type collide — they would produce one rid in the engine, silently
    merging their state."""
    raw = spec.get("rule_id")
    if raw is None:
        rid = str(spec.get("type", f"?{i}"))
    elif isinstance(raw, str) and raw and len(raw) <= _MAX_ID and set(raw) <= _ID_CHARS:
        rid = raw
    else:
        errors.append(f"rules[{i}].rule_id: must be a non-empty string of <= {_MAX_ID} "
                      f"chars from [A-Za-z0-9._:-]")
        rid = f"?{i}"
    if rid in seen:
        errors.append(f"rules[{i}].rule_id: duplicate id {rid!r} "
                      f"(first used in rules[{seen[rid]}])")
    else:
        seen[rid] = i


def validate_rules(rules) -> list[str]:
    """Validate a rules payload. Returns a list of field-path error strings.

    An empty list means the payload conforms to grammar v1."""
    errors: list[str] = []
    if not isinstance(rules, list):
        return ["rules: must be a JSON array of rule objects"]
    if len(rules) > MAX_RULES_PER_CAMERA:
        errors.append(f"rules: at most {MAX_RULES_PER_CAMERA} rules per camera (got {len(rules)})")
    seen: dict[str, int] = {}
    for i, spec in enumerate(rules):
        p = f"rules[{i}]"
        if not isinstance(spec, dict):
            errors.append(f"{p}: must be an object")
            continue
        rtype = spec.get("type")
        if rtype not in RULE_TYPES:
            errors.append(f"{p}.type: unknown rule type {rtype!r} "
                          f"(expected one of {', '.join(RULE_TYPES)})")
            continue
        _check_id(spec, i, seen, errors)
        if rtype == "line_cross":
            _check_point(spec.get("a"), f"{p}.a", errors)
            _check_point(spec.get("b"), f"{p}.b", errors)
            d = spec.get("direction")
            if d is not None and (isinstance(d, bool) or not isinstance(d, int)
                                  or d not in (1, -1)):
                errors.append(f"{p}.direction: must be 1 or -1 (or omitted for either direction)")
        else:
            zone = spec.get("zone")
            if not isinstance(zone, (list, tuple)) or not 3 <= len(zone) <= _MAX_ZONE_POINTS:
                errors.append(f"{p}.zone: expected 3..{_MAX_ZONE_POINTS} [x, y] points")
            else:
                for j, pt in enumerate(zone):
                    _check_point(pt, f"{p}.zone[{j}]", errors)
        if rtype == "intrusion":
            _check_num(spec.get("min_dwell_sec", 0.0), f"{p}.min_dwell_sec", 0.0, 3600.0, errors)
        elif rtype == "loitering":
            _check_num(spec.get("dwell_sec", 30.0), f"{p}.dwell_sec", 0.5, 3600.0, errors)
        elif rtype == "object_left":
            _check_num(spec.get("stationary_sec", 30.0), f"{p}.stationary_sec", 0.5, 3600.0, errors)
        elif rtype == "crowd":
            _check_num(spec.get("threshold", 10), f"{p}.threshold", 1, 500, errors, integral=True)
        labels = spec.get("labels")
        if labels is not None:
            if not isinstance(labels, list) or not all(isinstance(x, str) for x in labels):
                errors.append(f"{p}.labels: must be a list of strings")
            else:
                for x in labels:
                    if x not in PLATFORM_LABELS:
                        errors.append(f"{p}.labels: unknown label {x!r} (platform vocabulary: "
                                      f"{', '.join(sorted(PLATFORM_LABELS))})")
        cd = spec.get("cooldown_sec")
        if cd is not None:
            _check_num(cd, f"{p}.cooldown_sec", 0.0, 3600.0, errors)
        ms = spec.get("min_size")
        if ms is not None:
            _check_num(ms, f"{p}.min_size", 0.0, 0.5, errors)
        gs = spec.get("id_switch_grace_sec")
        if gs is not None:
            if rtype not in ("intrusion", "loitering", "object_left"):
                errors.append(f"{p}.id_switch_grace_sec: only supported for zone rules "
                              f"(intrusion, loitering, object_left)")
            else:
                _check_num(gs, f"{p}.id_switch_grace_sec", 0.0, 60.0, errors)
    return errors


def _point(v) -> list[float]:
    return [float(v[0]), float(v[1])]


def normalize_rules(rules: list[dict]) -> list[dict]:
    """Type-coerce a validated payload. No keys are added or removed.

    Raises ``RuleGrammarError`` if ``validate_rules`` would find problems —
    call ``validate_rules`` first at the API boundary for field-path errors."""
    errs = validate_rules(rules)
    if errs:
        raise RuleGrammarError(errs)
    out: list[dict] = []
    for spec in rules:
        s = dict(spec)
        rtype = s.get("type")
        if rtype == "line_cross":
            if isinstance(s.get("a"), (list, tuple)) and len(s["a"]) == 2:
                s["a"] = _point(s["a"])
            if isinstance(s.get("b"), (list, tuple)) and len(s["b"]) == 2:
                s["b"] = _point(s["b"])
            if s.get("direction") is not None:
                s["direction"] = int(s["direction"])
        else:
            zone = s.get("zone")
            if isinstance(zone, (list, tuple)):
                s["zone"] = [_point(pt) for pt in zone
                             if isinstance(pt, (list, tuple)) and len(pt) == 2]
            if rtype == "crowd":
                s["threshold"] = int(s.get("threshold", 10))
        for k in ("dwell_sec", "stationary_sec", "min_dwell_sec", "cooldown_sec", "min_size",
                  "id_switch_grace_sec"):
            if s.get(k) is not None:
                s[k] = float(s[k])
        out.append(s)
    return out
