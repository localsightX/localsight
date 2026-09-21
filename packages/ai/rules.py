"""Behavior analytics rule engine.

Real, dependency-free geometry + timing rules evaluated over *tracked objects*
(not raw pixels), matching the ONVIF Analytics Service Specification family:

  * Line crossing (virtual tripwire, optional direction)
  * Zone intrusion (field detector)
  * Loitering (zone + dwell time)
  * Object left behind / object removed (stationarity memory)
  * Crowd / occupancy counting (threshold in a zone)

The engine is stateful and intended to be instantiated **once per camera** by the
worker; it keeps per-track and per-zone memory across frames so a rule fires only
on a meaningful event. All coordinates are normalized [0,1] to match Detection/Track
boxes, so rule geometry configured in the UI maps directly onto model output.

Every emitted AnalyticEvent carries a stable rule_id and is the unit the alerting
and event-store layers consume.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# A normalized point
Pt = Tuple[float, float]

EVENT_LINE_CROSS = "line_cross"
EVENT_INTRUSION = "intrusion"
EVENT_LOITERING = "loitering"
EVENT_OBJECT_LEFT = "object_left"
EVENT_OBJECT_REMOVED = "object_removed"
EVENT_CROWD = "crowd"


@dataclass
class AnalyticEvent:
    rule_id: str
    rule_type: str
    camera_id: str
    track_id: str
    label: str
    bbox: Tuple[float, float, float, float]
    ts: dt.datetime
    score: float = 1.0
    detail: dict = field(default_factory=dict)


# ── geometry primitives (pure) ──────────────────────────────────────────────
def point_in_polygon(pt: Pt, poly: List[Pt]) -> bool:
    """Ray-casting point-in-polygon test."""
    x, y = pt
    inside = False
    n = len(poly)
    if n < 3:
        return False
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        intersect = ((yi > y) != (yj > y)) and (
            x < (xj - xi) * (y - yi) / (yj - yi) + xi
        )
        if intersect:
            inside = not inside
        j = i
    return inside


def _orient(a: Pt, b: Pt, c: Pt) -> float:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def segments_intersect(p1: Pt, p2: Pt, p3: Pt, p4: Pt) -> bool:
    """True if segment p1p2 properly crosses segment p3p4."""
    d1 = _orient(p3, p4, p1)
    d2 = _orient(p3, p4, p2)
    d3 = _orient(p1, p2, p3)
    d4 = _orient(p1, p2, p4)
    if ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0)):
        return True
    return False


def crossing_direction(prev: Pt, cur: Pt, line_a: Pt, line_b: Pt) -> float:
    """Sign of the cross product telling which side of the line we moved to.

    +1 / -1 encode the two traversal directions; used to honor directional
    tripwires (e.g. only alarm when entering, not when leaving)."""
    side_prev = (line_b[0] - line_a[0]) * (prev[1] - line_a[1]) - (
        line_b[1] - line_a[1]
    ) * (prev[0] - line_a[0])
    side_cur = (line_b[0] - line_a[0]) * (cur[1] - line_a[1]) - (
        line_b[1] - line_a[1]
    ) * (cur[0] - line_a[0])
    if side_prev == 0 and side_cur == 0:
        return 0.0
    return 1.0 if side_cur > side_prev else -1.0


# ── rule definitions ─────────────────────────────────────────────────────────
@dataclass
class LineCrossingRule:
    rule_id: str
    a: Pt
    b: Pt
    camera_id: str = ""
    direction: Optional[int] = None  # None=any, 1 or -1 = require that sign
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    labels: Tuple[str, ...] = ("person", "vehicle")


@dataclass
class ZoneIntrusionRule:
    rule_id: str
    zone: List[Pt]
    camera_id: str = ""
    min_dwell_sec: float = 0.0
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    labels: Tuple[str, ...] = ("person", "vehicle")


@dataclass
class LoiteringRule:
    rule_id: str
    zone: List[Pt]
    camera_id: str = ""
    dwell_sec: float = 30.0
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    labels: Tuple[str, ...] = ("person",)


@dataclass
class ObjectLeftRule:
    rule_id: str
    zone: List[Pt]
    camera_id: str = ""
    stationary_sec: float = 30.0
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    labels: Tuple[str, ...] = ("bag", "package", "person")


@dataclass
class CrowdCountRule:
    rule_id: str
    zone: List[Pt]
    camera_id: str = ""
    threshold: int = 10
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    labels: Tuple[str, ...] = ("person",)


@dataclass
class _TrackMem:
    last_center: Optional[Pt] = None
    inside_zones: dict = field(default_factory=dict)  # rule_id -> first entered ts
    loiter_zones: dict = field(default_factory=dict)  # rule_id -> first entered ts
    crossed_lines: set = field(default_factory=set)  # rule_ids already fired (hysteresis)
    bbox: Tuple[float, float, float, float] = (0.0, 0.0, 0.0, 0.0)
    label: str = "person"


class RuleEngine:
    """Stateful per-camera evaluator for behavior analytics."""

    def __init__(self, camera_id: str) -> None:
        self.camera_id = camera_id
        self.rules: List = []
        self._mem: dict[str, _TrackMem] = {}
        self._crowd_fired: dict = {}
        self._last_fire: dict[tuple[str, str] | str, dt.datetime] = {}  # grammar v1 cooldown

    def add(self, rule) -> None:
        if not getattr(rule, "camera_id", ""):
            rule.camera_id = self.camera_id
        self.rules.append(rule)

    def _center(self, bbox: Tuple[float, float, float, float]) -> Pt:
        x, y, w, h = bbox
        return (x + w / 2.0, y + h / 2.0)

    def _track_mem(self, track_id: str) -> _TrackMem:
        if track_id not in self._mem:
            self._mem[track_id] = _TrackMem()
        return self._mem[track_id]

    def _matches(self, rule_labels, label: str) -> bool:
        return not rule_labels or label in rule_labels

    def _cooldown_ok(self, key: str, ts: dt.datetime, cooldown_sec: float) -> bool:
        """Grammar v1 cooldown gate: True if ``key`` may fire at ``ts``.

        ``cooldown_sec <= 0`` (the default) never throttles; otherwise a key
        may fire again only once ``cooldown_sec`` have elapsed since its last
        fire. Callers that pass the gate must record it via ``_mark_fire``."""
        if cooldown_sec <= 0:
            return True
        last = self._last_fire.get(key)
        return last is None or (ts - last).total_seconds() >= cooldown_sec

    def _mark_fire(self, key: str, ts: dt.datetime) -> None:
        self._last_fire[key] = ts

    def evaluate(
        self,
        tracks: List[Tuple[str, str, Tuple[float, float, float, float]]],
        ts: dt.datetime,
    ) -> List[AnalyticEvent]:
        """tracks: list of (track_id, label, bbox). Returns fired AnalyticEvents.

        A track absent from this frame is forgotten (its memory is cleared)."""
        out: List[AnalyticEvent] = []
        seen = set()
        for track_id, label, bbox in tracks:
            seen.add(track_id)
            m = self._track_mem(track_id)
            m.bbox = bbox
            m.label = label
            center = self._center(bbox)
            prev = m.last_center
            m.last_center = center

            for rule in self.rules:
                if not self._matches(getattr(rule, "labels", ()), label):
                    continue
                if getattr(rule, "min_size", 0.0) and bbox[2] * bbox[3] < rule.min_size:
                    continue  # grammar v1 min_size: ignore tracks below the area floor
                rtype = type(rule).__name__
                if rtype == "LineCrossingRule":
                    out.extend(self._eval_line(rule, track_id, label, bbox, prev, center, ts, m))
                elif rtype == "ZoneIntrusionRule":
                    out.extend(self._eval_zone(rule, track_id, label, bbox, center, ts, m))
                elif rtype == "LoiteringRule":
                    out.extend(self._eval_loiter(rule, track_id, label, bbox, center, ts, m))
                elif rtype == "ObjectLeftRule":
                    out.extend(self._eval_object_left(rule, track_id, label, bbox, center, ts, m))
                elif rtype == "CrowdCountRule":
                    pass  # handled in a global pass below
        out.extend(self._eval_crowd(tracks, ts))
        for tid in list(self._mem):
            if tid not in seen:
                del self._mem[tid]
        return out

    # ── individual rule evaluators ──────────────────────────────────────────
    def _eval_line(self, rule, track_id, label, bbox, prev, cur, ts, m):
        if prev is None:
            return []
        if not segments_intersect(prev, cur, rule.a, rule.b):
            return []
        direction = crossing_direction(prev, cur, rule.a, rule.b)
        if rule.direction is not None and direction != rule.direction:
            return []
        rid = rule.rule_id
        if rid in m.crossed_lines:
            return []  # hysteresis: one event per entry
        m.crossed_lines.add(rid)
        return [AnalyticEvent(rid, EVENT_LINE_CROSS, self.camera_id, track_id, label, bbox, ts,
                               detail={"direction": direction})]

    def _eval_zone(self, rule, track_id, label, bbox, center, ts, m):
        rid = rule.rule_id
        inside = point_in_polygon(center, rule.zone)
        if inside:
            if rid not in m.inside_zones:
                m.inside_zones[rid] = ts
            dwell = (ts - m.inside_zones[rid]).total_seconds()
            if rule.min_dwell_sec and dwell < rule.min_dwell_sec:
                return []
            key = (rid, track_id)
            if not self._cooldown_ok(key, ts, getattr(rule, "cooldown_sec", 0.0)):
                return []  # cooldown active: _fired_ left unset so a later visit can fire
            if m.inside_zones.get("_fired_" + rid) is True:
                return []
            m.inside_zones["_fired_" + rid] = True
            self._mark_fire(key, ts)
            return [AnalyticEvent(rid, EVENT_INTRUSION, self.camera_id, track_id, label,
                                  bbox, ts, detail={"dwell_sec": round(dwell, 2)})]
        else:
            m.inside_zones.pop(rid, None)
            m.inside_zones.pop("_fired_" + rid, None)
            return []

    def _eval_loiter(self, rule, track_id, label, bbox, center, ts, m):
        rid = rule.rule_id
        inside = point_in_polygon(center, rule.zone)
        if inside:
            if rid not in m.loiter_zones:
                m.loiter_zones[rid] = ts
            dwell = (ts - m.loiter_zones[rid]).total_seconds()
            if dwell >= rule.dwell_sec and m.loiter_zones.get("_fired_" + rid) is not True:
                key = (rid, track_id)
                if not self._cooldown_ok(key, ts, getattr(rule, "cooldown_sec", 0.0)):
                    return []  # cooldown active: _fired_ left unset so a later visit can fire
                m.loiter_zones["_fired_" + rid] = True
                self._mark_fire(key, ts)
                return [AnalyticEvent(rid, EVENT_LOITERING, self.camera_id, track_id, label,
                                      bbox, ts, detail={"dwell_sec": round(dwell, 2)})]
            return []
        else:
            m.loiter_zones.pop(rid, None)
            m.loiter_zones.pop("_fired_" + rid, None)
            return []

    def _eval_object_left(self, rule, track_id, label, bbox, center, ts, m):
        rid = rule.rule_id
        inside = point_in_polygon(center, rule.zone)
        if inside:
            if rid not in m.loiter_zones:
                m.loiter_zones[rid] = ts
            dwell = (ts - m.loiter_zones[rid]).total_seconds()
            if dwell >= rule.stationary_sec and m.loiter_zones.get("_left_fired_" + rid) is not True:
                key = (rid, track_id)
                if not self._cooldown_ok(key, ts, getattr(rule, "cooldown_sec", 0.0)):
                    return []  # cooldown active: _left_fired_ left unset so a later visit can fire
                m.loiter_zones["_left_fired_" + rid] = True
                self._mark_fire(key, ts)
                return [AnalyticEvent(rid, EVENT_OBJECT_LEFT, self.camera_id, track_id, label,
                                      bbox, ts, detail={"stationary_sec": round(dwell, 2)})]
        else:
            if m.loiter_zones.get("_left_fired_" + rid) is True and label != "person":
                m.loiter_zones.pop("_left_fired_" + rid, None)
                return [AnalyticEvent(rid, EVENT_OBJECT_REMOVED, self.camera_id,
                                      track_id, label, bbox, ts)]
            m.loiter_zones.pop(rid, None)
            m.loiter_zones.pop("_left_fired_" + rid, None)
        return []

    def _eval_crowd(self, tracks, ts):
        out: List[AnalyticEvent] = []
        for rule in self.rules:
            if type(rule).__name__ != "CrowdCountRule":
                continue
            count = 0
            for track_id, label, bbox in tracks:
                if not self._matches(rule.labels, label):
                    continue
                if getattr(rule, "min_size", 0.0) and bbox[2] * bbox[3] < rule.min_size:
                    continue  # grammar v1 min_size: ignore tracks below the area floor
                if point_in_polygon(self._center(bbox), rule.zone):
                    count += 1
            fired = self._crowd_fired.get(rule.rule_id, False)
            if (count >= rule.threshold and not fired
                    and self._cooldown_ok(rule.rule_id, ts, getattr(rule, "cooldown_sec", 0.0))):
                self._crowd_fired[rule.rule_id] = True
                self._mark_fire(rule.rule_id, ts)
                rep = max((t for t in tracks if self._matches(rule.labels, t[1])),
                          key=lambda t: t[2][2] * t[2][3])[2] if tracks else (0, 0, 0, 0)
                out.append(AnalyticEvent(rule.rule_id, EVENT_CROWD, self.camera_id, "",
                                         "person", rep, ts,
                                         score=float(count), detail={"count": count}))
            elif count < rule.threshold:
                self._crowd_fired[rule.rule_id] = False
        return out


def rule_from_dict(camera_id: str, spec: dict):
    """Build a single rule from a JSON spec (UI/stored on Camera.rules).

    spec keys: type, rule_id, plus geometry (a/b points, or zone polygon),
    optional direction/dwell_sec/threshold/labels and the grammar v1 knobs
    cooldown_sec/min_size (see packages.ai.rulegrammar).
    """
    rtype = spec.get("type")
    rid = spec.get("rule_id") or f"{rtype}-{camera_id}"
    labels = tuple(spec.get("labels", ())) or ()
    cooldown = spec.get("cooldown_sec", 0.0)
    min_size = spec.get("min_size", 0.0)
    if rtype == "line_cross":
        return LineCrossingRule(rid, tuple(spec["a"]), tuple(spec["b"]), camera_id,
                                direction=spec.get("direction"),
                                labels=labels or ("person", "vehicle"),
                                cooldown_sec=cooldown, min_size=min_size)
    if rtype in ("intrusion", "loitering", "object_left"):
        zone = [tuple(p) for p in spec["zone"]]
        if rtype == "intrusion":
            return ZoneIntrusionRule(rid, zone, camera_id,
                                     min_dwell_sec=spec.get("min_dwell_sec", 0.0),
                                     labels=labels or ("person", "vehicle"),
                                     cooldown_sec=cooldown, min_size=min_size)
        if rtype == "loitering":
            return LoiteringRule(rid, zone, camera_id, dwell_sec=spec.get("dwell_sec", 30.0),
                                 labels=labels or ("person",),
                                 cooldown_sec=cooldown, min_size=min_size)
        return ObjectLeftRule(rid, zone, camera_id, stationary_sec=spec.get("stationary_sec", 30.0),
                              labels=labels or ("bag", "package"),
                              cooldown_sec=cooldown, min_size=min_size)
    if rtype == "crowd":
        return CrowdCountRule(rid, [tuple(p) for p in spec["zone"]], camera_id,
                              threshold=spec.get("threshold", 10), labels=labels or ("person",),
                              cooldown_sec=cooldown, min_size=min_size)
    raise ValueError(f"unknown rule type: {rtype}")


def rule_engine_from_json(camera_id: str, rules_json: list | None) -> "RuleEngine":
    """Construct a per-camera RuleEngine from a stored rules list (or empty)."""
    engine = RuleEngine(camera_id)
    for spec in (rules_json or []):
        try:
            engine.add(rule_from_dict(camera_id, spec))
        except (KeyError, ValueError):
            continue  # skip malformed rule specs rather than crash the worker
    return engine
