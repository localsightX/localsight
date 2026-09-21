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
from collections import deque
from collections.abc import Sequence
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
EVENT_STOPPED_VEHICLE = "stopped_vehicle"

# R3.4: labels that can *own* an abandoned-object candidate
_OWNER_LABELS = frozenset({"person", "vehicle", "truck", "bus", "motorcycle", "bicycle"})
_ATTACH_MIN_OVERLAP = 0.1  # owner must cover this share of the candidate's area

# Verdict tracing (R3.5 replay tester): dataclass name -> grammar type name
_RULE_TYPE_NAMES = {
    "LineCrossingRule": "line_cross",
    "ZoneIntrusionRule": "intrusion",
    "LoiteringRule": "loitering",
    "ObjectLeftRule": "object_left",
    "CrowdCountRule": "crowd",
    "StoppedVehicleRule": "stopped_vehicle",
}
_TRACE_MAX = 10000  # verdict-trace cap so a pathological dry-run cannot balloon
_DIR_MIN_SAMPLES = 3  # R3.3: direction from a >=3-sample trajectory window
_DIR_WINDOW = 4       # bounded per-track center history (deque maxlen)


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


def signed_side(p: Pt, line_a: Pt, line_b: Pt) -> float:
    """Signed side of ``p`` relative to the a->b line (crossing_direction's
    convention: +1 reported when the side value increases)."""
    return (line_b[0] - line_a[0]) * (p[1] - line_a[1]) - (
        line_b[1] - line_a[1]
    ) * (p[0] - line_a[0])


def crossing_direction(prev: Pt, cur: Pt, line_a: Pt, line_b: Pt) -> float:
    """Sign of the cross product telling which side of the line we moved to.

    +1 / -1 encode the two traversal directions; used to honor directional
    tripwires (e.g. only alarm when entering, not when leaving)."""
    side_prev = signed_side(prev, line_a, line_b)
    side_cur = signed_side(cur, line_a, line_b)
    if side_prev == 0 and side_cur == 0:
        return 0.0
    return 1.0 if side_cur > side_prev else -1.0


def crossing_direction_window(history: Sequence[Pt], line_a: Pt, line_b: Pt) -> float | None:
    """Net traversal direction over a trajectory window (R3.3, >= 3 samples).

    Compares the signed side of the earliest vs the latest sample, so a single
    jittery detection cannot flip the reported direction. Returns None when
    fewer than ``_DIR_MIN_SAMPLES`` points are available or the net
    displacement is zero (genuinely ambiguous) - callers fall back to
    ``crossing_direction`` on the crossing segment itself."""
    if len(history) < _DIR_MIN_SAMPLES:
        return None
    delta = signed_side(history[-1], line_a, line_b) - signed_side(history[0], line_a, line_b)
    if delta == 0:
        return None
    return 1.0 if delta > 0 else -1.0


# Zone-hit coverage floor — mirrors pipeline._MASK_MIN_OVERLAP so rule zones and
# privacy masks agree on what "in the zone" means (R3.1 acceptance).
_ZONE_MIN_OVERLAP = 0.5
_MAX_DEPARTED = 32        # ID-switch grace tombstone cap (memory bound)
_INHERIT_REACH_MIN = 0.12  # min normalized center distance for inheritance


def polygon_area(poly: List[Pt]) -> float:
    """Unsigned shoelace area of a simple polygon."""
    s = 0.0
    n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]
        x2, y2 = poly[(i + 1) % n]
        s += x1 * y2 - x2 * y1
    return abs(s) / 2.0


def _clip_polygon(poly: List[Pt], rect: Tuple[float, float, float, float]) -> List[Pt]:
    """Sutherland-Hodgman clip of `poly` against the bbox rectangle (convex)."""
    rx, ry, rw, rh = rect
    corners = ((rx, ry), (rx + rw, ry), (rx + rw, ry + rh), (rx, ry + rh))  # CCW

    def side(p: Pt, a: Pt, b: Pt) -> float:
        return _orient(a, b, p)

    out = list(poly)
    n = len(corners)
    for i in range(n):
        a, b = corners[i], corners[(i + 1) % n]
        inp, out = out, []
        j = len(inp)
        for k in range(j):
            p, q = inp[k], inp[(k + 1) % j]
            pin, qin = side(p, a, b) >= 0, side(q, a, b) >= 0
            if qin:
                if not pin:
                    denom = side(p, a, b) - side(q, a, b)
                    t = side(p, a, b) / denom if denom else 0.0
                    out.append((p[0] + t * (q[0] - p[0]), p[1] + t * (q[1] - p[1])))
                out.append(q)
            elif pin:
                denom = side(p, a, b) - side(q, a, b)
                t = side(p, a, b) / denom if denom else 0.0
                out.append((p[0] + t * (q[0] - p[0]), p[1] + t * (q[1] - p[1])))
    return out


def bboxes_attached(cand: tuple[float, float, float, float],
                    other: tuple[float, float, float, float]) -> bool:
    """True when ``other`` (an owner box: person/vehicle) is attached to ``cand``.

    R3.4 abandonment test: the candidate's center lies inside the owner's box
    (carried, stood over) or the owner covers at least ``_ATTACH_MIN_OVERLAP``
    of the candidate's area (a hand on the handle, a car door). Both in
    normalized [0,1] coordinates."""
    cx, cy = cand[0] + cand[2] / 2, cand[1] + cand[3] / 2
    if other[0] <= cx <= other[0] + other[2] and other[1] <= cy <= other[1] + other[3]:
        return True
    ix = max(0.0, min(cand[0] + cand[2], other[0] + other[2]) - max(cand[0], other[0]))
    iy = max(0.0, min(cand[1] + cand[3], other[1] + other[3]) - max(cand[1], other[1]))
    area = cand[2] * cand[3]
    return area > 0 and (ix * iy) / area >= _ATTACH_MIN_OVERLAP


def bbox_zone_overlap_fraction(
    bbox: Tuple[float, float, float, float], poly: List[Pt]
) -> float:
    """Fraction of `bbox` covered by the zone polygon (both normalized).

    The polygon analogue of pipeline._bbox_overlap_fraction: clip the zone to
    the bbox rectangle, shoelace the result, divide by the bbox area. Used by
    the zone-hit predicate so a detection whose centroid sits outside the zone
    but whose box is majority-covered still counts as inside."""
    bw, bh = bbox[2], bbox[3]
    area = bw * bh
    if area <= 0 or len(poly) < 3:
        return 0.0
    clipped = _clip_polygon(poly, bbox)
    if len(clipped) < 3:
        return 0.0
    return min(1.0, polygon_area(clipped) / area)


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
    id_switch_grace_sec: float = 0.0  # R3.2: inherit dwell across tracker ID switches
    labels: Tuple[str, ...] = ("person", "vehicle")


@dataclass
class LoiteringRule:
    rule_id: str
    zone: List[Pt]
    camera_id: str = ""
    dwell_sec: float = 30.0
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    id_switch_grace_sec: float = 0.0  # R3.2: inherit dwell across tracker ID switches
    labels: Tuple[str, ...] = ("person",)


@dataclass
class ObjectLeftRule:
    rule_id: str
    zone: List[Pt]
    camera_id: str = ""
    stationary_sec: float = 30.0
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    id_switch_grace_sec: float = 0.0  # R3.2: inherit dwell across tracker ID switches
    require_unattended: bool = True   # R3.4: attached owner => not abandoned
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
class StoppedVehicleRule:
    rule_id: str
    zone: list[Pt]
    camera_id: str = ""
    stopped_sec: float = 30.0  # R3.4: dwell at ~0 speed before firing
    max_speed: float = 0.02    # R3.4: normalized units/second that counts as stopped
    cooldown_sec: float = 0.0  # grammar v1: min seconds between fires (0 = unlimited)
    min_size: float = 0.0      # grammar v1: minimum normalized bbox area (w*h)
    id_switch_grace_sec: float = 0.0  # R3.2: inherit dwell across tracker ID switches
    labels: tuple[str, ...] = ("vehicle", "truck", "bus", "motorcycle", "bicycle")


@dataclass
class _TrackMem:
    last_center: Optional[Pt] = None
    history: deque = field(default_factory=lambda: deque(maxlen=_DIR_WINDOW))  # R3.3
    ts_history: deque = field(default_factory=lambda: deque(maxlen=_DIR_WINDOW))  # R3.4 speed
    inside_zones: dict = field(default_factory=dict)  # rule_id -> first entered ts
    loiter_zones: dict = field(default_factory=dict)  # rule_id -> first entered ts
    stopped_zones: dict = field(default_factory=dict)  # R3.4 rule_id -> stopped since ts
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
        self._departed: dict[str, tuple[dt.datetime, _TrackMem]] = {}  # R3.2 grace
        self._trace: list[dict] | None = None  # R3.5 verdict tracing (per evaluate call)

    def add(self, rule) -> None:
        if not getattr(rule, "camera_id", ""):
            rule.camera_id = self.camera_id
        self.rules.append(rule)

    def _center(self, bbox: Tuple[float, float, float, float]) -> Pt:
        x, y, w, h = bbox
        return (x + w / 2.0, y + h / 2.0)

    def _track_mem(self, track_id: str, bbox=None, ts: dt.datetime | None = None) -> _TrackMem:
        """Per-track memory. A *new* track id may inherit a departed track's
        zone dwell state (R3.2 ID-switch grace) when bbox/ts are provided —
        see ``_inherit_departed``; without them behavior is unchanged."""
        m = self._mem.get(track_id)
        if m is None:
            m = self._inherit_departed(track_id, bbox, ts) if ts is not None else None
            m = m if m is not None else _TrackMem()
            self._mem[track_id] = m
        return m

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

    def _trace_append(self, ts: dt.datetime, decision: str, rule, track_id: str = "",
                      **detail) -> None:
        """Append a verdict-trace record (R3.5 replay tester).

        No-op unless ``evaluate()`` was handed a trace list — the worker path
        never does, so production pays only one ``is None`` check. Capped at
        ``_TRACE_MAX`` so a pathological dry-run cannot balloon memory."""
        if self._trace is None or len(self._trace) >= _TRACE_MAX:
            return
        self._trace.append({
            "t": ts, "decision": decision,
            "rule_id": getattr(rule, "rule_id", ""),
            "rule_type": _RULE_TYPE_NAMES.get(type(rule).__name__, "unknown"),
            "track_id": track_id, **detail,
        })

    def _grace_max(self) -> float:
        """Largest configured ID-switch grace across rules (0 disables the
        tombstone machinery entirely, preserving pre-R3.2 behavior)."""
        return max((getattr(r, "id_switch_grace_sec", 0.0) or 0.0
                    for r in self.rules), default=0.0)

    def _zone_hit(self, poly, bbox) -> bool:
        """Zone hit = center inside OR >= _ZONE_MIN_OVERLAP of the bbox covered.

        Mirrors ``CameraPipeline._is_masked`` so rule zones and privacy masks
        agree on what "in the zone" means (R3.1 acceptance)."""
        if point_in_polygon(self._center(bbox), poly):
            return True
        return bbox_zone_overlap_fraction(bbox, poly) >= _ZONE_MIN_OVERLAP

    def _trajectory_speed(self, m: _TrackMem) -> float:
        """Mean speed over the trajectory window (normalized units / second).

        R3.4: uses the same bounded window as R3.3's direction, so one jittery
        detection cannot make a parked car look like it is moving. Returns 0.0
        when the window is too short to measure — a fresh track has no evidence
        of movement yet, so a stopped-vehicle timer may start."""
        if len(m.history) < 2 or len(m.ts_history) < 2:
            return 0.0
        (x0, y0), (x1, y1) = m.history[0], m.history[-1]
        span = (m.ts_history[-1] - m.ts_history[0]).total_seconds()
        if span <= 0:
            return 0.0
        return (((x1 - x0) ** 2 + (y1 - y0) ** 2) ** 0.5) / span

    def _has_attached_owner(self, cand, track_id: str, tracks) -> bool:
        """R3.4: is any person/vehicle track attached to this candidate box?"""
        for tid, label, bbox in tracks:
            if tid == track_id or label not in _OWNER_LABELS:
                continue
            if bboxes_attached(cand, bbox):
                return True
        return False

    def _inherit_departed(self, track_id: str, bbox, ts: dt.datetime) -> _TrackMem | None:
        """ID-switch grace (R3.2): a new track id appearing near where a
        recently-departed track vanished inherits its zone dwell state (entry
        timestamps + fired flags), so a tracker re-assignment inside a zone
        neither resets dwell nor double-fires.

        Line-crossing state is deliberately NOT inherited (a new id is a new
        approach; per-entry hysteresis must re-arm), the tombstone is consumed
        on inheritance (transfer, not copy), and inheritance requires the new
        center to be within ``max(_INHERIT_REACH_MIN, w+h)`` of the departed
        one — detector flicker, not a different object."""
        if not self._departed or bbox is None:
            return None
        cx, cy = bbox[0] + bbox[2] / 2, bbox[1] + bbox[3] / 2
        reach = max(_INHERIT_REACH_MIN, bbox[2] + bbox[3])
        grace = self._grace_max()
        best, best_d = None, None
        for tid, (dts, dmem) in self._departed.items():
            if (ts - dts).total_seconds() > grace:
                continue
            db = dmem.bbox
            dx, dy = db[0] + db[2] / 2, db[1] + db[3] / 2
            d = ((cx - dx) ** 2 + (cy - dy) ** 2) ** 0.5
            if d <= reach and (best_d is None or d < best_d):
                best, best_d = tid, d
        if best is None:
            return None
        _, mem = self._departed.pop(best)
        mem.last_center = None  # never fabricate a line crossing across ids
        mem.crossed_lines = set()
        mem.history.clear()  # a new id is a new trajectory
        return mem

    def _prune_departed(self, ts: dt.datetime, grace: float) -> None:
        """Bound the tombstone table: expire past grace, cap at _MAX_DEPARTED."""
        if not self._departed:
            return
        for tid, (dts, _) in list(self._departed.items()):
            if (ts - dts).total_seconds() > grace:
                del self._departed[tid]
        while len(self._departed) > _MAX_DEPARTED:
            oldest = min(self._departed, key=lambda t: self._departed[t][0])
            del self._departed[oldest]

    def evaluate(
        self,
        tracks: List[Tuple[str, str, Tuple[float, float, float, float]]],
        ts: dt.datetime,
        trace: list[dict] | None = None,
    ) -> List[AnalyticEvent]:
        """tracks: list of (track_id, label, bbox). Returns fired AnalyticEvents.

        A track absent from this frame is forgotten (its memory is cleared).
        ``trace`` (R3.5): when given, a verdict record is appended for every
        evaluated decision (fired / blocked / warming / ...) so the replay
        tester can explain itself. The worker leaves it None."""
        self._trace = trace
        out: List[AnalyticEvent] = []
        seen = set()
        for track_id, label, bbox in tracks:
            seen.add(track_id)
            m = self._track_mem(track_id, bbox, ts)
            m.bbox = bbox
            m.label = label
            center = self._center(bbox)
            prev = m.last_center
            m.last_center = center
            m.history.append(center)
            m.ts_history.append(ts)

            for rule in self.rules:
                if not self._matches(getattr(rule, "labels", ()), label):
                    continue
                if getattr(rule, "min_size", 0.0) and bbox[2] * bbox[3] < rule.min_size:
                    self._trace_append(ts, "min_size_skipped", rule, track_id,
                                       area=round(bbox[2] * bbox[3], 4), need=rule.min_size)
                    continue  # grammar v1 min_size: ignore tracks below the area floor
                rtype = type(rule).__name__
                if rtype == "LineCrossingRule":
                    out.extend(self._eval_line(rule, track_id, label, bbox, prev, center, ts, m))
                elif rtype == "ZoneIntrusionRule":
                    out.extend(self._eval_zone(rule, track_id, label, bbox, center, ts, m))
                elif rtype == "LoiteringRule":
                    out.extend(self._eval_loiter(rule, track_id, label, bbox, center, ts, m))
                elif rtype == "ObjectLeftRule":
                    out.extend(self._eval_object_left(rule, track_id, label, bbox, center, ts, m,
                                                      tracks))
                elif rtype == "StoppedVehicleRule":
                    out.extend(self._eval_stopped(rule, track_id, label, bbox, center, ts, m))
                elif rtype == "CrowdCountRule":
                    pass  # handled in a global pass below
        out.extend(self._eval_crowd(tracks, ts))
        grace = self._grace_max()
        for tid in list(self._mem):
            if tid not in seen:
                mem = self._mem.pop(tid)
                if grace > 0 and (mem.inside_zones or mem.loiter_zones
                                  or mem.stopped_zones):
                    self._departed[tid] = (ts, mem)  # ID-switch grace tombstone
        self._prune_departed(ts, grace)
        return out

    # ── individual rule evaluators ──────────────────────────────────────────
    def _eval_line(self, rule, track_id, label, bbox, prev, cur, ts, m):
        if prev is None:
            return []
        if not segments_intersect(prev, cur, rule.a, rule.b):
            self._trace_append(ts, "no_cross", rule, track_id)
            return []
        # R3.3: direction from the trajectory window (>= 3 samples) so one
        # jittery detection cannot flip it; fall back to the crossing segment
        # while the track is still building history (or the window is ambiguous).
        direction = crossing_direction_window(m.history, rule.a, rule.b)
        if direction is None:
            direction = crossing_direction(prev, cur, rule.a, rule.b)
        if rule.direction is not None and direction != rule.direction:
            self._trace_append(ts, "direction_mismatch", rule, track_id, got=direction)
            return []
        rid = rule.rule_id
        if rid in m.crossed_lines:
            self._trace_append(ts, "already_fired", rule, track_id)
            return []  # hysteresis: one event per entry
        m.crossed_lines.add(rid)
        self._trace_append(ts, "fired", rule, track_id, direction=direction,
                           window=len(m.history))
        return [AnalyticEvent(rid, EVENT_LINE_CROSS, self.camera_id, track_id, label, bbox, ts,
                               detail={"direction": direction, "window": len(m.history)})]

    def _eval_zone(self, rule, track_id, label, bbox, center, ts, m):
        rid = rule.rule_id
        inside = self._zone_hit(rule.zone, bbox)
        if inside:
            if rid not in m.inside_zones:
                m.inside_zones[rid] = ts
            dwell = (ts - m.inside_zones[rid]).total_seconds()
            if rule.min_dwell_sec and dwell < rule.min_dwell_sec:
                self._trace_append(ts, "min_dwell_warming", rule, track_id,
                                   dwell=round(dwell, 2), need=rule.min_dwell_sec)
                return []
            key = (rid, track_id)
            if not self._cooldown_ok(key, ts, getattr(rule, "cooldown_sec", 0.0)):
                self._trace_append(ts, "cooldown_blocked", rule, track_id)
                return []  # cooldown active: _fired_ left unset so a later visit can fire
            if m.inside_zones.get("_fired_" + rid) is True:
                self._trace_append(ts, "already_fired", rule, track_id)
                return []
            m.inside_zones["_fired_" + rid] = True
            self._mark_fire(key, ts)
            self._trace_append(ts, "fired", rule, track_id, dwell=round(dwell, 2))
            return [AnalyticEvent(rid, EVENT_INTRUSION, self.camera_id, track_id, label,
                                  bbox, ts, detail={"dwell_sec": round(dwell, 2)})]
        else:
            self._trace_append(ts, "no_zone_hit", rule, track_id)
            m.inside_zones.pop(rid, None)
            m.inside_zones.pop("_fired_" + rid, None)
            return []

    def _eval_loiter(self, rule, track_id, label, bbox, center, ts, m):
        rid = rule.rule_id
        inside = self._zone_hit(rule.zone, bbox)
        if inside:
            if rid not in m.loiter_zones:
                m.loiter_zones[rid] = ts
            dwell = (ts - m.loiter_zones[rid]).total_seconds()
            if dwell >= rule.dwell_sec and m.loiter_zones.get("_fired_" + rid) is not True:
                key = (rid, track_id)
                if not self._cooldown_ok(key, ts, getattr(rule, "cooldown_sec", 0.0)):
                    self._trace_append(ts, "cooldown_blocked", rule, track_id)
                    return []  # cooldown active: _fired_ left unset so a later visit can fire
                m.loiter_zones["_fired_" + rid] = True
                self._mark_fire(key, ts)
                self._trace_append(ts, "fired", rule, track_id, dwell=round(dwell, 2))
                return [AnalyticEvent(rid, EVENT_LOITERING, self.camera_id, track_id, label,
                                      bbox, ts, detail={"dwell_sec": round(dwell, 2)})]
            self._trace_append(ts, "dwell_warming" if dwell < rule.dwell_sec
                               else "already_fired", rule, track_id,
                               dwell=round(dwell, 2), need=rule.dwell_sec)
            return []
        else:
            self._trace_append(ts, "no_zone_hit", rule, track_id)
            m.loiter_zones.pop(rid, None)
            m.loiter_zones.pop("_fired_" + rid, None)
            return []

    def _eval_object_left(self, rule, track_id, label, bbox, center, ts, m, tracks=()):
        rid = rule.rule_id
        inside = self._zone_hit(rule.zone, bbox)
        attended = (getattr(rule, "require_unattended", True)
                    and self._has_attached_owner(bbox, track_id, tracks))
        if inside and attended:
            # R3.4: a bag/package with its owner attached is not abandoned —
            # clear any pending dwell so the clock restarts if they walk off.
            self._trace_append(ts, "attended_owner", rule, track_id)
            m.loiter_zones.pop(rid, None)
            m.loiter_zones.pop("_left_fired_" + rid, None)
            return []
        if inside:
            if rid not in m.loiter_zones:
                m.loiter_zones[rid] = ts
            dwell = (ts - m.loiter_zones[rid]).total_seconds()
            if (dwell >= rule.stationary_sec
                    and m.loiter_zones.get("_left_fired_" + rid) is not True):
                key = (rid, track_id)
                if not self._cooldown_ok(key, ts, getattr(rule, "cooldown_sec", 0.0)):
                    self._trace_append(ts, "cooldown_blocked", rule, track_id)
                    return []  # cooldown active: _left_fired_ left unset so a later visit can fire
                m.loiter_zones["_left_fired_" + rid] = True
                self._mark_fire(key, ts)
                self._trace_append(ts, "fired", rule, track_id, dwell=round(dwell, 2))
                return [AnalyticEvent(rid, EVENT_OBJECT_LEFT, self.camera_id, track_id, label,
                                      bbox, ts, detail={"stationary_sec": round(dwell, 2)})]
            self._trace_append(ts, "stationary_warming" if dwell < rule.stationary_sec
                               else "already_fired", rule, track_id,
                               dwell=round(dwell, 2), need=rule.stationary_sec)
        else:
            self._trace_append(ts, "no_zone_hit", rule, track_id)
            if m.loiter_zones.get("_left_fired_" + rid) is True and label != "person":
                m.loiter_zones.pop("_left_fired_" + rid, None)
                self._trace_append(ts, "fired_removed", rule, track_id)
                return [AnalyticEvent(rid, EVENT_OBJECT_REMOVED, self.camera_id,
                                      track_id, label, bbox, ts)]
            m.loiter_zones.pop(rid, None)
            m.loiter_zones.pop("_left_fired_" + rid, None)
        return []

    def _eval_stopped(self, rule, track_id, label, bbox, center, ts, m):
        """R3.4 stopped vehicle: ~0 speed for >= stopped_sec inside a no-stopping
        zone. Movement (or leaving the zone) re-arms both the timer and the
        fire, so a vehicle that stops again can alert again (cooldown applies)."""
        rid = rule.rule_id
        inside = self._zone_hit(rule.zone, bbox)
        if not inside:
            self._trace_append(ts, "no_zone_hit", rule, track_id)
            m.stopped_zones.pop(rid, None)
            m.stopped_zones.pop("_fired_" + rid, None)
            return []
        speed = self._trajectory_speed(m)
        if speed > rule.max_speed:
            self._trace_append(ts, "moving", rule, track_id, speed=round(speed, 4))
            m.stopped_zones.pop(rid, None)
            m.stopped_zones.pop("_fired_" + rid, None)
            return []
        if rid not in m.stopped_zones:
            m.stopped_zones[rid] = ts
        dwell = (ts - m.stopped_zones[rid]).total_seconds()
        if dwell < rule.stopped_sec:
            self._trace_append(ts, "stopped_warming", rule, track_id,
                               dwell=round(dwell, 2), need=rule.stopped_sec)
            return []
        if m.stopped_zones.get("_fired_" + rid) is True:
            self._trace_append(ts, "already_fired", rule, track_id)
            return []
        key = (rid, track_id)
        if not self._cooldown_ok(key, ts, getattr(rule, "cooldown_sec", 0.0)):
            self._trace_append(ts, "cooldown_blocked", rule, track_id)
            return []
        m.stopped_zones["_fired_" + rid] = True
        self._mark_fire(key, ts)
        self._trace_append(ts, "fired", rule, track_id, dwell=round(dwell, 2),
                           speed=round(speed, 4))
        return [AnalyticEvent(rid, EVENT_STOPPED_VEHICLE, self.camera_id, track_id, label, bbox,
                              ts, detail={"stopped_sec": round(dwell, 2),
                                          "speed": round(speed, 4)})]

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
                    self._trace_append(ts, "min_size_skipped", rule, track_id,
                                       area=round(bbox[2] * bbox[3], 4), need=rule.min_size)
                    continue  # grammar v1 min_size: ignore tracks below the area floor
                if self._zone_hit(rule.zone, bbox):
                    count += 1
            fired = self._crowd_fired.get(rule.rule_id, False)
            if count >= rule.threshold and self._trace is not None:
                if fired:
                    self._trace_append(ts, "already_fired", rule, "", count=count)
                elif not self._cooldown_ok(rule.rule_id, ts, getattr(rule, "cooldown_sec", 0.0)):
                    self._trace_append(ts, "cooldown_blocked", rule, "", count=count)
            if (count >= rule.threshold and not fired
                    and self._cooldown_ok(rule.rule_id, ts, getattr(rule, "cooldown_sec", 0.0))):
                self._crowd_fired[rule.rule_id] = True
                self._mark_fire(rule.rule_id, ts)
                self._trace_append(ts, "fired", rule, "", count=count)
                rep = max((t for t in tracks if self._matches(rule.labels, t[1])),
                          key=lambda t: t[2][2] * t[2][3])[2] if tracks else (0, 0, 0, 0)
                out.append(AnalyticEvent(rule.rule_id, EVENT_CROWD, self.camera_id, "",
                                         "person", rep, ts,
                                         score=float(count), detail={"count": count}))
            elif count < rule.threshold:
                self._crowd_fired[rule.rule_id] = False
                self._trace_append(ts, "count_below", rule, "", count=count, need=rule.threshold)
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
                                     cooldown_sec=cooldown, min_size=min_size,
                                     id_switch_grace_sec=spec.get("id_switch_grace_sec", 0.0))
        if rtype == "loitering":
            return LoiteringRule(rid, zone, camera_id, dwell_sec=spec.get("dwell_sec", 30.0),
                                 labels=labels or ("person",),
                                 cooldown_sec=cooldown, min_size=min_size,
                                 id_switch_grace_sec=spec.get("id_switch_grace_sec", 0.0))
        return ObjectLeftRule(rid, zone, camera_id, stationary_sec=spec.get("stationary_sec", 30.0),
                              labels=labels or ("bag", "package"),
                              cooldown_sec=cooldown, min_size=min_size,
                              id_switch_grace_sec=spec.get("id_switch_grace_sec", 0.0),
                              require_unattended=spec.get("require_unattended", True))
    if rtype == "crowd":
        return CrowdCountRule(rid, [tuple(p) for p in spec["zone"]], camera_id,
                              threshold=spec.get("threshold", 10), labels=labels or ("person",),
                              cooldown_sec=cooldown, min_size=min_size)
    if rtype == "stopped_vehicle":
        return StoppedVehicleRule(rid, [tuple(p) for p in spec["zone"]], camera_id,
                                  stopped_sec=spec.get("stopped_sec", 30.0),
                                  max_speed=spec.get("max_speed", 0.02),
                                  cooldown_sec=cooldown, min_size=min_size,
                                  id_switch_grace_sec=spec.get("id_switch_grace_sec", 0.0),
                                  labels=labels or ("vehicle", "truck", "bus",
                                                    "motorcycle", "bicycle"))
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
