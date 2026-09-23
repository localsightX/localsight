"""R4.1 gate-access event path: plate read → whitelist join → allow window →
barrier command.

Covers the wiring the roadmap acceptance criteria depend on: a whitelisted plate
inside its allow window opens the barrier exactly once (per-plate cooldown),
every other outcome is recorded as an event and never reaches the relay, and
plate material (ciphertext or digest) never leaves the host in the command
payload. The pure decision is exercised with detached ORM objects; the worker
path is exercised against the test DB with an injectable barrier sender so no
network is touched.
"""
from __future__ import annotations

import datetime as dt

from apps.worker import main as worker_main
from packages.domain.lane import (
    DECISION_BARRIER_UNAVAILABLE,
    DECISION_GRANTED,
    DECISION_LANE_DISABLED,
    DECISION_NOT_WHITELISTED,
    DECISION_OUTSIDE_WINDOW,
    decide_gate_access,
)
from packages.domain.models import (
    PIPELINE_FLAG_LANE_ACCESS,
    AuditLog,
    Camera,
    Event,
    Lane,
    LaneWhitelistEntry,
)
from packages.notify import build_notifier

_TUE_MORNING = dt.datetime(2026, 9, 22, 9, 30, tzinfo=dt.UTC)  # Tue 09:30 UTC
_TUE_EVENING = dt.datetime(2026, 9, 22, 18, 0, tzinfo=dt.UTC)  # Tue 18:00 UTC


def _lane(**kw) -> Lane:
    base = {"camera_id": "cam-1", "name": "main gate", "barrier_channel": "webhook",
            "allow_window": None, "cooldown_sec": 30, "enabled": True}
    base.update(kw)
    return Lane(**base)


def _entry(**kw) -> LaneWhitelistEntry:
    base = {"plate_hash": "token-abc", "label": "delivery van",
            "allow_window": None, "enabled": True}
    base.update(kw)
    return LaneWhitelistEntry(**base)


# ── pure decision: deny-by-default, strictest check first ─────────────────────


def test_decide_grants_whitelisted_plate_in_window():
    d = decide_gate_access(_lane(), "token-abc", _entry(), _TUE_MORNING)
    assert d.granted is True
    assert d.reason == DECISION_GRANTED
    assert d.entry_label == "delivery van"
    assert d.plate_hash == "token-abc"


def test_decide_denies_when_lane_disabled():
    d = decide_gate_access(_lane(enabled=False), "token-abc", _entry(), _TUE_MORNING)
    assert d.granted is False
    assert d.reason == DECISION_LANE_DISABLED


def test_decide_denies_unknown_plate():
    d = decide_gate_access(_lane(), "token-abc", None, _TUE_MORNING)
    assert d.granted is False
    assert d.reason == DECISION_NOT_WHITELISTED


def test_decide_denies_disabled_entry():
    d = decide_gate_access(_lane(), "token-abc", _entry(enabled=False), _TUE_MORNING)
    assert d.granted is False
    assert d.reason == DECISION_NOT_WHITELISTED


def test_decide_denies_outside_window():
    lane = _lane(allow_window={"start": "09:00", "end": "17:00"})
    d = decide_gate_access(lane, "token-abc", _entry(), _TUE_EVENING)
    assert d.granted is False
    assert d.reason == DECISION_OUTSIDE_WINDOW


def test_decide_entry_window_overrides_lane_window():
    # The lane is 24/7 but the entry is only valid 09:00-17:00.
    entry = _entry(allow_window={"start": "09:00", "end": "17:00"})
    assert decide_gate_access(_lane(), "t", entry, _TUE_MORNING).granted is True
    assert decide_gate_access(_lane(), "t", entry, _TUE_EVENING).granted is False
    # An entry without its own window inherits the lane window.
    lane = _lane(allow_window={"start": "09:00", "end": "17:00"})
    assert decide_gate_access(lane, "t", _entry(), _TUE_MORNING).granted is True
    assert decide_gate_access(lane, "t", _entry(), _TUE_EVENING).granted is False


def test_decide_malformed_entry_window_denies():
    d = decide_gate_access(_lane(), "t", _entry(allow_window={}), _TUE_MORNING)
    assert d.granted is False
    assert d.reason == DECISION_OUTSIDE_WINDOW


def test_decide_default_tz_honours_camera_timezone():
    # 09:00-17:00 Berlin = 07:00-15:00 UTC, so 09:30 UTC is inside; 16:00 UTC
    # (18:00 local) is outside — same window, decided by the camera's tz.
    lane = _lane(allow_window={"start": "09:00", "end": "17:00"})
    assert decide_gate_access(lane, "t", _entry(), _TUE_MORNING,
                              default_tz="Europe/Berlin").granted is True
    assert decide_gate_access(lane, "t", _entry(), _TUE_EVENING,
                              default_tz="Europe/Berlin").granted is False


# ── cooldown: one command per vehicle passage ─────────────────────────────────


def test_gate_cooldown_suppresses_repeat_then_releases():
    cd = worker_main.GateCooldown()
    key = ("lane-1", "token-abc")
    assert cd.is_suppressed(key, _TUE_MORNING, 30) is False
    cd.record(key, _TUE_MORNING)
    assert cd.is_suppressed(key, _TUE_MORNING + dt.timedelta(seconds=10), 30) is True
    # Exactly at the window boundary the plate can open again.
    assert cd.is_suppressed(key, _TUE_MORNING + dt.timedelta(seconds=30), 30) is False


def test_gate_cooldown_zero_never_suppresses():
    cd = worker_main.GateCooldown()
    key = ("lane-1", "token-abc")
    cd.record(key, _TUE_MORNING)
    assert cd.is_suppressed(key, _TUE_MORNING, 0) is False


# ── worker path: flag → lane → join → window → barrier ────────────────────────


def _setup(client, *, lane_kw=None, entry_plate="AB12CDE", entry_kw=None,
           barrier_channel="webhook", barrier_cfg=None, create_lane=True,
           create_entry=True, flags=None):
    """Arm a camera as a lane with one whitelisted plate. Returns ids only —
    callers load ORM objects inside their own session (the setup session is
    closed, so returned objects would be detached)."""
    rt = client.app.state.runtime
    with rt.SessionLocal() as s:
        cam = Camera(
            name="gate-cam", timezone="UTC",
            pipeline_flags=flags if flags is not None else {PIPELINE_FLAG_LANE_ACCESS: True},
        )
        s.add(cam)
        s.commit()
        s.refresh(cam)
        lane_id = entry_id = None
        if create_lane:
            lane_kw_ = {"cooldown_sec": 30}
            lane_kw_.update(lane_kw or {})
            lane = Lane(
                camera_id=cam.id, name="main gate", armed_by="operator-1",
                barrier_channel=barrier_channel,
                barrier_config_enc=rt.crypto.encrypt_json(barrier_cfg) if barrier_cfg else None,
                **lane_kw_,
            )
            s.add(lane)
            s.commit()
            s.refresh(lane)
            lane_id = lane.id
            if create_entry:
                entry = LaneWhitelistEntry(
                    lane_id=lane.id, plate_hash=rt.crypto.hmac_str(entry_plate),
                    label="delivery van", **(entry_kw or {}),
                )
                s.add(entry)
                s.commit()
                s.refresh(entry)
                entry_id = entry.id
        cam_id = cam.id  # capture before the session closes (attrs expire on commit)
    return rt, cam_id, lane_id, entry_id


def _anpr_event(camera_id, plate_hash, ts, track_id="t-1") -> Event:
    return Event(
        camera_id=camera_id, track_id=track_id, event_type="anpr",
        identity_status="unknown", timestamp_start=ts, timestamp_end=ts,
        confidence=0.9, bbox={"x": 0.1, "y": 0.1, "w": 0.3, "h": 0.1},
        detail={"plate_enc": "gAAAAA.encrypted", "plate_hash": plate_hash},
    )


def _capturing_sender(record: list):
    def send(rt, lane, camera, ev, detail):
        record.append({"lane": lane.id, "camera": camera.id, "event": ev.id,
                       "detail": detail})
        return True
    return send


def test_evaluate_noop_when_flag_off(client):
    rt, cam_id, _lane_id, _entry_id = _setup(client, flags={})
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, rt.crypto.hmac_str("AB12CDE"), _TUE_MORNING)
        s.add(ev)
        s.flush()
        sent: list = []
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev],
                                               send_barrier=_capturing_sender(sent))
        s.commit()
    assert out == []
    assert sent == []
    with rt.SessionLocal() as s:
        assert s.query(Event).filter(
            Event.event_type.in_(("gate_open", "gate_deny"))).count() == 0


def test_evaluate_noop_when_camera_has_no_lane(client):
    rt, cam_id, _lane_id, _entry_id = _setup(client, create_lane=False)
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, rt.crypto.hmac_str("AB12CDE"), _TUE_MORNING)
        s.add(ev)
        s.flush()
        sent: list = []
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev],
                                               send_barrier=_capturing_sender(sent))
        s.commit()
    assert out == []
    assert sent == []


def test_evaluate_grant_opens_barrier_and_records(client):
    rt, cam_id, _lane_id, _entry_id = _setup(
        client, barrier_cfg={"url": "http://192.168.99.10/open"})
    sent: list = []
    ph = rt.crypto.hmac_str("AB12CDE")
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, ph, _TUE_MORNING)
        s.add(ev)
        s.flush()
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev],
                                               send_barrier=_capturing_sender(sent))
        s.commit()
    assert len(out) == 1 and out[0].granted is True
    assert len(sent) == 1
    # The command payload carries no plate material to the relay.
    assert "plate_enc" not in sent[0]["detail"]
    assert "plate_hash" not in sent[0]["detail"]
    assert sent[0]["detail"]["command"] == "open"
    with rt.SessionLocal() as s:
        open_ev = s.query(Event).filter(Event.event_type == "gate_open").one()
        assert open_ev.detail["plate_hash"] == ph
        assert open_ev.detail["reason"] == DECISION_GRANTED
        assert open_ev.detail["entry_label"] == "delivery van"
        audit = s.query(AuditLog).filter(AuditLog.action == "gate_open").one()
        assert audit.result == "success"
        assert audit.detail["plate_hash"] == ph
        assert audit.username == "operator-1"  # who armed the lane, never the plate


def test_evaluate_unknown_plate_denies_without_barrier(client):
    rt, cam_id, _lane_id, _entry_id = _setup(client)
    sent: list = []
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, rt.crypto.hmac_str("ZZ999ZZ"), _TUE_MORNING)
        s.add(ev)
        s.flush()
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev],
                                               send_barrier=_capturing_sender(sent))
        s.commit()
    assert len(out) == 1 and out[0].granted is False
    assert out[0].reason == DECISION_NOT_WHITELISTED
    assert sent == []
    with rt.SessionLocal() as s:
        deny = s.query(Event).filter(Event.event_type == "gate_deny").one()
        assert deny.detail["reason"] == DECISION_NOT_WHITELISTED
        audit = s.query(AuditLog).filter(AuditLog.action == "gate_deny").one()
        assert audit.result == "failure"


def test_evaluate_outside_window_denies(client):
    rt, cam_id, _lane_id, _entry_id = _setup(
        client, lane_kw={"allow_window": {"start": "09:00", "end": "17:00"}})
    sent: list = []
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, rt.crypto.hmac_str("AB12CDE"), _TUE_EVENING)
        s.add(ev)
        s.flush()
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev],
                                               send_barrier=_capturing_sender(sent),
                                               now=_TUE_EVENING)
        s.commit()
    assert out[0].granted is False and out[0].reason == DECISION_OUTSIDE_WINDOW
    assert sent == []
    with rt.SessionLocal() as s:
        deny = s.query(Event).filter(Event.event_type == "gate_deny").one()
        assert deny.detail["reason"] == DECISION_OUTSIDE_WINDOW


def test_evaluate_disabled_lane_is_denied_and_recorded(client):
    rt, cam_id, _lane_id, _entry_id = _setup(client, lane_kw={"enabled": False})
    sent: list = []
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, rt.crypto.hmac_str("AB12CDE"), _TUE_MORNING)
        s.add(ev)
        s.flush()
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev],
                                               send_barrier=_capturing_sender(sent))
        s.commit()
    # A disarmed lane denies (operator-visible) rather than silently passing.
    assert out[0].granted is False and out[0].reason == DECISION_LANE_DISABLED
    assert sent == []
    with rt.SessionLocal() as s:
        deny = s.query(Event).filter(Event.event_type == "gate_deny").one()
        assert deny.detail["reason"] == DECISION_LANE_DISABLED


def test_evaluate_cooldown_suppresses_second_command(client):
    rt, cam_id, _lane_id, _entry_id = _setup(client, lane_kw={"cooldown_sec": 300})
    cd = worker_main.GateCooldown()
    sent: list = []
    ph = rt.crypto.hmac_str("AB12CDE")
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev1 = _anpr_event(cam.id, ph, _TUE_MORNING, track_id="t-1")
        ev2 = _anpr_event(cam.id, ph, _TUE_MORNING + dt.timedelta(seconds=60), track_id="t-2")
        s.add_all([ev1, ev2])
        s.flush()
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev1, ev2],
                                               send_barrier=_capturing_sender(sent),
                                               cooldown=cd)
        s.commit()
    # First read opens; the repeat inside 300 s is suppressed.
    assert len(sent) == 1
    assert [d.granted for d in out] == [True, True]
    with rt.SessionLocal() as s:
        # One recorded open; the suppressed repeat writes no row of its own.
        assert s.query(Event).filter(Event.event_type == "gate_open").count() == 1


def test_evaluate_relay_failure_records_and_does_not_consume_cooldown(client):
    rt, cam_id, lane_id, _entry_id = _setup(client)
    cd = worker_main.GateCooldown()
    ph = rt.crypto.hmac_str("AB12CDE")
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        ev1 = _anpr_event(cam.id, ph, _TUE_MORNING, track_id="t-1")
        ev2 = _anpr_event(cam.id, ph, _TUE_MORNING + dt.timedelta(seconds=60), track_id="t-2")
        s.add_all([ev1, ev2])
        s.flush()
        out = worker_main.evaluate_lane_access(s, rt, cam, [ev1, ev2],
                                               send_barrier=lambda *a, **k: False,
                                               cooldown=cd)
        s.commit()
    # Policy granted both, but the relay could not be commanded: both attempts
    # are recorded as failed opens and the cooldown is NOT consumed, so the
    # second read was still attempted instead of being suppressed.
    assert [d.granted for d in out] == [True, True]
    with rt.SessionLocal() as s:
        rows = s.query(Event).filter(Event.event_type == "gate_open").all()
        assert len(rows) == 2
        assert all(r.detail["reason"] == DECISION_BARRIER_UNAVAILABLE for r in rows)
        audits = s.query(AuditLog).filter(AuditLog.action == "gate_open").all()
        assert all(a.result == "failure" for a in audits)
    assert cd.is_suppressed((lane_id, ph), _TUE_MORNING + dt.timedelta(seconds=60), 30) is False


# ── relay dispatch: SSRF re-validation + encrypted config handling ────────────


def test_send_barrier_dispatches_over_mqtt_offline(client):
    published: list = []
    rt, cam_id, lane_id, _entry_id = _setup(
        client, barrier_channel="mqtt",
        barrier_cfg={"host": "192.168.99.10", "port": 1883,
                     "topic": "localsight/barrier/{camera_id}"})

    def build(channel, cfg, allowlist):
        # The publish hook is a runtime injection (functions are not
        # JSON-serializable, so it cannot live in the encrypted envelope).
        def publish(topic, payload, qos, retain):
            published.append((topic, payload))
        return build_notifier(channel, {**cfg, "_publish": publish})

    with rt.SessionLocal() as s:
        lane = s.get(Lane, lane_id)
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, "tok", _TUE_MORNING)
        s.add(ev)
        s.flush()
        ok = worker_main._send_barrier_command(rt, lane, cam, ev, {"command": "open"},
                                               build=build)
    assert ok is True
    assert len(published) == 1
    topic, payload = published[0]
    assert topic == f"localsight/barrier/{cam_id}"
    # No plate material in the outbound payload.
    assert "plate_enc" not in payload and "plate_hash" not in payload


def test_send_barrier_rejects_loopback_webhook(client):
    # The conftest SSRF allowlist is 192.168.99.0/24, so loopback is refused at
    # send time — defense in depth on top of the create-time validation (part 3).
    rt, cam_id, lane_id, _entry_id = _setup(
        client, barrier_cfg={"url": "http://127.0.0.1:9999/open"})
    with rt.SessionLocal() as s:
        lane = s.get(Lane, lane_id)
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, "tok", _TUE_MORNING)
        s.add(ev)
        s.flush()
        ok = worker_main._send_barrier_command(rt, lane, cam, ev, {"command": "open"})
    assert ok is False


def test_send_barrier_missing_config_denies(client):
    rt, cam_id, lane_id, _entry_id = _setup(client, barrier_cfg=None)
    with rt.SessionLocal() as s:
        lane = s.get(Lane, lane_id)
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, "tok", _TUE_MORNING)
        s.add(ev)
        s.flush()
        ok = worker_main._send_barrier_command(rt, lane, cam, ev, {"command": "open"})
    assert ok is False


def test_send_barrier_undecryptable_config_denies(client):
    rt, cam_id, lane_id, _entry_id = _setup(client, barrier_cfg=None)
    with rt.SessionLocal() as s:
        lane = s.get(Lane, lane_id)
        lane.barrier_config_enc = "not-a-valid-envelope"
        cam = s.get(Camera, cam_id)
        ev = _anpr_event(cam.id, "tok", _TUE_MORNING)
        s.add(ev)
        s.flush()
        ok = worker_main._send_barrier_command(rt, lane, cam, ev, {"command": "open"})
    assert ok is False
