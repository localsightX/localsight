"""R4.1 gate-access lane API: lane CRUD, whitelist enrollment, SSRF gate on the
barrier destination, RBAC, and the no-plaintext-plate invariant.

The worker decision path is covered by tests/test_gate_access.py; this suite
covers the operator-facing config surface that arms it. The load-bearing
assertions: (1) a barrier destination that would be an SSRF primitive is
rejected at write time and never persisted, (2) a plaintext plate never reaches
any persisted column, and (3) an enrolled plate matches the token the worker
joins against by construction.
"""
import pytest
from sqlalchemy import select

from packages.domain.models import (
    PIPELINE_FLAG_LANE_ACCESS,
    AuditLog,
    Camera,
    Lane,
    LaneWhitelistEntry,
)


@pytest.fixture()
def rt(app):
    return app.state.runtime


def _admin(client):
    r = client.post("/api/auth/login",
                    json={"email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _viewer(client):
    client.post("/api/users", json={"email": "lane-viewer@test.com",
                                    "password": "ViewerPw12345", "role": "VIEWER"},
                headers=_admin(client))
    r = client.post("/api/auth/login",
                    json={"email": "lane-viewer@test.com", "password": "ViewerPw12345"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _camera(client, h, name="gate-cam"):
    r = client.post("/api/cameras", json={"name": name}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()["id"]


# An allowlisted host (conftest sets SSRF_ALLOWLIST=192.168.99.0/24) and a
# blocked one (loopback is never permitted without an explicit allowlist).
_OK_WEBHOOK = "http://192.168.99.7:9000/barrier/open"
_LOOPBACK_WEBHOOK = "http://127.0.0.1:9000/barrier/open"


def _arm_lane(client, h, cam_id, **over):
    body = {
        "name": "front gate",
        "barrier_channel": "webhook",
        "barrier_config": {"url": _OK_WEBHOOK, "method": "POST"},
        "cooldown_sec": 30,
        "enabled": True,
    }
    body.update(over)
    return client.put(f"/api/cameras/{cam_id}/lane", json=body, headers=h)


# ── lane lifecycle ────────────────────────────────────────────────────────────

def test_put_lane_creates_and_arms_the_camera_flag(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    r = _arm_lane(client, h, cam_id)
    assert r.status_code == 200, r.text
    lane = r.json()
    assert lane["camera_id"] == cam_id
    assert lane["enabled"] is True
    assert lane["barrier_configured"] is True
    # The relay destination is never echoed — only that one is configured.
    assert "barrier_config" not in lane
    assert _OK_WEBHOOK not in r.text

    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        assert cam.pipeline_flags[PIPELINE_FLAG_LANE_ACCESS] is True
        row = s.execute(select(Lane).where(Lane.camera_id == cam_id)).scalar_one()
        # The stored config is envelope ciphertext, not the plaintext URL.
        assert _OK_WEBHOOK not in row.barrier_config_enc
        assert rt.crypto.decrypt_json(row.barrier_config_enc)["url"] == _OK_WEBHOOK
        assert row.armed_by is not None


def test_put_lane_is_idempotent_replace_per_camera(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    _arm_lane(client, h, cam_id, name="first")
    r = _arm_lane(client, h, cam_id, name="second", cooldown_sec=45)
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "second"
    with rt.SessionLocal() as s:
        lanes = s.execute(select(Lane).where(Lane.camera_id == cam_id)).scalars().all()
        assert len(lanes) == 1
        assert s.get(Camera, cam_id).pipeline_flags[PIPELINE_FLAG_LANE_ACCESS] is True


def test_disarming_clears_the_flag_and_delete_removes_the_lane(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    assert _arm_lane(client, h, cam_id, enabled=False).status_code == 200
    with rt.SessionLocal() as s:
        assert s.get(Camera, cam_id).pipeline_flags.get(PIPELINE_FLAG_LANE_ACCESS) is False

    # Re-arm, enroll, then delete — the whitelist cascades away with the lane.
    _arm_lane(client, h, cam_id)
    client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                json={"plate": "AB12CDE", "label": "delivery van"}, headers=h)
    r = client.delete(f"/api/cameras/{cam_id}/lane", headers=h)
    assert r.status_code == 200, r.text
    assert client.get(f"/api/cameras/{cam_id}/lane", headers=h).status_code == 404
    with rt.SessionLocal() as s:
        cam = s.get(Camera, cam_id)
        assert PIPELINE_FLAG_LANE_ACCESS not in (cam.pipeline_flags or {})
        assert s.execute(select(Lane)).scalars().first() is None
        assert s.execute(select(LaneWhitelistEntry)).scalars().first() is None


def test_get_lane_lists_whitelist_and_404s_when_not_a_lane(client):
    h = _admin(client)
    cam_id = _camera(client, h)
    assert client.get(f"/api/cameras/{cam_id}/lane", headers=h).status_code == 404
    assert client.get("/api/cameras/nope/lane", headers=h).status_code == 404
    _arm_lane(client, h, cam_id)
    client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                json={"plate": "ab12cde", "label": "delivery van"}, headers=h)
    r = client.get(f"/api/cameras/{cam_id}/lane", headers=h)
    assert r.status_code == 200, r.text
    assert len(r.json()["whitelist"]) == 1


# ── SSRF gate on the barrier destination ──────────────────────────────────────

def test_loopback_barrier_destination_is_rejected_and_not_persisted(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    r = _arm_lane(client, h, cam_id,
                  barrier_config={"url": _LOOPBACK_WEBHOOK, "method": "POST"})
    assert r.status_code == 400, r.text
    # Fail BEFORE persist: no half-armed lane is left behind.
    with rt.SessionLocal() as s:
        assert s.execute(select(Lane)).scalars().first() is None
        assert PIPELINE_FLAG_LANE_ACCESS not in (s.get(Camera, cam_id).pipeline_flags or {})


def test_mqtt_barrier_destination_is_validated_like_alert_routes(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    # Private-range broker is refused without an explicit allowlist.
    r = _arm_lane(client, h, cam_id, barrier_channel="mqtt",
                  barrier_config={"host": "10.0.0.9", "port": 1883, "topic": "gate/open"})
    assert r.status_code == 400, r.text
    # A missing host is a 400, not a silent lane that can never fire.
    r = _arm_lane(client, h, cam_id, barrier_channel="mqtt",
                  barrier_config={"port": 1883})
    assert r.status_code == 400, r.text
    # Allowlisted broker is accepted and stored as ciphertext.
    r = _arm_lane(client, h, cam_id, barrier_channel="mqtt",
                  barrier_config={"host": "192.168.99.7", "port": 1883,
                                  "topic": "gate/open", "username": "u", "password": "p"})
    assert r.status_code == 200, r.text
    with rt.SessionLocal() as s:
        row = s.execute(select(Lane).where(Lane.camera_id == cam_id)).scalar_one()
        assert "192.168.99.7" not in row.barrier_config_enc
        assert rt.crypto.decrypt_json(row.barrier_config_enc)["password"] == "p"


def test_unknown_barrier_channel_is_rejected(client):
    h = _admin(client)
    cam_id = _camera(client, h)
    r = _arm_lane(client, h, cam_id, barrier_channel="carrier-pigeon",
                  barrier_config={"url": _OK_WEBHOOK})
    assert r.status_code == 422, r.text  # pydantic pattern


# ── allow-window validation (fail closed at write time) ───────────────────────

@pytest.mark.parametrize("window", [
    {"start": "09:00"},                  # missing end
    {"start": "25:00", "end": "17:00"},  # not HH:MM
    {"start": "09:00", "end": "17:00", "tz": "Nowhere/Plausible"},
    {"start": "09:00", "end": "17:00", "days": [0, 9]},
    {"start": "09:00", "end": "17:00", "days": "weekdays"},
])
def test_malformed_window_is_rejected_not_silently_denying(client, window):
    h = _admin(client)
    cam_id = _camera(client, h)
    r = _arm_lane(client, h, cam_id, allow_window=window)
    assert r.status_code == 400, r.text


def test_non_object_window_is_rejected_by_the_schema(client):
    # Never reaches the validator (pydantic rejects it), but the write still
    # fails closed — a garbage window can never be persisted to deny later.
    h = _admin(client)
    cam_id = _camera(client, h)
    r = _arm_lane(client, h, cam_id, allow_window="not-an-object")
    assert r.status_code == 422, r.text


def test_valid_overnight_window_is_accepted(client):
    h = _admin(client)
    cam_id = _camera(client, h)
    window = {"start": "17:00", "end": "07:00", "days": [1, 2, 3, 4, 5], "tz": "Europe/Berlin"}
    r = _arm_lane(client, h, cam_id, allow_window=window)
    assert r.status_code == 200, r.text
    assert r.json()["allow_window"] == window


# ── whitelist enrollment: token parity with the worker ────────────────────────

def test_enrollment_token_matches_what_the_worker_joins_on(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    _arm_lane(client, h, cam_id)
    r = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                    json={"plate": " ab-12-cd ", "label": "pool car"}, headers=h)
    assert r.status_code == 201, r.text
    body = r.json()
    # Normalized exactly like packages.ai.anpr before hashing.
    assert body["query"]["plate"] == "AB12CD"
    token = body["plate_hash"]
    assert token == rt.crypto.hmac_str("AB12CD")
    # Case/format variants of one plate collapse to a single token, so a plate
    # read by the OCR pipeline matches the enrolled row by construction. The
    # normalization happens in the API/OCR layer — hmac_str itself is
    # case-sensitive, which is exactly why both sides must normalize first
    # (proven end-to-end by the duplicate-enrollment test below).
    assert token != rt.crypto.hmac_str("AB12CE")  # distinct plates stay distinct
    with rt.SessionLocal() as s:
        row = s.execute(select(LaneWhitelistEntry)).scalar_one()
        assert row.plate_hash == token
        assert row.label == "pool car"


def test_enrollment_rejects_duplicate_and_label_as_plate(client):
    h = _admin(client)
    cam_id = _camera(client, h)
    _arm_lane(client, h, cam_id)
    r = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                    json={"plate": "AB12CD", "label": "van"}, headers=h)
    assert r.status_code == 201, r.text
    # Same plate under different casing is still a duplicate (one token).
    r = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                    json={"plate": "ab12cd", "label": "van 2"}, headers=h)
    assert r.status_code == 409, r.text
    # A note that duplicates the plate is a plaintext-plate store with a worse name.
    r = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                    json={"plate": "XY99ZZ", "label": "XY-99-ZZ pool"}, headers=h)
    assert r.status_code == 400, r.text
    # A plate that normalizes to nothing can never match a sighting.
    r = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                    json={"plate": "---", "label": "nonsense"}, headers=h)
    assert r.status_code == 400, r.text


def test_revoke_takes_effect_immediately(client):
    h = _admin(client)
    cam_id = _camera(client, h)
    _arm_lane(client, h, cam_id)
    entry_id = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                           json={"plate": "AB12CD", "label": "temp pass"},
                           headers=h).json()["id"]
    r = client.delete(f"/api/lanes/whitelist/{entry_id}", headers=h)
    assert r.status_code == 200, r.text
    assert client.delete(f"/api/lanes/whitelist/{entry_id}", headers=h).status_code == 404
    # The worker joins the whitelist per read, so deletion is instant denial.


def test_enrollment_404s_without_a_lane(client):
    h = _admin(client)
    cam_id = _camera(client, h)
    r = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                    json={"plate": "AB12CD", "label": "x"}, headers=h)
    assert r.status_code == 404, r.text


# ── the privacy invariant: no plaintext plate anywhere persisted ──────────────

def test_no_plaintext_plate_is_ever_persisted(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    _arm_lane(client, h, cam_id)
    for plate in ("AB12CD", "ZZ999ZZ"):
        r = client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                        json={"plate": plate, "label": "note"}, headers=h)
        assert r.status_code == 201, r.text
        assert plate in r.text  # the query echo is the operator's own input
    with rt.SessionLocal() as s:
        rows = s.execute(select(LaneWhitelistEntry)).scalars().all()
        audits = s.execute(select(AuditLog)).scalars().all()
    for row in rows:
        assert "AB12CD" not in (row.plate_hash + row.label)
    for a in audits:
        if not a.detail:
            continue
        blob = f"{a.action}{a.resource}{a.detail}"
        assert "AB12CD" not in blob and "ZZ999ZZ" not in blob
        if a.action.startswith("lane.whitelist"):
            assert a.detail.get("plate_hash")  # the hash, never the plate


# ── RBAC ──────────────────────────────────────────────────────────────────────

def test_viewer_can_neither_read_nor_configure_lanes(client):
    h = _admin(client)
    v = _viewer(client)
    cam_id = _camera(client, h)
    # VIEWER holds neither lanes:view nor lanes:manage.
    assert client.get(f"/api/cameras/{cam_id}/lane", headers=v).status_code == 403
    assert _arm_lane(client, v, cam_id).status_code == 403
    assert client.post(f"/api/cameras/{cam_id}/lane/whitelist",
                       json={"plate": "AB12CD"}, headers=v).status_code == 403
    _arm_lane(client, h, cam_id)
    assert client.get(f"/api/cameras/{cam_id}/lane/whitelist", headers=v).status_code == 403
    assert client.delete(f"/api/cameras/{cam_id}/lane", headers=v).status_code == 403


def test_lane_arm_is_audited_without_relay_secrets(rt, client):
    h = _admin(client)
    cam_id = _camera(client, h)
    _arm_lane(client, h, cam_id)
    with rt.SessionLocal() as s:
        arm = s.execute(select(AuditLog).where(AuditLog.action == "lane.arm")).scalar_one()
    assert arm.resource.startswith("lanes/")
    assert _OK_WEBHOOK not in str(arm.detail)

