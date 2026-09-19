"""API behavior tests: events search/pagination, timeline, audit, MFA, and secure
media delivery via signed URLs.
"""
from __future__ import annotations

import datetime as dt
import urllib.parse

from packages.domain.models import Event
from packages.security.mfa import current_code


def _admin(client):
    r = client.post("/api/auth/login", json={"email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_event(client, cam_id, identity_status="unknown", minutes_ago=10, label=None):
    rt = client.app.state.runtime
    with rt.SessionLocal() as s:
        start = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=minutes_ago)
        ev = Event(
            camera_id=cam_id, track_id="t1", identity_id=None, identity_status=identity_status,
            event_type="presence", timestamp_start=start,
            timestamp_end=start + dt.timedelta(minutes=2), confidence=0.9,
            bbox={"x": 0.1, "y": 0.1, "w": 0.1, "h": 0.1},
        )
        s.add(ev)
        s.commit()
        return ev.id


def test_events_pagination_and_filter(client, admin_auth):
    r = client.post("/api/cameras", json={"name": "cam-e"}, headers=admin_auth)
    cam_id = r.json()["id"]
    for _ in range(3):
        _make_event(client, cam_id)

    # total
    res = client.get("/api/events", headers=admin_auth)
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 3
    # pagination
    paged = client.get("/api/events?limit=2&offset=0", headers=admin_auth).json()
    assert len(paged["items"]) == 2
    # filter by camera
    by_cam = client.get(f"/api/events?camera_id={cam_id}", headers=admin_auth).json()
    assert by_cam["total"] >= 3
    assert all(i["camera_id"] == cam_id for i in by_cam["items"])


def test_timeline_groups_events(client, admin_auth):
    r = client.post("/api/cameras", json={"name": "cam-t"}, headers=admin_auth)
    cam_id = r.json()["id"]
    _make_event(client, cam_id)
    # Query by the event's own UTC day, not `now`: near the UTC midnight
    # boundary the event (10 min ago) lands on yesterday's date and a
    # "today" query finds nothing (observed flake at 23:59 UTC).
    day = (dt.datetime.now(dt.UTC) - dt.timedelta(minutes=10)).strftime("%Y-%m-%d")
    res = client.get(f"/api/timeline?date={day}&camera_id={cam_id}", headers=admin_auth)
    assert res.status_code == 200
    assert len(res.json()["timeline"]) >= 1


def test_audit_logged_and_queryable(client, admin_auth):
    # admin_auth already triggered a login audit entry
    res = client.get("/api/audit?action=login", headers=admin_auth)
    assert res.status_code == 200
    assert res.json()["total"] >= 1


def test_mfa_enrollment_and_step_up(client):
    auth = _admin(client)
    setup = client.post("/api/auth/mfa/setup", headers=auth)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    code = current_code(secret)
    verify = client.post("/api/auth/mfa/verify", json={"code": code}, headers=auth)
    assert verify.status_code == 200

    # login now requires MFA
    bad = client.post("/api/auth/login", json={"email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    assert bad.status_code == 401
    good = client.post("/api/auth/login", json={"email": "admin@test.com", "password": "Sup3rStr0ngPw!", "mfa_code": code})
    assert good.status_code == 200


def test_signed_video_url_access(client, admin_auth):
    rt = client.app.state.runtime
    r = client.post("/api/cameras", json={"name": "cam-v"}, headers=admin_auth)
    cam_id = r.json()["id"]
    key = f"segments/{cam_id}/clip.mp4"
    rt.storage.put(key, b"fake-video-bytes", "video/mp4")
    enc = rt.crypto.encrypt_str(key)
    with rt.SessionLocal() as s:
        ev = Event(camera_id=cam_id, track_id="t", identity_status="unknown", event_type="presence",
                   timestamp_start=dt.datetime.now(dt.UTC),
                   timestamp_end=dt.datetime.now(dt.UTC) + dt.timedelta(minutes=1),
                   confidence=0.9, bbox={}, video_segment_key_enc=enc)
        s.add(ev)
        s.commit()
        ev_id = ev.id

    detail = client.get(f"/api/events/{ev_id}", headers=admin_auth).json()
    assert detail["video_url"]
    u = urllib.parse.urlparse(detail["video_url"])
    q = urllib.parse.parse_qs(u.query)
    # fetch with valid signature AND a session header
    g = client.get(f"/api/video/{urllib.parse.quote(key, safe='')}?exp={q['exp'][0]}&sig={q['sig'][0]}", headers=admin_auth)
    assert g.status_code == 200
    assert g.content == b"fake-video-bytes"
    # fetch with valid signature and NO Authorization header — this is how
    # <img>/<video> tags consume the link. Regression: the route used to
    # require a Bearer, which media tags cannot send, so every drawer
    # snapshot/clip in the real UI 401'd.
    g2 = client.get(f"/api/video/{urllib.parse.quote(key, safe='')}?exp={q['exp'][0]}&sig={q['sig'][0]}")
    assert g2.status_code == 200
    assert g2.content == b"fake-video-bytes"
    # tampered signature rejected
    bad = client.get(f"/api/video/{urllib.parse.quote(key, safe='')}?exp={q['exp'][0]}&sig=deadbeef", headers=admin_auth)
    assert bad.status_code == 403
    # tampered signature rejected without a session too
    bad2 = client.get(f"/api/video/{urllib.parse.quote(key, safe='')}?exp={q['exp'][0]}&sig=deadbeef")
    assert bad2.status_code == 403


def test_user_management_requires_privilege(client, viewer_auth):
    r = client.post("/api/users", json={"email": "x@y.z", "password": "NewUserPw1234", "role": "VIEWER"}, headers=viewer_auth)
    assert r.status_code == 403


def test_tplink_presets_listed(client, admin_auth):
    res = client.get("/api/cameras/presets", headers=admin_auth)
    assert res.status_code == 200
    vendors = {p["vendor"] for p in res.json()}
    assert {"vigi_camera", "vigi_nvr", "tapo"} <= vendors
    vigi_nvr = next(p for p in res.json() if p["vendor"] == "vigi_nvr")
    assert "live/ch/" in vigi_nvr["main_stream"]
    assert vigi_nvr["onvif_ports"] == [80, 2020]


def test_provision_vigi_nvr_creates_channels(client, admin_auth):
    res = client.post("/api/cameras/from-nvr", json={
        "nvr_ip": "192.168.99.50", "nvr_name": "VIGI NVR", "channel_count": 2,
    }, headers=admin_auth)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["nvr_host"] == "192.168.99.50"
    assert len(body["cameras"]) == 2
    for c in body["cameras"]:
        assert "/live/ch/" in c["main_stream"]
        assert c["sub_stream"].endswith("/stream/2")
    # cameras are listed and linked to the NVR
    cams = client.get("/api/cameras", headers=admin_auth).json()
    assert len([c for c in cams if c["nvr_device_id"] == body["nvr_id"]]) == 2


def test_from_nvr_blocks_metadata_ip(client, admin_auth):
    # SSRF egress guard must reject link-local/metadata destinations.
    res = client.post("/api/cameras/from-nvr", json={
        "nvr_ip": "169.254.169.254", "channel_count": 1,
    }, headers=admin_auth)
    assert res.status_code == 400


def test_system_metrics_with_user_session(client, admin_auth):
    """Regression (UI audit C-11): /api/system/metrics 500'd for every user
    session because get_current_user was called as a plain function — its
    `db` parameter was a Depends() marker, not a Session. The scrape-token
    path masked it from Prometheus, so dashboards hit the 500 directly."""
    res = client.get("/api/system/metrics", headers=admin_auth)
    assert res.status_code == 200, res.text
    assert "text/plain" in res.headers["content-type"]
    # The registry may be empty in tests; a 200 text/plain body is the contract.
    assert res.text is not None


def test_system_metrics_rejects_anonymous(client):
    res = client.get("/api/system/metrics")
    assert res.status_code == 401


def test_dashboard_summary_counts_today_only(client, admin_auth):
    """Regression (UI audit C-9): the dashboard previously faked "events
    today" from /api/events?limit=1 total (= ALL events ever). The summary
    endpoint must count from local midnight and split unknown identities."""
    from datetime import datetime, timedelta

    from packages.domain.models import Camera
    from packages.domain.models import Event as EventModel

    rt = client.app.state.runtime
    s = rt.SessionLocal()
    try:
        cam = s.query(Camera).first()
        if cam is None:
            cam = Camera(id="cam-summary-1", name="Summary Cam", status="ONLINE")
            s.add(cam)
            s.flush()
        now = datetime.now(dt.UTC)
        for i, delta in enumerate((timedelta(minutes=-30), timedelta(hours=-30))):
            s.add(EventModel(
                id=f"ev-sum-{i}", camera_id=cam.id,
                event_type="presence", identity_status="unknown",
                timestamp_start=now + delta, timestamp_end=now + delta + timedelta(seconds=30),
                bbox={"x": 0, "y": 0, "w": 0.1, "h": 0.1}, confidence=0.5,
            ))
        s.commit()
    finally:
        s.close()

    res = client.get("/api/dashboard/summary", headers=admin_auth)
    assert res.status_code == 200, res.text
    body = res.json()
    # today's event counted; yesterday's NOT (the old bug counted all-time)
    assert body["events_today"]["total"] == 1
    assert body["events_today"]["unknown"] == 1
    assert body["cameras"]["total"] >= 1
    assert body["cameras"]["online"] >= 1
    assert isinstance(body["cameras"]["per_camera"], list)
    assert set(body["cameras"]) >= {"online", "degraded", "offline", "per_camera"}


# ── M2: the account story — password, MFA, sessions (E-5/E-6/E-13) ─────────

def test_password_change_flow(client, admin_auth):
    """Rotate own password: old verified, hash rotated, other sessions
    revoked, audit written. The demo rule (never break the admin) is
    respected by rotating BACK at the end."""
    # arrange a second session (another refresh token) to see it revoked
    login = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    assert login.status_code == 200
    other_refresh = login.json()["refresh_token"]

    r = client.post("/api/auth/password", headers=admin_auth, json={
        "old_password": "Sup3rStr0ngPw!", "new_password": "Rotated-Pw-123456!"})
    assert r.status_code == 200, r.text
    assert r.json()["sessions_revoked"] is True

    # old password no longer works; new one does
    assert client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Sup3rStr0ngPw!"}).status_code in (401, 423)
    fresh = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Rotated-Pw-123456!"})
    assert fresh.status_code == 200

    # the OTHER session's refresh token is dead (revoked server-side)
    assert client.post("/api/auth/refresh", json={"refresh_token": other_refresh}).status_code == 401

    # audit trail recorded the rotation
    audit = client.get("/api/audit?action=user.password_change", headers=admin_auth).json()
    assert audit["total"] >= 1

    # rotate back so the rest of the suite's fixtures still work
    back = client.post("/api/auth/password", headers={
        "Authorization": f"Bearer {fresh.json()['access_token']}"},
        json={"old_password": "Rotated-Pw-123456!", "new_password": "Sup3rStr0ngPw!"})
    assert back.status_code == 200


def test_password_change_wrong_old_password(client, admin_auth):
    r = client.post("/api/auth/password", headers=admin_auth, json={
        "old_password": "totally-wrong", "new_password": "Another-Pw-123456!"})
    assert r.status_code == 401
    assert "incorrect" in r.json()["detail"]


def test_password_change_too_short(client, admin_auth):
    r = client.post("/api/auth/password", headers=admin_auth, json={
        "old_password": "Sup3rStr0ngPw!", "new_password": "short"})
    assert r.status_code == 422  # Field(min_length=12)


def test_password_change_same_password(client, admin_auth):
    r = client.post("/api/auth/password", headers=admin_auth, json={
        "old_password": "Sup3rStr0ngPw!", "new_password": "Sup3rStr0ngPw!"})
    assert r.status_code == 400


def test_mfa_enroll_verify_disable_flow(client, admin_auth):
    """E-5: the API that had no UI — setup, verify with a REAL TOTP code,
    login now requires MFA, then disable (which also clears the secret)."""
    from packages.security.mfa import current_code

    setup = client.post("/api/auth/mfa/setup", headers=admin_auth)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert "otpauth://" in setup.json()["otpauth_uri"]

    # a second setup before verify regenerates (restart enrollment)
    s2 = client.post("/api/auth/mfa/setup", headers=admin_auth)
    secret = s2.json()["secret"]

    verify = client.post("/api/auth/mfa/verify", headers=admin_auth,
                         json={"code": current_code(secret)})
    assert verify.status_code == 200
    assert verify.json()["mfa_enabled"] is True

    # login without a code now fails; with the code succeeds
    bare = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    assert bare.status_code in (401, 423)
    with_code = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Sup3rStr0ngPw!",
        "mfa_code": current_code(secret)})
    assert withCode_login_ok(with_code)

    # admin MFA reset clears it (E-5 admin path)
    users = client.get("/api/users", headers=admin_auth).json()
    me = next(u for u in users if u["email"] == "admin@test.com")
    reset = client.post(f"/api/users/{me['id']}/mfa-reset", headers=admin_auth)
    assert reset.status_code == 200
    # login works again without a code
    bare2 = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    assert bare2.status_code == 200


def withCode_login_ok(resp):
    # NOTE: mfa_code login happens AFTER enrollment; some deployments
    # lock after failed attempts — this helper keeps the assertion honest.
    return resp.status_code == 200


def test_sessions_list_and_revoke(client, admin_auth):
    """E-13: a user can see their active sessions and revoke one."""
    login = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    other_refresh = login.json()["refresh_token"]

    sessions = client.get("/api/auth/sessions", headers=admin_auth).json()
    ids = [s["id"] for s in sessions["sessions"]]
    assert len(ids) >= 2  # this client + the one we just minted

    # revoke EVERY listed session (created_at ties make newest-first
    # ambiguous at test speed; revoking all proves per-token revocation)
    for sid in ids:
        r = client.post(f"/api/auth/sessions/{sid}/revoke", headers=admin_auth)
        assert r.status_code == 200
    # the freshly minted token is now dead
    assert client.post("/api/auth/refresh", json={"refresh_token": other_refresh}).status_code == 401


def test_admin_revokes_all_user_sessions(client, admin_auth):
    login = client.post("/api/auth/login", json={
        "email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    tok = login.json()["refresh_token"]
    users = client.get("/api/users", headers=admin_auth).json()
    me = next(u for u in users if u["email"] == "admin@test.com")

    r = client.post(f"/api/users/{me['id']}/sessions/revoke-all", headers=admin_auth)
    assert r.status_code == 200
    assert r.json()["revoked"] >= 1
    assert client.post("/api/auth/refresh", json={"refresh_token": tok}).status_code == 401


# ── R2 forensic search: saved searches (B8) ─────────────────────────────────
def test_saved_search_crud_and_quota_rules(client, admin_auth):
    body = {"name": "red jacket", "kind": "attributes",
            "params": {"key": "color", "value": "red"}}
    r = client.post("/api/searches", headers=admin_auth, json=body)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]

    items = client.get("/api/searches", headers=admin_auth).json()["items"]
    assert any(i["id"] == sid and i["kind"] == "attributes" for i in items)

    # duplicate name → 409; bad kind → 422; oversized payload → 422
    assert client.post("/api/searches", headers=admin_auth, json=body).status_code == 409
    bad = {"name": "x", "kind": "plates", "params": {"blob": "x" * 3000}}
    assert client.post("/api/searches", headers=admin_auth, json=bad).status_code == 422
    assert client.post("/api/searches", headers=admin_auth,
                       json={"name": "y", "kind": "nope", "params": {}}).status_code == 422

    assert client.delete(f"/api/searches/{sid}", headers=admin_auth).status_code == 200
    assert client.delete(f"/api/searches/{sid}", headers=admin_auth).status_code == 404


def test_saved_searches_are_private_per_user(client, admin_auth, viewer_auth):
    """Ownership boundary: permission gate first (VIEWER 403), then ownership
    (a entitled user never touches another's saved search -> 404)."""
    r = client.post("/api/searches", headers=admin_auth,
                    json={"name": "admin only", "kind": "plates", "params": {"q": "AB12CD"}})
    sid = r.json()["id"]
    assert client.get("/api/searches", headers=viewer_auth).json()["items"] == []
    # VIEWER lacks search:save entirely -> permission gate, not ownership
    assert client.post("/api/searches", headers=viewer_auth,
                       json={"name": "v", "kind": "text", "params": {}}).status_code == 403
    assert client.delete(f"/api/searches/{sid}", headers=viewer_auth).status_code == 403

    # an entitled second user (ANALYST has search:save) gets 404, not the row
    client.post("/api/users", json={"email": "analyst@test.com", "password": "AnalystPw12345",
                                    "role": "ANALYST"}, headers=_admin(client))
    analyst = client.post("/api/auth/login",
                          json={"email": "analyst@test.com", "password": "AnalystPw12345"}).json()
    ah = {"Authorization": f"Bearer {analyst['access_token']}"}
    assert client.get("/api/searches", headers=ah).json()["items"] == []
    assert client.delete(f"/api/searches/{sid}", headers=ah).status_code == 404
    assert client.delete(f"/api/searches/{sid}", headers=admin_auth).status_code == 200


def test_saved_search_lifecycle_is_audited(client, admin_auth):
    client.post("/api/searches", headers=admin_auth,
                json={"name": "audited", "kind": "text", "params": {"q": "loitering"}})
    items = client.get("/api/audit", params={"action": "search.save"},
                       headers=admin_auth).json()
    rows = items.get("items", items) if isinstance(items, dict) else items
    assert any("saved_search" in str(a.get("resource", "")) for a in rows), rows

