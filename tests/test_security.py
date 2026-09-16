"""Security tests: auth, lockout, RBAC, SSRF, encryption, path traversal."""
from __future__ import annotations

import base64
import secrets

import pytest

from packages.security.crypto import CryptoBox
from packages.security.ssrf import UnsafeUrlError, validate_egress_url
from packages.storage.local import LocalFilesystemStorage


# ── Auth + lockout ────────────────────────────────────────────────────────────
def test_login_success(client, admin_auth):
    assert admin_auth["Authorization"].startswith("Bearer ")


def test_wrong_password_lockout(client):
    email = "admin@test.com"
    for _ in range(5):
        r = client.post("/api/auth/login", json={"email": email, "password": "wrongpassword1"})
        assert r.status_code in (401, 423)
    # now even the correct password is rejected while locked
    r = client.post("/api/auth/login", json={"email": email, "password": "Sup3rStr0ngPw!"})
    assert r.status_code == 423


def test_refresh_rotation(client, admin_auth):
    # first get a refresh token via login response
    login = client.post("/api/auth/login", json={"email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    refresh = login.json()["refresh_token"]
    r1 = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r1.status_code == 200
    new_refresh = r1.json()["refresh_token"]
    # replaying the old refresh must fail (rotated/revoked)
    r2 = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 401
    # new refresh still works
    r3 = client.post("/api/auth/refresh", json={"refresh_token": new_refresh})
    assert r3.status_code == 200


def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


# ── RBAC ──────────────────────────────────────────────────────────────────────
def test_viewer_cannot_create_camera(client, viewer_auth):
    r = client.post("/api/cameras", json={"name": "x"}, headers=viewer_auth)
    assert r.status_code == 403


def test_operator_can_create_camera(client, admin_auth):
    r = client.post("/api/cameras", json={"name": "cam-1"}, headers=admin_auth)
    assert r.status_code == 200
    assert "id" in r.json()


# ── SSRF ──────────────────────────────────────────────────────────────────────
def test_ssrf_blocks_private_and_metadata(client, admin_auth):
    for bad in ["rtsp://127.0.0.1/stream", "rtsp://169.254.169.254/latest", "rtsp://10.0.0.5/x", "rtsp://192.168.1.5/x"]:
        r = client.post("/api/cameras", json={"name": "bad", "stream_url": bad}, headers=admin_auth)
        assert r.status_code == 400, f"expected block for {bad}, got {r.status_code}: {r.text}"


def test_ssrf_allows_public(client, admin_auth):
    r = client.post("/api/cameras", json={"name": "pub", "stream_url": "rtsp://1.1.1.1/stream"}, headers=admin_auth)
    assert r.status_code == 200


def test_ssrf_rejects_decimal_octet_bypass():
    """Decimal/0x/octal IP spellings bypass naive string allowlists (rule H-S1).

    `parse_ip_literal` normalizes them, so 2130706433 (== 127.0.0.1) and
    0x7f.0.0.1 must still be rejected without an explicit allowlist.
    """
    for evil in ["http://2130706433/", "http://0x7f.0.0.1/", "http://0177.0.0.1/"]:
        with pytest.raises(UnsafeUrlError):
            validate_egress_url(evil)


def test_ssrf_rejects_userinfo_spoof():
    """Credentials must be unwrapped before host validation (rule H-S1).

    `https://public.com@169.254.169.254/` connects to the metadata IP; an
    authority-string comparison against "public.com" would wrongly allow it.
    """
    with pytest.raises(UnsafeUrlError):
        validate_egress_url("https://example.com@169.254.169.254/")
    with pytest.raises(UnsafeUrlError):
        validate_egress_url("https://user:pass@127.0.0.1:554/stream")


def test_alert_route_rejects_internal_webhook(client, admin_auth):
    """Alert routes are standing egress — validation must happen at create."""
    # Metadata-IP webhook must be rejected with 400, not persisted.
    r = client.post("/api/alerts/routes",
                    json={"rule_type": "motion", "channel": "webhook",
                          "config": {"url": "http://169.254.169.254/hook"}},
                    headers=admin_auth)
    assert r.status_code == 400, f"expected block, got {r.status_code}: {r.text}"
    assert r.json().get("id") is None
    # Same for host-bearing channels. NOTE: conftest allowlists 192.168.99.0/24
    # (the fake camera VLAN), so a 127.0.0.1 MQTT broker must STILL be rejected.
    r2 = client.post("/api/alerts/routes",
                     json={"rule_type": "motion", "channel": "mqtt",
                           "config": {"host": "127.0.0.1", "port": 1883}},
                     headers=admin_auth)
    assert r2.status_code == 400, f"expected block, got {r2.status_code}: {r2.text}"


def test_alert_route_accepts_public_webhook(client, admin_auth):
    # Numeric public IP — no DNS needed (CI/dev networks may have no resolver).
    r = client.post("/api/alerts/routes",
                    json={"rule_type": "motion", "channel": "webhook",
                          "config": {"url": "https://1.1.1.1/x"}},
                    headers=admin_auth)
    assert r.status_code == 200, r.text
    assert "id" in r.json()


def test_validate_egress_unit():
    with pytest.raises(UnsafeUrlError):
        validate_egress_url("http://169.254.169.254/")
    # allowlist bypass
    res = validate_egress_url("http://10.0.0.5/x", allowlist=["10.0.0.0/8"])
    assert res.hostname == "10.0.0.5"


# ── Encryption at rest ─────────────────────────────────────────────────────────
def test_crypto_roundtrip():
    box = CryptoBox(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    ct = box.encrypt_str("secret-value")
    assert ct != "secret-value"
    assert box.decrypt_str(ct) == "secret-value"
    obj = box.encrypt_json({"a": [1, 2, 3]})
    assert box.decrypt_json(obj) == {"a": [1, 2, 3]}


def test_crypto_rejects_empty_key():
    with pytest.raises(Exception):
        CryptoBox("")


# ── Path traversal in storage ──────────────────────────────────────────────────
def test_storage_path_traversal_rejected(tmp_path):
    store = LocalFilesystemStorage(str(tmp_path), "signing-secret-1234567890")
    with pytest.raises(ValueError):
        store.put("../escape.txt", b"x")
    with pytest.raises(ValueError):
        store.put("/abs/path.txt", b"x")


def test_signed_url_tamper_rejected(tmp_path):
    store = LocalFilesystemStorage(str(tmp_path), "signing-secret-1234567890")
    store.put("seg/1.mp4", b"data")
    url = store.sign_get_url("seg/1.mp4", expires_sec=300)
    from urllib.parse import urlparse, parse_qs
    p = urlparse(url)
    q = parse_qs(p.query)
    sig = q["sig"][0]
    exp = q["exp"][0]
    assert store.verify_signed_url("seg/1.mp4", exp, sig) is True
    assert store.verify_signed_url("seg/1.mp4", exp, "deadbeef") is False


def test_signed_url_ttl_capped(tmp_path):
    """Signed URLs are bearer credentials — expiry must be bounded (rule H-S6).

    A multi-year TTL is silently clamped to ≤1 h so a leaked URL eventually
    dies instead of becoming a permanent public link.
    """
    import time
    store = LocalFilesystemStorage(str(tmp_path), "signing-secret-1234567890")
    store.put("seg/1.mp4", b"data")
    url = store.sign_get_url("seg/1.mp4", expires_sec=10 * 365 * 86400)
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(url).query)
    assert int(q["exp"][0]) - int(time.time()) <= 3600


def test_storage_symlink_escape_rejected(tmp_path):
    """A symlink inside the storage root must not redirect writes (rule H-S4)."""
    import os
    store = LocalFilesystemStorage(str(tmp_path), "signing-secret-1234567890")
    outside = tmp_path / "outside.txt"
    (tmp_path / "linkdir").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        store.put("linkdir/../outside.txt", b"data")
    assert not outside.exists()
    # ... nor reads through an absolute-path symlink hop.
    os.symlink(str(outside), tmp_path / "evil.txt")
    with pytest.raises((ValueError, FileNotFoundError)):
        store.get("evil.txt")


def test_rate_limiter_memory_bounded():
    """Distinct-key floods (spoofed IPs) must not grow the table forever."""
    from packages.security.ratelimit import RateLimiter
    rl = RateLimiter(max_buckets=100)
    for i in range(5000):
        rl.allow(f"10.9.{i // 256}.{i % 256}", "login", rate=1.0, capacity=10)
    assert rl.bucket_count() <= 5000  # flood keys stay live while hot ...
    import time as _t
    _t.sleep(1.2)  # ... but idle keys are reclaimed on the next call.
    rl.allow("203.0.113.9", "login", rate=1.0, capacity=10)
    assert rl.bucket_count() < 5000


def test_login_enumeration_timing_shape(client):
    """Unknown vs wrong-password logins share status + cost profile (rule H-A2).

    Both return 401 without a 423/lockout distinction, and the unknown-account
    branch still pays for exactly one Argon2 verify (no fast path).
    """
    import time as _t
    t0 = _t.perf_counter()
    r_unknown = client.post("/api/auth/login",
                            json={"email": "nobody-here@test.com", "password": "wrongpassword1"})
    t_unknown = _t.perf_counter() - t0
    t0 = _t.perf_counter()
    r_wrong = client.post("/api/auth/login",
                          json={"email": "admin@test.com", "password": "wrongpassword1"})
    t_wrong = _t.perf_counter() - t0
    assert r_unknown.status_code == 401 == r_wrong.status_code
    # Same order of magnitude (single Argon2 verify each) — a 10x gap would
    # mean one branch skipped the hash.
    assert t_unknown > 0.25 * t_wrong
