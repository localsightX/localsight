"""API tests for the R3.5 dry-run rule tester (POST /api/rules/test)."""
SQUARE = [[0.4, 0.4], [0.6, 0.4], [0.6, 0.6], [0.4, 0.6]]
RULES = [{"type": "intrusion", "rule_id": "z", "zone": SQUARE}]
FRAMES = [
    {"t": 0, "tracks": [["t1", "person", [0.48, 0.48, 0.04, 0.08]]]},
    {"t": 1, "tracks": [["t1", "person", [0.10, 0.10, 0.04, 0.08]]]},
]


def _admin(client):
    r = client.post("/api/auth/login",
                    json={"email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _viewer(client):
    client.post("/api/users", json={"email": "viewer2@test.com", "password": "ViewerPw12345",
                                    "role": "VIEWER"}, headers=_admin(client))
    r = client.post("/api/auth/login",
                    json={"email": "viewer2@test.com", "password": "ViewerPw12345"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_rule_test_dry_run(client):
    body = {"camera_id": "cam-x", "rules": RULES, "frames": FRAMES,
            "expect": [{"rule_type": "intrusion", "rule_id": "z", "at_frame": 0}]}
    r = client.post("/api/rules/test", json=body, headers=_admin(client))
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["pass"] is True and data["expect_errors"] == []
    assert data["camera_id"] == "cam-x" and data["frames"] == 2
    assert any(e["decision"] == "fired" for e in data["timeline"])
    assert data["events"][0]["rule_type"] == "intrusion"
    assert data["summary"]["total_events"] == 1


def test_rule_test_rejects_bad_rules_and_frames(client):
    h = _admin(client)
    r = client.post("/api/rules/test", json={"rules": [{"type": "bogus"}], "frames": []},
                    headers=h)
    assert r.status_code == 400
    assert r.json()["detail"]["schema_version"] == 1
    r = client.post("/api/rules/test",
                    json={"rules": RULES, "frames": [{"t": "now", "tracks": []}]}, headers=h)
    assert r.status_code == 400
    assert any("frames[0].t" in e for e in r.json()["detail"]["errors"])
    r = client.post("/api/rules/test",
                    json={"rules": RULES,
                          "frames": [{"t": 0, "tracks": [["t1", "person", [2, 0, 0, 0]]]}]},
                    headers=h)
    assert r.status_code == 400
    assert any("tracks[0][2]" in e for e in r.json()["detail"]["errors"])


def test_rule_test_requires_rules_configure(client):
    r = client.post("/api/rules/test", json={"rules": RULES, "frames": FRAMES},
                    headers=_viewer(client))
    assert r.status_code == 403
