"""API tests for the R3.6 daily alert budget (GET /api/alerts/budget, PUT camera)."""
import datetime as dt

import pytest

from packages.domain.models import Event


@pytest.fixture()
def rt(app):
    return app.state.runtime


def _admin(client):
    r = client.post("/api/auth/login",
                    json={"email": "admin@test.com", "password": "Sup3rStr0ngPw!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _viewer(client):
    client.post("/api/users", json={"email": "viewer3@test.com", "password": "ViewerPw12345",
                                    "role": "VIEWER"}, headers=_admin(client))
    r = client.post("/api/auth/login",
                    json={"email": "viewer3@test.com", "password": "ViewerPw12345"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_budget_endpoint_lists_cameras_with_usage(rt, app, client):
    h = _admin(client)
    cam_id = client.post("/api/cameras", json={"name": "budget-ui-cam"}, headers=h).json()["id"]
    now = dt.datetime.now(dt.UTC)
    with rt.SessionLocal() as s:
        s.add(Event(camera_id=cam_id, track_id="t", identity_status="unknown",
                    event_type="intrusion", timestamp_start=now, timestamp_end=now,
                    confidence=0.9, bbox={}))
        s.commit()
    r = client.get("/api/alerts/budget", headers=h)
    assert r.status_code == 200, r.text
    data = r.json()
    row = next(c for c in data["cameras"] if c["camera_id"] == cam_id)
    assert row["name"] == "budget-ui-cam"
    assert (row["limit_per_day"], row["effective_limit"]) == (None, 0)
    assert (row["used_today"], row["remaining"]) == (1, None)  # unlimited
    r = client.put(f"/api/cameras/{cam_id}", json={"alert_budget_per_day": 2}, headers=h)
    assert r.status_code == 200, r.text
    row = next(c for c in client.get("/api/alerts/budget", headers=h).json()["cameras"]
               if c["camera_id"] == cam_id)
    assert (row["limit_per_day"], row["effective_limit"]) == (2, 2)
    assert (row["used_today"], row["remaining"]) == (1, 1)


def test_budget_write_validation_and_rbac(client):
    h = _admin(client)
    cam_id = client.post("/api/cameras", json={"name": "budget-val-cam"}, headers=h).json()["id"]
    for bad in (-1, 10001, "5", True):
        r = client.put(f"/api/cameras/{cam_id}", json={"alert_budget_per_day": bad}, headers=h)
        assert r.status_code == 400, bad
    r = client.put(f"/api/cameras/{cam_id}", json={"alert_budget_per_day": None}, headers=h)
    assert r.status_code == 200, r.text
    assert client.get("/api/alerts/budget", headers=_viewer(client)).status_code == 403
