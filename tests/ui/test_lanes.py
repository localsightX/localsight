"""UI e2e for the R4.1 gate-access lane editor (Cameras → Gate access tab).

Mirrors the API suite's security invariants through the browser:

  - arming a lane round-trips (allow window, cooldown, barrier destination)
  - a lane cannot be armed without a barrier destination (the client blocks
    it; the worker would otherwise log "OPEN suppressed" on every read)
  - an SSRF-rejected destination is surfaced inline AND is not persisted —
    the guard runs before the write, so a refused loopback target never
    becomes a stored relay a plate read could fire
  - whitelist enroll/revoke store only the plate digest; the plaintext plate
    the operator typed is echoed once and never comes back
  - removing a lane cascades the whitelist
  - ANALYST (lanes:view, not lanes:manage) sees the tab but no forms
"""
import secrets

import httpx
import pytest

pytestmark = pytest.mark.ui

# A destination the SSRF guard accepts in the ui-e2e env (public host) and one
# it refuses (loopback; SSRF_ALLOWLIST is 192.168.99.0/24 — see conftest).
OK_DEST = "https://example.com/gate/open"
BAD_DEST = "http://127.0.0.1:9999/open"


def _api(base, path, token, method="GET", body=None):
    r = httpx.request(method, f"{base}{path}", json=body,
                      headers={"Authorization": f"Bearer {token}"}, timeout=10)
    return r


def _first_camera(base, token):
    r = _api(base, "/api/cameras", token)
    r.raise_for_status()
    cams = r.json()
    return (cams if isinstance(cams, list) else cams.get("items", []))[0]["id"]


def _clean_lane(base, token, cam_id):
    """Start every test from a camera with no lane (idempotent)."""
    _api(base, f"/api/cameras/{cam_id}/lane", token, method="DELETE")


def _arm_lane(base, token, cam_id, dest=OK_DEST):
    r = _api(base, f"/api/cameras/{cam_id}/lane", token, method="PUT", body={
        "name": "Probe lane",
        "barrier_channel": "webhook",
        "barrier_config": {"url": dest},
        "allow_window": None,
        "cooldown_sec": 45,
        "enabled": True,
    })
    r.raise_for_status()


def _poll_for_lane(base, token, cam_id, timeout=10.0):
    """Wait until the UI's async save has actually landed in the DB.

    A toast-poll is NOT a synchronization primitive here: the success notice
    only appears after the PUT resolves, so polling toasts can pass while the
    write is still in flight and then read a stale 404. Poll the store.
    """
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = _api(base, f"/api/cameras/{cam_id}/lane", token)
        if r.status_code == 200:
            return r.json()
        time.sleep(0.15)
    return None


def _open_gate_tab(page, cam_id, base):
    # Deep link — the same path the events/dvr handoffs use (proven in the
    # journeys suite). Reloads preserve the session via sessionStorage.
    page.goto(f"{base}/#/cameras?id={cam_id}&tab=gate-access")
    page.wait_for_selector("[data-form='lane-policy'], [data-role='lane-summary']")


def _clear_toasts(page):
    page.wait_for_function(
        "() => document.querySelectorAll('.toast').length === 0", timeout=10000)


@pytest.mark.usefixtures("server")
class TestLanePolicy:
    def test_arm_lane_round_trips_through_the_ui(self, logged_in, server, admin_token):
        page = logged_in
        base = server["base"]
        cam = _first_camera(base, admin_token)
        _clean_lane(base, admin_token, cam)

        _open_gate_tab(page, cam, base)
        page.fill("[data-form='lane-policy'] [data-field='name']", "North gate")
        page.fill("[data-form='lane-policy'] [data-field='cooldown']", "45")
        page.fill("[data-window='start']", "09:00")
        page.fill("[data-window='end']", "17:00")
        page.click("[data-day='3']")  # Wednesday; all-off means every day
        page.fill("[data-dest='url']", OK_DEST)
        page.click("[data-act='lane-save']")
        # The save is async — wait for the write to land before asserting.
        lane = _poll_for_lane(base, admin_token, cam)
        assert lane is not None, "lane was not created by the UI save"
        assert lane["enabled"] is True
        assert lane["name"] == "North gate"
        assert lane["cooldown_sec"] == 45
        assert lane["barrier_configured"] is True
        assert lane["allow_window"]["start"] == "09:00"
        assert lane["allow_window"]["end"] == "17:00"
        assert 3 in lane["allow_window"]["days"]
        # The summary card is the operator's at-a-glance state after arming.
        page.wait_for_selector("[data-role='lane-summary']")

    def test_arming_without_a_destination_is_blocked(self, logged_in, server, admin_token):
        page = logged_in
        base = server["base"]
        cam = _first_camera(base, admin_token)
        _clean_lane(base, admin_token, cam)

        _open_gate_tab(page, cam, base)
        # Armed is checked by default; destination left empty on purpose.
        page.click("[data-act='lane-save']")
        page.wait_for_selector("[data-role='lane-error']:not(:empty)")
        err = page.locator("[data-role='lane-error']").inner_text()
        assert "destination" in err.lower()

        # And nothing was written — no half-armed lane left behind.
        r = _api(base, f"/api/cameras/{cam}/lane", admin_token)
        assert r.status_code == 404

    def test_ssrf_rejected_destination_is_not_persisted(self, logged_in, server, admin_token):
        page = logged_in
        base = server["base"]
        cam = _first_camera(base, admin_token)
        _clean_lane(base, admin_token, cam)

        _open_gate_tab(page, cam, base)
        page.fill("[data-dest='url']", BAD_DEST)  # loopback: refused
        page.click("[data-act='lane-save']")
        page.wait_for_selector("[data-role='lane-error']:not(:empty)")
        err = page.locator("[data-role='lane-error']").inner_text()
        # The SSRF guard's own wording lands next to the field.
        assert "unsafe" in err.lower()

        # The guard runs BEFORE persist, so the refused target is not stored.
        r = _api(base, f"/api/cameras/{cam}/lane", admin_token)
        assert r.status_code == 404



@pytest.mark.usefixtures("server")
class TestWhitelist:
    def test_enroll_shows_digest_and_revokes(self, logged_in, server, admin_token):
        page = logged_in
        base = server["base"]
        cam = _first_camera(base, admin_token)
        _clean_lane(base, admin_token, cam)
        _arm_lane(base, admin_token, cam)

        _open_gate_tab(page, cam, base)
        page.fill("[data-form='lane-whitelist'] [data-field='plate']", "test-123")
        page.fill("[data-form='lane-whitelist'] [data-field='label']", "Delivery van")
        page.click("[data-act='whitelist-enroll']")
        # The row only renders after the enroll lands + re-render — wait for it
        # rather than racing the in-flight POST via a toast poll.
        page.wait_for_selector("[data-role='whitelist-rows'] [data-entry]")

        r = _api(base, f"/api/cameras/{cam}/lane", admin_token)
        wl = r.json()["whitelist"]
        assert len(wl) == 1
        # Stored shape: digest only — no plaintext plate anywhere in the row.
        entry = wl[0]
        assert entry["label"] == "Delivery van"
        assert entry["plate_hash"]

        # The row renders the digest (never the plate) and is revoke-able.
        row = page.locator("[data-role='whitelist-rows'] [data-entry]")
        assert row.count() == 1
        assert entry["plate_hash"].startswith(row.locator(".mono").inner_text())
        # The enroll notice can still be overlaying the row actions.
        _clear_toasts(page)
        row.locator("[data-act='whitelist-revoke']").click()
        page.locator("[data-act='whitelist-revoke-confirm']").click()
        _clear_toasts(page)
        page.wait_for_function(
            "() => document.querySelectorAll('[data-role=whitelist-rows] [data-entry]').length === 0")
        r = _api(base, f"/api/cameras/{cam}/lane", admin_token)
        assert r.json()["whitelist"] == []

    def test_label_cannot_be_the_plate(self, logged_in, server, admin_token):
        page = logged_in
        base = server["base"]
        cam = _first_camera(base, admin_token)
        _clean_lane(base, admin_token, cam)
        _arm_lane(base, admin_token, cam)

        _open_gate_tab(page, cam, base)
        page.fill("[data-form='lane-whitelist'] [data-field='plate']", "AB12CDE")
        page.fill("[data-form='lane-whitelist'] [data-field='label']", "AB12CDE")
        page.click("[data-act='whitelist-enroll']")
        page.wait_for_selector("[data-role='enroll-error']:not(:empty)")
        # Nothing enrolled: the note would otherwise be a plaintext-plate store.
        r = _api(base, f"/api/cameras/{cam}/lane", admin_token)
        assert r.json()["whitelist"] == []

    def test_remove_lane_cascades_whitelist(self, logged_in, server, admin_token):
        page = logged_in
        base = server["base"]
        cam = _first_camera(base, admin_token)
        _clean_lane(base, admin_token, cam)
        _arm_lane(base, admin_token, cam)
        r = _api(base, f"/api/cameras/{cam}/lane/whitelist", admin_token, method="POST",
                 body={"plate": "ZZ99 ZZZ", "label": "Pool car"})
        r.raise_for_status()

        _open_gate_tab(page, cam, base)
        page.click("[data-act='lane-remove']")
        page.locator("[data-act='lane-remove-confirm']").click()
        _clear_toasts(page)
        page.wait_for_function(
            "() => !document.querySelector('[data-role=remove-lane]')")

        r = _api(base, f"/api/cameras/{cam}/lane", admin_token)
        assert r.status_code == 404


@pytest.mark.usefixtures("server")
class TestLaneRBAC:
    def test_analyst_sees_tab_but_no_mutating_forms(self, page, server, admin_token, playwright):
        base = server["base"]
        cam = _first_camera(base, admin_token)
        _clean_lane(base, admin_token, cam)
        _arm_lane(base, admin_token, cam)

        email = f"lane-analyst-{secrets.token_hex(3)}@example.com"
        pw = "Analyst-Pw-123456"
        r = _api(base, "/api/users", admin_token, method="POST",
                 body={"email": email, "password": pw, "role": "ANALYST",
                       "full_name": "Lane Analyst"})
        r.raise_for_status()

        # Separate context: sessionStorage is per-context, so the admin's
        # session must not bleed into the analyst's tab (the wave-3 pattern).
        browser = playwright.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        pg = ctx.new_page()
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)[:200]))
        try:
            pg.goto(base + "/")
            pg.fill("#email", email)
            pg.fill("#password", pw)
            pg.click("button[type=submit]")
            pg.wait_for_selector("#app:not(.hidden)")
            # Deep link to the Gate access tab (the journeys-suite pattern).
            pg.goto(f"{base}/#/cameras?id={cam}&tab=gate-access")
            pg.wait_for_selector("[data-role='lane-summary']")
            # ANALYST holds lanes:view → the tab is present…
            assert pg.locator("[data-tab='gate-access']").count() == 1
            # …but not lanes:manage → no policy or whitelist forms, and no
            # destructive controls.
            assert pg.locator("[data-form='lane-policy']").count() == 0
            assert pg.locator("[data-form='lane-whitelist']").count() == 0
            assert pg.locator("[data-act='lane-remove']").count() == 0
            assert pg.locator("[data-act='whitelist-revoke']").count() == 0
        finally:
            ctx.close()
            browser.close()
        assert errors == []


def test_gate_access_tab_axe_clean(logged_in, server, admin_token, axe):
    """The broad a11y scan covers top-level views, not camera detail tabs —
    and this one is form-heavy (labels, chips with aria-pressed, a time range),
    so it gets its own scan."""
    page = logged_in
    base = server["base"]
    cam = _first_camera(base, admin_token)
    _clean_lane(base, admin_token, cam)
    _arm_lane(base, admin_token, cam)
    r = _api(base, f"/api/cameras/{cam}/lane/whitelist", admin_token, method="POST",
             body={"plate": "AB12 CDE", "label": "Pool car"})
    r.raise_for_status()
    _open_gate_tab(page, cam, base)
    page.wait_for_selector("[data-role='whitelist-rows'] [data-entry]")
    page.wait_for_timeout(400)
    res = axe()
    ids = [v["id"] for v in res["violations"]]
    assert ids == [], ids

