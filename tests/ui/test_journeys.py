"""Operator journeys across waves: login → investigate → live → configure.

Each journey is the real click-path an operator takes, asserting the
outcome — not DOM internals. These encode the redesign's exit criteria:
shareable investigations, honest live states, and management flows that
expose every backend capability.
"""
import httpx
import pytest

pytestmark = pytest.mark.ui


def _login_error(server, page, email, password):
    page.goto(server["base"] + "/")
    page.fill("#email", email)
    page.fill("#password", password)
    page.click("button[type=submit]")
    page.wait_for_timeout(700)
    return page.inner_text("#login-error")


class TestLoginJourney:
    def test_login_wrong_password_copy(self, server, page):
        """C-7: the error names the problem, no status-code soup."""
        msg = _login_error(server, page, "admin@test.com", "wrong-password")
        assert "Incorrect" in msg, msg

    def test_login_unknown_account_same_copy(self, server, page):
        """User enumeration: a wrong email and a wrong password read alike."""
        msg = _login_error(server, page, "nobody@test.com", "whatever")
        assert "Incorrect" in msg, msg

    def test_login_success_lands_on_overview(self, logged_in):
        logged_in.wait_for_timeout(600)
        visible = logged_in.evaluate(
            "!document.querySelector('[data-panel=dashboard]').classList.contains('hidden')")
        assert visible


class TestInvestigationJourney:
    def test_row_to_drawer_to_deep_link(self, logged_in):
        """Wave 1 exit: thumbnail → drawer → shareable URL → back."""
        page = logged_in
        page.click("#nav button[data-view='events']")
        page.wait_for_selector("tr.event-row")
        page.locator("tr.event-row").first.click()
        page.wait_for_selector(".drawer:not(.hidden)")
        assert "#/event/" in page.url
        page.go_back()
        page.wait_for_selector(".drawer.hidden", state="attached")
        page.wait_for_selector("tr.event-row")

    def test_keyboard_path_opens_drawer(self, logged_in):
        page = logged_in
        page.click("#nav button[data-view='events']")
        page.wait_for_selector("tr.event-row")
        page.keyboard.press("ArrowDown")
        page.keyboard.press("Enter")
        page.wait_for_selector(".drawer:not(.hidden)")

    def test_timeline_to_events_handoff(self, logged_in):
        page = logged_in
        page.click("#nav button[data-view='timeline']")
        page.wait_for_selector(".tl-svg")
        page.click("#nav button[data-view='events']")
        page.wait_for_selector("tr.event-row")


class TestLiveJourney:
    def test_live_grid_tiles_render_with_honest_states(self, logged_in):
        """Cameras unreachable in the e2e env → visible offline states,
        never console crashes (the Wave-2 promise)."""
        page = logged_in
        page.click("#nav button[data-view='live']")
        page.wait_for_selector(".live-tile")
        page.wait_for_timeout(2500)
        tiles = page.locator(".live-tile").count()
        assert tiles >= 5  # seeded cameras all have tiles
        offline = page.locator(".live-tile.offline").count()
        states = page.locator(".live-state").all_inner_texts()
        assert offline >= 1 or any("unavailable" in s for s in states), states

    def test_layout_switch_persists_in_tab(self, logged_in):
        page = logged_in
        page.click("#nav button[data-view='live']")
        page.wait_for_selector(".live-tile")
        page.click('[data-role="layout"][data-cols="3"]')
        page.wait_for_timeout(800)
        cls = page.eval_on_selector("#live-grid", "el => el.className")
        assert "3" in cls


class TestManageJourney:
    def test_camera_detail_tabs_and_mask_editor(self, logged_in):
        page = logged_in
        page.click("#nav button[data-view='cameras']")
        page.wait_for_selector(".cam-card")
        page.locator(".cam-card [data-act='detail']").first.click()
        page.wait_for_selector(".cam-detail")
        assert page.locator(".tabs button").count() == 5
        page.click("[data-tab='masks']")
        page.wait_for_selector(".mask-editor")
        # drawing works without a snapshot (honest offline canvas)
        page.locator("[data-role='stage']").scroll_into_view_if_needed()
        page.wait_for_timeout(300)
        box = page.locator("[data-role='overlay']").bounding_box()
        assert box, "mask overlay must render even without a snapshot"
        page.mouse.move(box["x"] + box["width"] * 0.6, box["y"] + box["height"] * 0.2)
        page.mouse.down()
        page.mouse.move(box["x"] + box["width"] * 0.8, box["y"] + box["height"] * 0.5, steps=4)
        page.mouse.up()
        page.wait_for_timeout(200)
        assert page.locator(".mask-rect.draft").count() == 1

    def test_shortcut_jumps(self, logged_in):
        page = logged_in
        page.keyboard.press("g")
        page.keyboard.press("e")
        page.wait_for_timeout(700)
        assert page.evaluate(
            "!document.querySelector('[data-panel=events]').classList.contains('hidden')")

    def test_analytics_search_to_drawer(self, logged_in):
        page = logged_in
        page.click("#nav button[data-view='analytics']")
        page.wait_for_selector("#an-q")
        page.fill("#an-q", "presence")
        page.click("[data-form='an-search'] button[type=submit]")
        page.wait_for_timeout(1500)
        rows = page.locator("[data-role='an-results'] tbody tr").count()
        assert rows >= 1
        page.locator("[data-role='an-results'] tbody tr").first.click()
        page.wait_for_selector(".drawer:not(.hidden)")


class TestSessionJourney:
    def test_logout_returns_to_login(self, logged_in):
        logged_in.click("#logout")
        logged_in.wait_for_selector("#login:not(.hidden)")
        assert logged_in.evaluate(
            "!document.getElementById('app').classList.contains('hidden')") is False


class TestCameraRemovalJourney:
    def test_remove_camera_typed_confirm(self, server, logged_in, admin_token):
        """Removing a camera is a typed-confirm gate; the grid then loses the card."""
        page = logged_in
        r = httpx.post(f"{server['base']}/api/cameras",
                       json={"name": "e2e-remove-me"},
                       headers={"Authorization": f"Bearer {admin_token}"}, timeout=10)
        assert r.status_code == 200, r.text
        cam_id = r.json()["id"]

        page.goto(f"{server['base']}/#/cameras?id={cam_id}")
        page.wait_for_selector("[data-role=remove-camera]")
        # The destructive control is not even revealed until asked for…
        page.click("[data-act=remove-camera]")
        page.wait_for_selector("[data-role=remove-confirm]:not(.hidden)")
        # …and it stays locked until the camera's exact name is typed.
        assert page.is_disabled("[data-act=remove-camera-confirm]")
        page.fill("[data-field=confirm-name]", "e2e-remove")
        assert page.is_disabled("[data-act=remove-camera-confirm]")
        page.fill("[data-field=confirm-name]", "e2e-remove-me")
        page.wait_for_selector("[data-act=remove-camera-confirm]:not([disabled])")
        page.click("[data-act=remove-camera-confirm]")
        page.wait_for_selector(".cam-grid")
        assert page.locator(".cam-card[data-cam='e2e-remove-me']").count() == 0

    def test_remove_camera_cancel_keeps_it(self, server, logged_in, admin_token):
        """Cancel backs out without any API call — the camera survives."""
        page = logged_in
        r = httpx.post(f"{server['base']}/api/cameras",
                       json={"name": "e2e-keep-me"},
                       headers={"Authorization": f"Bearer {admin_token}"}, timeout=10)
        assert r.status_code == 200, r.text
        cam_id = r.json()["id"]

        page.goto(f"{server['base']}/#/cameras?id={cam_id}")
        page.wait_for_selector("[data-role=remove-camera]")
        page.click("[data-act=remove-camera]")
        page.wait_for_selector("[data-role=remove-confirm]:not(.hidden)")
        page.click("[data-act=remove-camera-cancel]")
        # 'hidden' means display:none — wait for attachment, not visibility.
        page.wait_for_selector("[data-role=remove-confirm].hidden", state="attached")
        page.click("#nav button[data-view='cameras']")
        page.wait_for_selector(".cam-grid")
        assert page.locator(".cam-card[data-cam='e2e-keep-me']").count() == 1
