"""Trust-flow guards from the audit: C-6 (silent refresh), C-12 (never
blank states), C-13 (double-submit).

These drive the API layer's behavior through the real UI: the token dies,
the user keeps working; the API fails, the state says so with a Retry;
the button disables during submit, then re-enables.
"""
import pytest

pytestmark = pytest.mark.ui


def refreshs_ok(n) -> bool:
    """The silent refresh must have fired at least once (it's the whole
    point of C-6); many is fine — api() dedupes in-flight refreshes but
    separate views may each need one."""
    return n and n >= 1


class TestRefreshOn401:
    def test_silent_refresh_keeps_the_session(self, logged_in, server):
        """C-6: a dead access token triggers ONE silent refresh, and the
        user's next action succeeds — no visible logout, no error.

        Forcing the 401 honestly: fetch is wrapped for one navigation to
        mangle the Authorization header; api() must use its valid refresh
        token to mint a fresh access token and retry transparently.
        """
        page = logged_in
        page.click("#nav button[data-view='events']")
        page.wait_for_selector("tr.event-row")
        page.evaluate("""
          () => {
            const orig = window.fetch;
            window.__lv_refresh_count = 0;
            const mangled = new Set();
            window.fetch = (input, init) => {
              const url = typeof input === 'string' ? input : input.url;
              if (url.includes('/api/auth/refresh')) window.__lv_refresh_count++;
              // Mangle each API URL exactly ONCE: the first call 401s, the
              // api() layer silently refreshes and retries, and the retry
              // must go through clean (else we'd be testing the mangler).
              if (init && init.headers && !url.includes('/api/auth/')
                  && !mangled.has(url)) {
                mangled.add(url);
                const h = new Headers(init.headers);
                h.set('Authorization', 'Bearer broken-on-purpose');
                return orig(input, {...init, headers: h});
              }
              return orig(input, init);
            };
          }""")
        page.click("#nav button[data-view='privacy']")
        page.wait_for_timeout(1200)
        restored = page.evaluate("() => { const f = window.fetch; return f && f.name; }")
        visible = page.evaluate(
            "!document.querySelector('[data-panel=privacy]').classList.contains('hidden')")
        assert visible
        # The privacy view actually loaded DATA (not stuck on skeleton):
        assert page.locator("#privacy-list .card").count() >= 1
        refreshes = page.evaluate("window.__lv_refresh_count")
        assert refreshs_ok(refreshes), refreshes
        _ = restored

    def test_dead_session_exits_to_login(self, server, page):
        """When BOTH tokens are dead: the app leaves to the login screen
        with a notice — never a silently broken page."""
        page.goto(server["base"] + "/")
        page.fill("#email", "admin@test.com")
        page.fill("#password", server["admin_password"])
        page.click("button[type=submit]")
        page.wait_for_selector("#app:not(.hidden)")
        # Burn the refresh token: every refresh from now on 401s.
        page.evaluate("""
          () => {
            const keys = [];
            for (let i = 0; i < sessionStorage.length; i++) {
              const k = sessionStorage.key(i);
              if (k.includes('refresh')) keys.push(k);
            }
            keys.forEach(k => sessionStorage.setItem(k, 'dead-token'));
            const orig = window.fetch;
            window.fetch = (input, init) => {
              const url = typeof input === 'string' ? input : input.url;
              if (init && init.headers && !url.includes('/api/auth/login')) {
                const h = new Headers(init.headers);
                h.set('Authorization', 'Bearer broken-on-purpose');
                return orig(input, {...init, headers: h});
              }
              return orig(input, init);
            };
          }""")
                # Dispatch the nav click directly: a dead session fires auth:expired
        # asynchronously during privacy view load, which calls leaveApp() —
        # hiding #app (the nav button's parent) mid-click and causing
        # Playwright's actionability check to time out. Bypass the check and
        # assert on the outcome instead.
        page.evaluate(
            "document.querySelector(\"#nav button[data-view='privacy']\").click()")
        page.wait_for_selector("#login:not(.hidden)", timeout=10000)
        login_visible = page.evaluate(
            "!document.getElementById('login').classList.contains('hidden')")
        assert login_visible, "dead session must land on the login screen"


class TestHonestStates:
    def test_api_failure_shows_error_with_retry(self, logged_in):
        """C-12: a dead API surfaces an inline error + Retry — never blank."""
        page = logged_in
        page.route("**/api/cameras", lambda route: route.abort()
                   if "ui-fail" in page.url else route.continue_())
        # abort every cameras fetch while on the events view, then navigate
        page.click("#nav button[data-view='events']")
        page.wait_for_selector("tr.event-row")
        page.unroute("**/api/cameras")
        page.route("**/api/cameras*", lambda route: route.abort())
        page.click("#nav button[data-view='cameras']")
        page.wait_for_timeout(2000)
        assert page.locator("text=Couldn't load").count() >= 1
        assert page.locator("button", has_text="Retry").count() >= 1
        page.unroute("**/api/cameras*")
        # Retry recovers to real data
        page.locator("button", has_text="Retry").first.click()
        page.wait_for_selector(".cam-card")


class TestDoubleSubmit:
    def test_person_create_disables_during_submit(self, logged_in):
        """C-13: the submit button disables synchronously and recovers."""
        page = logged_in
        page.click("#nav button[data-view='people']")
        page.wait_for_selector("[data-person]")
        page.click("#person-add")
        page.wait_for_selector("[data-form='person-new']")
        page.locator("[data-form='person-new'] [data-field='label']").fill(
            "doublesubmit-e2e")
        page.locator("[data-form='person-new'] [data-field='name']").fill(
            "Double Submit Probe")
        disabled_at_click = page.evaluate("""
          () => {
            const form = document.querySelector("[data-form='person-new']");
            const b = form.querySelector("[data-act='person-create']");
            if (!b) return false;
            b.click();
            return b.disabled;  // synchronous read right after the click
          }""")
        assert disabled_at_click
        page.wait_for_timeout(900)
        recovered = page.evaluate("""
          () => {
            const form = document.querySelector("[data-form='person-new']");
            if (!form) return true;  // unmounted = success path completed
            const b = form.querySelector("[data-act='person-create']");
            return b ? !b.disabled : true;
          }""")
        assert recovered
