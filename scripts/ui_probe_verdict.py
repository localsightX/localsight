#!/usr/bin/env python3
"""Verdict-timeline probe (R3.5 follow-up) — Playwright.

Verifies the rules editor's "Replay & verdict" card end-to-end against a
running app:

  1. card mounts in the rules tab with fixture input + run button
  2. running with no fixture picked surfaces the honest inline error
  3. a fixture (line_cross with an expect block) file-picked and replayed
     through POST /api/rules/test renders the verdict banner (PASS/FAIL),
     one SVG lane per rule with fire markers, and the summary line
  4. zero unexpected console errors under the live CSP

Self-provisions a fresh ADMIN via the bootstrap admin (same pattern as the
wave probes); the fixture is written to a temp file and attached with
set_input_files (no OS dialog).
"""
import json
import os
import secrets
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("LV_BASE", "http://127.0.0.1:8779")
ADMIN_EMAIL = "admin@localsight.local"
OUT = Path("ui_audit/verdict")
# Optional docs capture: set LV_DOCS_SHOT=docs/img to also write viewport
# screenshots of the rules editor (drawn geometry) and the replay verdict
# card (PASS banner + lanes) as a by-product of a real verification pass.
# Off by default — the probe's job is verification, not asset production.
DOCS = Path(os.environ["LV_DOCS_SHOT"]) if os.environ.get("LV_DOCS_SHOT") else None

if os.environ.get("LV_INSECURE_TLS"):
    ssl._create_default_https_context = ssl._create_unverified_context

_FILTERED = ("503", "403", "400", "409", "404")


def _login(email: str, password: str) -> str:
    body = json.dumps({"email": email, "password": password}).encode()
    r = urllib.request.Request(f"{BASE}/api/auth/login", data=body,
                               headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(r).read())["access_token"]


def admin_token() -> str:
    pw = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
    if not pw:
        for line in Path(".env").read_text().splitlines():
            if line.startswith("BOOTSTRAP_ADMIN_PASSWORD"):
                pw = line.split("=", 1)[1].strip().strip('"')
                break
    return _login(ADMIN_EMAIL, pw)


def provision(role: str) -> tuple[str, str]:
    token = admin_token()
    email = f"vt{secrets.token_hex(3)}@example.com"
    password = secrets.token_urlsafe(16) + "!Aa1"
    body = json.dumps({"email": email, "password": password, "role": role,
                       "full_name": "Verdict Probe"}).encode()
    r = urllib.request.Request(f"{BASE}/api/users", data=body,
                               headers={"Content-Type": "application/json",
                                        "Authorization": f"Bearer {token}"})
    urllib.request.urlopen(r).read()
    return email, password


def api(path: str, token: str, method: str = "GET", body: dict | None = None):
    r = urllib.request.Request(f"{BASE}{path}", method=method,
                               data=json.dumps(body).encode() if body else None,
                               headers={"Content-Type": "application/json",
                                        "Authorization": f"Bearer {token}"})
    return json.loads(urllib.request.urlopen(r).read())


def login_ui(page, email: str, password: str):
    page.goto(BASE + "/")
    page.fill("#email", email)
    # the login form posts BOTH fields; skipping the password yields a 401
    # and #app never un-hides, so the wait times out.
    page.fill("#password", password)
    page.click("button[type=submit]")
    page.wait_for_selector("#app:not(.hidden)")


def _assert_in_viewport(locator, what: str) -> None:
    """Guard for the docs capture: a screenshot whose subject scrolled back
    out of frame is a silently broken asset, so assert the target really sits
    inside the 1440x900 capture window before we save the PNG."""
    box = locator.bounding_box()
    assert box, f"{what} not rendered"
    bottom = box["y"] + box["height"]
    assert box["y"] < 900 and bottom > 0 and box["x"] < 1440, (
        f"{what} outside the capture viewport: {box}")


def fixture_json() -> dict:
    """A line-cross fixture in the tests/replays/ format (direction -1 =
    left-to-right, matching the golden directional fixture): fires at frame 3."""
    frames = [
        {"t": 0.0, "tracks": [["t1", "person", [0.30, 0.45, 0.04, 0.08]]]},
        {"t": 0.5, "tracks": [["t1", "person", [0.38, 0.45, 0.04, 0.08]]]},
        {"t": 1.0, "tracks": [["t1", "person", [0.46, 0.45, 0.04, 0.08]]]},
        {"t": 1.5, "tracks": [["t1", "person", [0.55, 0.45, 0.04, 0.08]]]},
        {"t": 2.0, "tracks": [["t1", "person", [0.63, 0.45, 0.04, 0.08]]]},
    ]
    return {
        "camera_id": "probe-cam",
        "description": "verdict probe: L→R cross at frame 3",
        "rules": [{"type": "line_cross", "rule_id": "lc-probe",
                   "a": [0.5, 0.0], "b": [0.5, 1.0],
                   "direction": -1, "labels": ["person"]}],
        "frames": frames,
        "expect": [{"rule_type": "line_cross", "rule_id": "lc-probe",
                    "at_frame": 3}],
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    admin_email, admin_pw = provision("ADMIN")
    boot = admin_token()
    cams = api("/api/cameras", boot)
    assert cams, "probe needs at least one camera"
    cam = cams[0]
    # For the docs capture, use a dedicated throwaway camera: seeded cameras
    # may carry a legacy non-list rules shape the editor renders read-only,
    # and a fresh camera gives the editor a clean list to draw into. Removed
    # in the finally below so nothing outlives the probe on a shared server.
    docs_cam: str | None = None
    if DOCS:
        # A realistic name: this camera appears in the user-facing screenshots
        # if the detail header lands in frame, so it should read like a real
        # camera rather than exposing the probe plumbing.
        docs_cam = api("/api/cameras", boot, "POST",
                       {"name": "Back yard"})["id"]
        cam = {"id": docs_cam}
    results: dict = {}

    fx_path = Path(tempfile.mkdtemp()) / "verdict_probe_fixture.json"
    fx_path.write_text(json.dumps(fixture_json()))

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            ctx = browser.new_context(
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=bool(os.environ.get("LV_INSECURE_TLS")))
            page = ctx.new_page()
            console_errors = []

            def _on_console(m):
                if m.type == "error" and not any(f in m.text for f in _FILTERED):
                    console_errors.append(m.text[:200])

            page.on("console", _on_console)
            login_ui(page, admin_email, admin_pw)

            # ── open the camera's rules tab (deep link, same as wave 3) ──
            page.goto(f"{BASE}/#/cameras?id={cam['id']}&tab=rules")
            page.wait_for_selector("[data-role='verdict-card']", timeout=15000)
            results["card_mounted"] = True

            # ── 1. run with no fixture → honest inline error ────────────
            page.click("[data-role='verdict-card'] button.primary")
            page.wait_for_selector("[data-role='vt-error']", timeout=8000)
            results["no_fixture_error"] = (
                "fixture" in page.inner_text("[data-role='vt-error']"))

            # ── 2. pick the fixture and run (fixture rules + expect) ────
            page.set_input_files("#vt-fixture", str(fx_path))
            # untick "use editor rules" so the fixture's own rule drives the run
            page.uncheck("#vt-draft")
            page.click("[data-role='verdict-card'] button.primary")
            page.wait_for_selector("[data-role='vt-banner']", timeout=15000)
            banner = page.inner_text("[data-role='vt-banner']")
            results["verdict_banner"] = banner
            results["golden_pass"] = "PASS" in banner
            results["lanes_drawn"] = page.locator(".vt-event").count() >= 1
            results["summary_line"] = (
                page.locator("[data-role='vt-summary']").count() == 1)
            page.screenshot(path=str(OUT / "verdict_timeline.png"), full_page=True)

            # ── 2b. docs capture (opt-in): draw a zone so the editor's ──
            #    SVG overlay shows real geometry, then shoot the editor and
            #    the verdict card. Same drawing interaction as wave 3; the
            #    drawn rule stays a draft (never saved), which is exactly
            #    the "verify before you save" story the docs describe.
            if DOCS:
                page.select_option("[data-field='type']", "loitering")
                stage = page.locator("[data-role='rules-stage']")
                overlay = page.locator("[data-role='rules-overlay']")
                for fx, fy in [(0.25, 0.25), (0.72, 0.22), (0.5, 0.72)]:
                    stage.scroll_into_view_if_needed()
                    page.wait_for_timeout(150)
                    box = overlay.bounding_box()
                    if not box:
                        continue
                    page.mouse.click(box["x"] + box["width"] * fx,
                                     box["y"] + box["height"] * fy)
                    page.wait_for_timeout(180)
                page.click("[data-form='rule'] button[type=submit]")
                page.wait_for_timeout(300)
                # the Add button rejects a draft with <3 points, so a row in
                # the list is proof the zone was drawn and accepted.
                results["docs_rule_drawn"] = (
                    page.locator("[data-role='rule-list'] [data-rule]").count() >= 1)
                # let the "added" toast clear so it can't cover the shot
                page.wait_for_function(
                    "() => document.querySelectorAll('.toast').length === 0",
                    timeout=10000)
                stage.scroll_into_view_if_needed()
                page.wait_for_timeout(400)
                _assert_in_viewport(stage, "rules stage")
                DOCS.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(DOCS / "rules.png"))
                banner_el = page.locator("[data-role='vt-banner']")
                banner_el.scroll_into_view_if_needed()
                page.wait_for_function(
                    "() => document.querySelectorAll('.toast').length === 0",
                    timeout=10000)
                page.wait_for_timeout(400)
                _assert_in_viewport(banner_el, "verdict banner")
                page.screenshot(path=str(DOCS / "rules-verdict.png"))

            # ── 3. draft mode with an emptied editor → honest error ─────
            page.check("#vt-draft")
            while page.locator("[data-rule-del]").count() > 0:
                page.locator("[data-rule-del]").first.click()
                page.wait_for_timeout(150)
            page.click("[data-role='verdict-card'] button.primary")
            page.wait_for_selector("[data-role='vt-error']", timeout=8000)
            results["empty_draft_error"] = (
                "no rules" in page.inner_text("[data-role='vt-error']"))

            results["console_errors"] = console_errors
            browser.close()
    finally:
        # The docs camera is a scratch artifact; remove it so the probe
        # leaves no trace on a shared server. Best-effort: a cleanup failure
        # must never mask the verification verdict above.
        if docs_cam:
            try:
                api(f"/api/cameras/{docs_cam}", boot, "DELETE")
            except Exception as exc:
                print(f"  note: docs camera cleanup failed: {exc}")

    ok = (results.get("card_mounted") and results.get("no_fixture_error")
          and results.get("golden_pass") and results.get("lanes_drawn")
          and results.get("summary_line") and results.get("empty_draft_error")
          and not results.get("console_errors"))
    print(json.dumps(results, indent=2))
    print("VERDICT PROBE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
