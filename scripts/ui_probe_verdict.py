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
    page.click("button[type=submit]")
    page.wait_for_selector("#app:not(.hidden)")


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
    results: dict = {}

    fx_path = Path(tempfile.mkdtemp()) / "verdict_probe_fixture.json"
    fx_path.write_text(json.dumps(fixture_json()))

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

    ok = (results.get("card_mounted") and results.get("no_fixture_error")
          and results.get("golden_pass") and results.get("lanes_drawn")
          and results.get("summary_line") and results.get("empty_draft_error")
          and not results.get("console_errors"))
    print(json.dumps(results, indent=2))
    print("VERDICT PROBE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
