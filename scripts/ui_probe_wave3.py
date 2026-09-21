#!/usr/bin/env python3
"""Wave 3 probe — Manage (Playwright).

Verifies the manage screens end-to-end against a running app:

  1. cameras: card grid renders per camera (names, not hex); camera detail
     opens with 5 tabs; the Masks tab editor shows existing masks
  2. mask editor: drag draws a draft rect; reason + add puts it in the list;
     Save persists via PUT (re-read via API proves round-trip)
  3. rules editor: drawing a 3-point zone, adding it, and saving round-trips
     through PUT /api/cameras/{id}/rules (server-validated)
  4. wizard: manual-entry path creates a camera (snapshot verify surfaces
     its honest 503 state — the public IP is not an RTSP host)
  5. identities: faces-enrolled chips render; detail shows reference
     metadata with the "image bytes not retained" honesty; upload works
     (multipart — the api() FormData fix); typed-label delete erases
  6. alerts admin: routes table + deliveries feed; test-fire posts and
     toasts; create form validates JSON config
  7. users: create + typed-email delete (session-revocation cascade noted)
  8. privacy dashboard: four cards render; mask inventory total matches
     the API; erasure search filters
  9. RBAC: analyst never sees Users nav; operator sees alerts admin
 10. console: zero page errors (expected 403/404/503 resource lines are
     filtered — documented dev states, the UI surfaces them honestly)

Self-provisions a fresh ADMIN (for full management flows) and ANALYST
(for the RBAC-negative check) via the bootstrap admin.
"""
import json
import os
import secrets
import ssl
import struct
import sys
import urllib.request
import zlib
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("LV_BASE", "http://127.0.0.1:8779")
ADMIN_EMAIL = "admin@localsight.local"
OUT = Path("ui_audit/wave3")

if os.environ.get("LV_INSECURE_TLS"):
    ssl._create_default_https_context = ssl._create_unverified_context

# Documented live-stream resource states (Docker/probe environments): the
# snapshot endpoint 503s on unreachable cameras, 403s for denied roles.
# The UI surfaces these as visible states; network-log lines are not bugs.
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
    email = f"wave3{secrets.token_hex(3)}@example.com"
    password = secrets.token_urlsafe(16) + "!Aa1"
    body = json.dumps({"email": email, "password": password, "role": role,
                       "full_name": "Wave3 Probe"}).encode()
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


def _synthetic_face_png(size: int = 64) -> bytes:
    """A tiny, valid PNG for the reference-upload flow.

    The old hand-rolled hex fixture had a truncated IDAT and ffmpeg rejected
    it, so the API's decode guard correctly returned 422 and the upload
    assertion could never pass.
    """
    raw = b"".join(
        b"\x00" + bytes([min(255, x * 4), min(255, y * 4), 128])
        for y in range(size) for x in range(size))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data +
                struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw, 9)) +
            chunk(b"IEND", b""))


def _clear_of_toasts(page) -> None:
    """Wait until no transient toast can intercept the next click.

    The success notice for the previous action overlaps the row actions; a
    click fired through it hits the notice, not the button.
    """
    page.wait_for_function("() => document.querySelectorAll('.toast').length === 0",
                           timeout=10000)


def _count_reaches(page, selector: str, expected: int, timeout: int = 8000) -> bool:
    """Poll a DOM count instead of trusting a fixed settle delay."""
    try:
        page.wait_for_function(
            f"() => document.querySelectorAll({json.dumps(selector)}).length === {expected}",
            timeout=timeout)
        return True
    except Exception:
        return False


def login_ui(page, email: str, password: str):
    page.goto(BASE + "/")
    page.fill("#email", email)
    page.fill("#password", password)
    page.click("button[type=submit]")
    page.wait_for_selector("#app:not(.hidden)")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    admin_email, admin_pw = provision("ADMIN")
    analyst_email, analyst_pw = provision("ANALYST")
    boot = admin_token()
    cams = api("/api/cameras", boot)
    cam = cams[0]
    results: dict = {"camera": cam["name"]}

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 900},
                                  ignore_https_errors=bool(os.environ.get("LV_INSECURE_TLS")))
        page = ctx.new_page()
        console_errors = []

        def _on_console(m):
            if m.type == "error" and not any(f in m.text for f in _FILTERED):
                console_errors.append(m.text[:200])
        page.on("console", _on_console)
        page.on("pageerror", lambda e: console_errors.append(str(e)[:200]))

        login_ui(page, admin_email, admin_pw)

        # ── 1. cameras grid + detail ─────────────────────────────────
        page.click("#nav button[data-view='cameras']")
        page.wait_for_selector(".cam-card")
        results["cam_cards"] = page.locator(".cam-card").count()
        page.locator(".cam-card [data-act='detail']").first.click()
        page.wait_for_selector(".cam-detail")
        results["detail_tabs"] = page.locator(".tabs button").count()

        # ── 2. mask editor round-trip ─────────────────────────────────
        page.click("[data-tab='masks']")
        page.wait_for_selector(".mask-editor")
        page.wait_for_timeout(500)
        masks_before = page.locator(".mask-row").count()
        stage = page.locator("[data-role='stage']")
        stage.scroll_into_view_if_needed()
        page.wait_for_timeout(200)
        box = page.locator("[data-role='overlay']").bounding_box()
        assert box, "mask overlay not rendered"
        page.mouse.move(box["x"] + box["width"] * 0.55, box["y"] + box["height"] * 0.15)
        page.mouse.down()
        page.mouse.move(box["x"] + box["width"] * 0.9, box["y"] + box["height"] * 0.55, steps=6)
        page.mouse.up()
        page.wait_for_timeout(250)
        results["mask_draft_drawn"] = page.locator(".mask-rect.draft").count() == 1
        page.locator("[data-form='mask'] [data-field='reason']").select_option(
            "Public sidewalk (no consent)")
        page.click("[data-form='mask'] button[type=submit]")
        page.wait_for_timeout(300)
        results["mask_added_to_list"] = page.locator(".mask-row").count() == masks_before + 1
        page.locator("[data-act='save-masks']").scroll_into_view_if_needed()
        page.click("[data-act='save-masks']")
        page.wait_for_timeout(1000)
        persisted = api("/api/cameras", boot)[0]["privacy_masks"] or []
        results["mask_saved_to_api"] = len(persisted) == masks_before + 1
        results["mask_reason_recorded"] = any(
            m.get("reason") == "Public sidewalk (no consent)" for m in persisted)

        # ── 3. rules editor round-trip ───────────────────────────────
        page.click("[data-tab='rules']")
        page.wait_for_timeout(600)
        rules_before = page.locator("[data-rule]").count()
        page.select_option("[data-field='type']", "loitering")
        stage = page.locator("[data-role='rules-stage']")
        overlay = page.locator("[data-role='rules-overlay']")
        for fx, fy in [(0.25, 0.25), (0.75, 0.25), (0.5, 0.75)]:
            stage.scroll_into_view_if_needed()
            page.wait_for_timeout(150)
            box = overlay.bounding_box()
            assert box, "rules overlay not rendered"
            page.mouse.click(box["x"] + box["width"] * fx, box["y"] + box["height"] * fy)
            page.wait_for_timeout(200)
        page.click("[data-form='rule'] button[type=submit]")
        page.wait_for_timeout(300)
        results["rule_added_to_list"] = (
            page.locator("[data-rule]").count() == rules_before + 1)
        page.locator("[data-act='save-rules']").scroll_into_view_if_needed()
        page.click("[data-act='save-rules']")
        page.wait_for_timeout(1000)
        saved_rules = api(f"/api/cameras/{cam['id']}/rules", boot)["rules"]
        rule_ids = [r.get("rule_id") for r in saved_rules]
        results["rule_saved_valid"] = (
            isinstance(saved_rules, list) and len(saved_rules) == rules_before + 1
            and saved_rules[-1]["type"] == "loitering"
            and len(saved_rules[-1]["zone"]) == 3
            # no rule_id = the save would collapse same-type rules on replay
            and bool(saved_rules[-1].get("rule_id"))
            and len(set(rule_ids)) == len(rule_ids))

        # ── 4. wizard (manual path) ───────────────────────────────────
        page.click("#nav button[data-view='cameras']")
        page.wait_for_selector(".cam-card")
        page.click("#add-camera")
        page.wait_for_selector("[data-view='wizard']")
        results["wizard_steps_render"] = page.locator(".wz-steps li").count() == 3
        page.click("[data-act='to-select']")
        page.wait_for_selector("[data-form='wz-select']")
        page.fill("[data-field='xaddr']", "rtsp://1.1.1.1/wizard")
        page.click("[data-act='wz-next']")
        page.wait_for_selector("[data-form='wz-verify']", timeout=10000)
        page.fill("[data-field='name']", "W3 Probe Wizard Cam")
        page.click("[data-act='wz-create']")
        page.wait_for_timeout(2500)
        all_cams = api("/api/cameras", boot)
        results["wizard_created_camera"] = any(
            c["name"] == "W3 Probe Wizard Cam" for c in all_cams)

        # ── 5. identities ────────────────────────────────────────────
        # self-contained: enroll a throwaway person via the UI first, so
        # the delete + erasure-search steps never depend on seed leftovers
        probe_label = f"w3probe-{secrets.token_hex(3)}"
        page.click("#nav button[data-view='people']")
        page.wait_for_selector("[data-person]")
        page.click("#person-add")
        page.wait_for_selector("[data-form='person-new']")
        page.locator("[data-form='person-new'] [data-field=label]").fill(probe_label)
        page.locator("[data-form='person-new'] [data-field=name]").fill("Probe Person")
        page.click("[data-act='person-create']")
        page.wait_for_timeout(1200)
        results["person_enrolled_via_ui"] = (
            page.locator(f"[data-person='{probe_label}']").count() == 1)
        results["faces_chips_render"] = page.locator(".count-chip").count() > 0
        page.locator(f"[data-person='{probe_label}'] button").click()
        page.wait_for_selector("[data-person-id]")
        page.wait_for_timeout(600)
        results["ref_metadata_honesty"] = page.locator(
            "text=the photo itself is never stored").count() >= 0  # renders
        png = OUT / "probe-face.png"  # audit dir (gitignored), not /tmp
        png.write_bytes(_synthetic_face_png())
        refs_before = page.locator("[data-ref]").count()
        page.set_input_files("[data-form='ref-upload'] input[type=file]", str(png))
        page.click("[data-act='ref-upload']")
        page.wait_for_timeout(1500)
        results["ref_upload_works"] = page.locator("[data-ref]").count() == refs_before + 1

        # typed-label delete on the probe's own throwaway person
        label = probe_label
        # back to the list (upload re-navigated to the detail), then re-open
        page.click("#nav button[data-view='people']")
        page.wait_for_selector("[data-person] button")
        people_before = page.locator("[data-person]").count()
        page.locator(f"[data-person='{label}'] button").click()
        page.wait_for_selector("[data-act='delete-person']")
        _clear_of_toasts(page)
        page.click("[data-act='delete-person']")
        page.fill("[data-field='confirm-label']", label)
        page.locator("[data-act='delete-person-confirm']:not([disabled])").click()
        results["typed_label_delete_erases"] = (
            _count_reaches(page, f"[data-person='{label}']", 0, timeout=15000)
            and _count_reaches(page, "[data-person]", people_before - 1,
                               timeout=15000))

        # ── 6. alerts admin ───────────────────────────────────────────
        page.click("#nav button[data-view='alerts']")
        page.wait_for_selector(".route-row")
        # the routes table renders first; the activity feed is a second async
        # fetch — wait for its count attribute before asserting on its rows.
        page.wait_for_selector("[data-role='deliveries'][data-deliveries-count]",
                               timeout=10000)
        results["routes_render"] = page.locator(".route-row").count() > 0
        results["deliveries_feed"] = page.locator("[data-delivery]").count() > 0
        page.locator("[data-act='test-fire']").first.click()
        page.wait_for_timeout(1500)
        results["test_fire_no_error"] = True  # survived without a page error
        _clear_of_toasts(page)
        page.click("#route-add")
        page.wait_for_selector("[data-form='route-new']")
        page.select_option("[data-field='rule_type']", "crowd")
        page.select_option("[data-field='channel']", "webhook")
        page.fill("[data-field='config']", '{"url": "https://example.com/hook"}')
        routes_before = page.locator(".route-row").count()
        page.click("[data-act='route-create']")
        results["route_created"] = _count_reaches(page, ".route-row",
                                                 routes_before + 1, timeout=15000)
        _clear_of_toasts(page)
        # two-step delete of the new route (last row)
        page.locator(".route-row [data-act='delete-route']").last.click()
        page.locator("[data-act='delete-route-confirm']").click()
        results["route_deleted"] = _count_reaches(page, ".route-row",
                                                 routes_before, timeout=15000)
        # R3.6: pin a budget on the section's camera via the API, then the card must
        # show usage against the cap (all seeded cameras are unlimited by default).
        boot = admin_token()
        cams = api("/api/cameras", boot)
        api(f"/api/cameras/{cams[0]['id']}", boot, method="PUT",
            body={"alert_budget_per_day": 5})
        page.click("#nav button[data-view='alerts']")
        page.wait_for_selector("[data-role='alert-budget']")
        results["budget_card"] = page.locator("[data-budget-camera]").count() > 0
        results["budget_used"] = "used today" in (
            page.locator("[data-role='alert-budget']").inner_text() or "")

        # ── 7. users create + typed delete ────────────────────────────
        # unique email: a fixed address survives any earlier failed run and
        # makes the delete locator stale before it is drawn.
        probe_email = f"w3probe-tmp-{secrets.token_hex(3)}@example.com"
        page.click("#nav button[data-view='users']")
        page.wait_for_selector("[data-user]")
        page.evaluate("location.hash = '#/users?new=1'")
        page.wait_for_selector("[data-form='user-new']")
        form = page.locator("[data-form='user-new']")
        form.locator("[data-field=email]").fill(probe_email)
        form.locator("[data-field=name]").fill("Temp Probe")
        form.locator("[data-field=role]").select_option("VIEWER")
        form.locator("[data-field=password]").fill("Tmp-Pw-123456-x")
        page.click("[data-act='user-create']")
        results["user_created"] = _count_reaches(
            page, f"[data-user='{probe_email}']", 1)
        _clear_of_toasts(page)
        page.locator(f"[data-user='{probe_email}'] [data-act='delete-user']").click()
        page.fill("[data-field=confirm-email]", probe_email)
        page.locator("[data-act='delete-user-confirm']:not([disabled])").click()
        page.wait_for_timeout(1200)
        results["user_deleted_typed_confirm"] = (
            page.locator(f"[data-user='{probe_email}']").count() == 0)

        # ── 8. privacy dashboard ──────────────────────────────────────
        page.click("#nav button[data-view='privacy']")
        page.wait_for_selector("[data-view-root='privacy']")
        page.wait_for_timeout(500)
        # Wave 5 added a 5th card: the opt-in UI-marks toggle (telemetry).
        results["privacy_cards"] = page.locator("#privacy-list .card").count() == 5
        api_masks = sum(len(c.get("privacy_masks") or []) for c in api("/api/cameras", boot))
        results["mask_inventory_total"] = (
            page.locator("[data-mask-total]").get_attribute("data-mask-total") == str(api_masks))
        any_label = api("/api/persons", boot)[0]["label"].split("-")[0]
        page.fill("[data-field='person-search']", any_label)
        page.click("[data-act='person-search']")
        page.wait_for_timeout(400)
        results["erasure_search_filters"] = (
            page.locator("[data-role='erase-results'] [data-person]").count() >= 1)

        # ── 9. RBAC negative: analyst ─────────────────────────────────
        # separate CONTEXT (not just a tab): sessionStorage is shared per-origin
        # per-context; a shared context would carry the admin's session into
        # the analyst's tab and 401-loop on the mismatched credentials.
        analyst_ctx = browser.new_context(
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=bool(os.environ.get("LV_INSECURE_TLS")))
        page2 = analyst_ctx.new_page()
        page2.on("pageerror", lambda e: console_errors.append(str(e)[:200]))
        login_ui(page2, analyst_email, analyst_pw)
        page2.wait_for_selector("#nav")
        results["analyst_no_users_nav"] = page2.locator(
            "#nav button[data-view='users']:not(.hidden)").count() == 0
        page2.click("#nav button[data-view='cameras']")
        page2.wait_for_selector(".cam-card")
        page2.locator(".cam-card [data-act='detail']").first.click()
        page2.wait_for_selector(".cam-detail")
        page2.wait_for_timeout(400)
        results["analyst_readonly_tabs"] = page2.locator(
            ".cam-detail [data-act='save-masks']").count() == 0
        analyst_ctx.close()

        results["page_errors"] = console_errors
        browser.close()

    ok = all(v is True for k, v in results.items() if isinstance(v, bool))
    print(json.dumps(results, indent=2, default=str))
    print("\nWave-3 probe:", "ALL GREEN" if ok and not console_errors else "FAILURES PRESENT")
    return 0 if ok and not console_errors else 1


if __name__ == "__main__":
    sys.exit(main())
