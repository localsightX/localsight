#!/usr/bin/env python3
# ruff: noqa: E501  (metrics JS template is one long literal by design)
"""UI maturity scan — the instrumented sweep over the console's screen states.

For every screen state it captures:
  - a screenshot (ui_maturity/shots/)
  - computed-style telemetry (ui_maturity/metrics.json):
      typography scale, color usage, control sizes, table semantics,
      focus targets, form labeling, timestamps/timezone, toasts, nav depth

READ-ONLY against the app: no data is created, mutated, or deleted. It
logs in as the seeded demo admin (read-only journey) so the demo DB
stays pristine for the live demo.

Usage:
  LV_BASE=http://localhost:8779 python scripts/ui_maturity_scan.py

(E501 is suppressed file-wide: the metrics payload is one long JS
template literal kept unbroken on purpose — it ships to the browser as
a unit and wrapping it would obscure the query.)
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("LV_BASE", "http://localhost:8779")
EMAIL = os.environ.get("LV_SCAN_USER", "admin@localsight.local")
PASSWORD = os.environ.get("LV_SCAN_PASSWORD", "Demo-Admin-2026!")
OUT = Path("ui_maturity")
SHOTS = OUT / "shots"

# ── states: (id, nav-view or None, extra reach steps) ─────────────────────
def _st(state_id, view=None, click=None, wait=None, click2=None,
        wait2=None, settle=None, key=None):
    """Build one state record (kept short per-line for lint)."""
    d = {"id": state_id}
    if view:
        d["view"] = view
    if key:
        d["key"] = key
    if click:
        d["click"] = click
    if wait:
        d["wait"] = wait
    if click2:
        d["click2"] = click2
    if wait2:
        d["wait2"] = wait2
    if settle:
        d["settle"] = settle
    return d


CAM = ".cam-card [data-act='detail']"
STATES: list[dict] = [
    _st("login"),
    _st("dashboard", view="dashboard"),
    _st("live", view="live", settle=2500),
    _st("cameras", view="cameras"),
    _st("camera-detail", view="cameras", click=CAM, wait=".cam-detail"),
    _st("camera-masks", view="cameras", click=CAM, wait=".cam-detail",
        click2="[data-tab='masks']", wait2=".mask-editor"),
    _st("camera-rules", view="cameras", click=CAM, wait=".cam-detail",
        click2="[data-tab='rules']", wait2="[data-role='rule-list']"),
    _st("events", view="events"),
    _st("event-drawer", view="events", click="tr.event-row",
        wait=".drawer:not(.hidden)"),
    _st("timeline", view="timeline"),
    _st("analytics", view="analytics", settle=1500),
    _st("people", view="people"),
    _st("person-detail", view="people", click="[data-person] a, [data-person] button",
        wait="[data-refs], .person-detail, [data-role=refs]"),
    _st("alerts", view="alerts", settle=1200),
    _st("route-editor", view="alerts", click="#route-add",
        wait="[data-form='route-new']"),
    _st("users", view="users"),
    _st("user-editor", view="users", click="[data-act='user-add']",
        wait="[data-act='user-create']"),
    _st("privacy", view="privacy"),
    _st("audit", view="audit"),
    # M2: the account story — self-service security
    _st("account", view="account", wait="[data-view-root='account']", settle=800),
    # M3/E-12: the command palette (Ctrl-K)
    _st("palette", view="dashboard", key="Control+k", wait=".palette", settle=900),
]

# metrics harvested from the live DOM (pure reads)
METRIC_JS = """() => {
  const px = (v) => parseFloat(v) || 0;
  const txt = (sel) => { const el = document.querySelector(sel); return el ? el.textContent.trim().slice(0, 200) : null; };
  const out = {};
  // typography scale across visible headings + body
  const sizes = new Set();
  for (const el of document.querySelectorAll('h1,h2,h3,h4,p,td,th,button,a,dt,dd,label')) {
    const cs = getComputedStyle(el);
    if (cs.display !== 'none') sizes.add(`${cs.fontSize}/${cs.fontWeight}`);
  }
  out.type_scale = [...sizes].sort();
  // distinct background colors actually used (design-token discipline)
  const bgs = new Set(), fgs = new Set();
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    if (el.children.length === 0 || el.matches('button,a,input,section,div.card,header')) {
      bgs.add(cs.backgroundColor); fgs.add(cs.color);
    }
  }
  out.bg_colors = [...bgs].slice(0, 40);
  out.fg_colors = [...fgs].slice(0, 40);
  // control metrics: min/median heights of interactive elements
  const ctrls = [...document.querySelectorAll('button,a.btn,button.primary,button.ghost,[role=button],input,select,textarea')]
    .filter(el => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; })
    .map(el => { const r = el.getBoundingClientRect(); return {t: el.tagName.toLowerCase(), h: +r.height.toFixed(1), w: +r.width.toFixed(1)}; });
  out.controls = {count: ctrls.length,
    min_h: ctrls.length ? Math.min(...ctrls.map(c => c.h)) : null,
    heights: ctrls.map(c => c.h)};
  // table semantics
  const tables = [...document.querySelectorAll('table')];
  out.tables = tables.map(t => ({
    headers: [...t.querySelectorAll('th')].map(th => th.textContent.trim().slice(0, 24)),
    aria_sort: [...t.querySelectorAll('th')].some(th => th.getAttribute('aria-sort')),
    row_count: t.querySelectorAll('tbody tr').length,
    caption: t.querySelector('caption') ? true : false,
  }));
  // pagination / bulk / filter affordances (M-wave regression probes)
  out.affordances = {
    pagination_text: txt('#ev-pages, [data-role=pagination]'),
    bulk_checkbox: !!document.querySelector("input[type=checkbox][data-bulk], th input[type=checkbox]"),
    sort_indicators: [...document.querySelectorAll('[data-sort], .sort-arrow, th[onclick]')].length,
    // M1/E-1: real sortable headers carry aria-sort
    sortable_th: [...document.querySelectorAll('th[aria-sort]')].length,
    filter_inputs: [...document.querySelectorAll('select,input[type=search],input.filter')].length,
    export_buttons: [...document.querySelectorAll('[data-act*=export],[data-export],#ev-export,#au-export')].length,
    timezone_labels: [...document.querySelectorAll('*')].filter(el => /UTC|GMT|[+-]\\d{2}:\\d{2}/.test(el.textContent)).length,
    // M2/E-5/E-6/E-13: self-service security affordances
    mfa_enroll: !!document.querySelector("[data-act='mfa-setup'],[data-act='mfa-verify']"),
    password_form: !!document.querySelector("[data-form='pw-change']"),
    session_rows: document.querySelectorAll("[data-session]").length,
    tz_picker: !!document.querySelector("[data-field='tz']"),
    // M3/E-3/E-8/E-9/E-10: density, bulk, feedback host, labelled drawer
    bulk_boxes: document.querySelectorAll("[data-bulk]").length,
    toast_host: !!document.getElementById("toast"),
    copy_link: [...document.querySelectorAll("#ev-link,#au-link,[data-act='an-link']")].length,
    drawer_labelled: (() => {
      const d = document.querySelector(".drawer");
      return d ? (d.getAttribute("aria-labelledby") || "") : "";
    })(),
    palette_wired: !!document.querySelector(".palette"),
  };
  // forms: labeled vs orphan controls
  const inputs = [...document.querySelectorAll('input:not([type=hidden]),select,textarea')];
  out.forms = {
    input_count: inputs.length,
    labeled: inputs.filter(i => (i.labels && i.labels.length) || i.getAttribute('aria-label') || i.getAttribute('aria-labelledby')).length,
    placeholder_only: inputs.filter(i => i.placeholder && !((i.labels && i.labels.length) || i.getAttribute('aria-label'))).length,
  };
  // timestamps: how many, any tz indicator
  out.dates = {
    iso_count: (document.body.textContent.match(/\\d{4}-\\d{2}-\\d{2}/g) || []).length,
    clock_count: (document.body.textContent.match(/\\d{2}:\\d{2}:\\d{2}/g) || []).length,
    tz_hint: /UTC|GMT|[+-]\\d{2}:\\d{2}/.test(document.body.textContent),
  };
  // focus visibility: outline on the active nav button when focused
  const navBtn = document.querySelector('#nav button.active');
  out.focus = navBtn ? (() => { const cs = getComputedStyle(navBtn); return {outline: cs.outlineWidth, style: cs.outlineStyle}; })() : null;
  // empty-state / skeleton / error-state presence (honest-state pattern)
  out.states = {
    skeletons: document.querySelectorAll('.skeleton, [class*=skeleton]').length,
    empty_states: [...document.querySelectorAll('*')].filter(el => /no |nothing|yet|unavailable/i.test(el.textContent || '') && el.children.length === 0).length,
  };
  // toast host (non-blocking feedback)
  out.toast_host = !!document.querySelector('#toast, .toast-host, [data-role=toasts]');
  // dialog/drawer semantics
  const drawer = document.querySelector('.drawer:not(.hidden)');
  out.drawer = drawer ? {
    role: drawer.getAttribute('role'),
    aria_label: drawer.getAttribute('aria-label'),
    aria_modal: drawer.getAttribute('aria-modal'),
    focus_trap: !!drawer.querySelector('[tabindex]'),
  } : null;
  // main/landmarks + h1
  out.landmarks = {
    main: !!document.querySelector('main'),
    nav: !!document.querySelector('nav, [role=navigation]'),
    header: !!document.querySelector('header, [role=banner]'),
    h1: !!document.querySelector('h1'),
  };
  // keyboard-shortcut discoverability
  out.shortcut_overlay = !!document.querySelector('.shortcut-card, [data-role=shortcuts]');
  // density / responsive toggles
  out.density_toggle = !!document.querySelector('#density-toggle');
  // per-view canonical title
  out.view_title = txt('#panel-title, header h2, .panel:not(.hidden) h2');
  return out;
}"""


def reach(page, st):
    if st["id"] == "login":
        page.goto(f"{BASE}/")
        page.wait_for_selector("#login:not(.hidden)")
        return
    page.click(f"#nav button[data-view='{st['view']}']")
    if "settle" in st:
        page.wait_for_timeout(st["settle"])
    if "click" in st:
        page.locator(st["click"]).first.click()
        if "wait" in st:
            page.wait_for_selector(st["wait"], timeout=8000)
    if "click2" in st:
        page.locator(st["click2"]).first.click()
        if "wait2" in st:
            page.wait_for_selector(st["wait2"], timeout=8000)
    if "key" in st:
        page.keyboard.press(st["key"])
        if "wait" in st:
            page.wait_for_selector(st["wait"], timeout=8000)
    page.wait_for_timeout(600)


def main() -> int:
    SHOTS.mkdir(parents=True, exist_ok=True)
    metrics = {}
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1440, "height": 900})
        pg.goto(f"{BASE}/")
        pg.wait_for_selector("#login:not(.hidden)")
        # login state is scanned first (pre-auth)
        for st in STATES:
            t0 = time.time()
            if st["id"] != "login" and not pg.locator("#app:not(.hidden)").count():
                pg.fill("#email", EMAIL)
                pg.fill("#password", PASSWORD)
                pg.click("button[type=submit]")
                pg.wait_for_selector("#app:not(.hidden)")
            # (login handled inline above)
            # from second state on, close any drawer left open first
            if (st["id"] != "login" and st.get("view")
                    and pg.locator(".drawer:not(.hidden)").count()):
                pg.keyboard.press("Escape")
                pg.wait_for_timeout(300)
            reach(pg, st)
            m = pg.evaluate(METRIC_JS)
            m["_seconds"] = round(time.time() - t0, 2)
            metrics[st["id"]] = m
            pg.screenshot(path=str(SHOTS / f"{st['id']}.png"), animations="disabled")
            print(f"  scanned {st['id']:16s} ({m['_seconds']}s)")
            if st["id"] == "login":
                pg.fill("#email", EMAIL)
                pg.fill("#password", PASSWORD)
                pg.click("button[type=submit]")
                pg.wait_for_selector("#app:not(.hidden)")
        b.close()
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nwrote {OUT}/metrics.json + {len(metrics)} screenshots to {SHOTS}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
