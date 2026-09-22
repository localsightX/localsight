// Verdict timeline (R3.5 follow-up) — visualize a rule replay in the browser.
//
// POST /api/rules/test runs a frame fixture through the REAL RuleEngine and
// returns { timeline (verdict trace), events, summary, pass?, expect_errors? }.
// This card turns that response into a CSP-safe SVG: one lane per rule,
// decision marks along the frame axis (fired vs suppressed), fire markers,
// and the golden-replay verdict banner.
//
// Frames come from a fixture file picked locally (the tests/replays/ JSON
// format — camera_id, rules?, frames, expect?) — the API is dry-run only and
// never persists, so testing a draft costs nothing. By default the card
// replays the EDITOR'S current draft rules (unsaved edits included), which is
// the whole point: verify before you save.
//
// CSP rules honored: no inline styles, no innerHTML — geometry via SVG
// x/width attributes, DOM via h()/svgEl() only.

import { h, render, svgEl } from "../core/dom.js";
import { api } from "../core/api.js";
import { toast } from "../core/toast.js";

const LANE_H = 18;
const LANE_GAP = 6;
const SVG_H_PAD = 22;

// Decisions that mean "this frame would have fired but something stopped it".
const BLOCKED = new Set(["cooldown_blocked", "min_dwell_warming", "not_crossed",
  "no_zone_hit", "below_threshold", "hysteresis_skip"]);

export function verdictCard(cam, getRules) {
  let result = null;
  let lastError = null;

  const out = h("div", { "data-role": "verdict-out", "aria-live": "polite" });
  const fileInput = h("input", {
    id: "vt-fixture", type: "file", accept: ".json,application/json",
  });
  const useDraft = h("input", { id: "vt-draft", type: "checkbox", checked: true });
  const runBtn = h("button", { class: "primary", type: "button" }, "Run replay");

  function banner() {
    if (lastError) {
      return h("p", { class: "confirm-zone", "data-role": "vt-error" },
        `Replay failed: ${lastError}`);
    }
    if (!result) return null;
    const hasExpect = Object.prototype.hasOwnProperty.call(result, "pass");
    if (!hasExpect) {
      return h("p", { class: "pill info", "data-role": "vt-banner" },
        `Dry run — ${result.summary?.total_events ?? 0} fire(s) across ${result.frames} frames (no expect block)`);
    }
    const cls = result.pass ? "pill ok" : "pill danger";
    const text = result.pass ? "Golden replay PASS" : "Golden replay FAIL";
    const errs = (result.expect_errors || []).slice(0, 4).join(" · ");
    return h("p", { class: cls, "data-role": "vt-banner" },
      errs ? `${text} — ${errs}` : text);
  }

  function draw() {
    const kids = [banner()];
    if (result) {
      const trace = result.timeline || [];
      const events = result.events || [];
      const nFrames = Math.max(result.frames, 1);
      // One lane per rule that appears in the trace or events, first-seen
      // order, labelled "type/id" (the id is what the operator picked).
      const lanes = [];
      const laneOf = new Map();
      for (const e of [...trace, ...events]) {
        const key = `${e.rule_type}/${e.rule_id}`;
        if (!laneOf.has(key)) {
          laneOf.set(key, lanes.length);
          lanes.push({ key });
        }
      }
      const W = Math.max(nFrames, 60); // 1 unit = 1 frame
      const H = SVG_H_PAD + lanes.length * (LANE_H + LANE_GAP);
      const svg = svgEl("svg", {
        class: "tl-svg", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none",
        role: "img", "aria-label": "Rule replay verdict timeline",
      });
      for (let f = 0; f <= nFrames; f += Math.max(1, Math.round(nFrames / 10))) {
        svg.append(svgEl("line", { class: "vt-grid", x1: f, y1: 0, x2: f, y2: H }));
      }
      lanes.forEach((ln, i) => {
        const y = SVG_H_PAD + i * (LANE_H + LANE_GAP);
        svg.append(svgEl("rect",
          { class: "tl-track", x: 0, y, width: W, height: LANE_H, rx: 2 }));
        const lbl = svgEl("text", { class: "vt-lane-label", x: 2, y: y + LANE_H - 5 });
        lbl.textContent = ln.key;
        svg.append(lbl);
      });
      for (const e of trace) {
        const i = laneOf.get(`${e.rule_type}/${e.rule_id}`);
        const y = SVG_H_PAD + i * (LANE_H + LANE_GAP);
        const fired = e.decision === "fired";
        svg.append(svgEl("rect", {
          class: fired ? "vt-fired" : (BLOCKED.has(e.decision) ? "vt-blocked" : "vt-other"),
          x: Math.max(0, e.frame), y: y + 4, width: 1.5, height: LANE_H - 8,
        }, svgEl("title", {},
          `f${e.frame} ${e.decision}${e.track_id ? ` [${e.track_id}]` : ""}`)));
      }
      for (const ev of events) {
        const i = laneOf.get(`${ev.rule_type}/${ev.rule_id}`);
        const y = SVG_H_PAD + i * (LANE_H + LANE_GAP);
        svg.append(svgEl("circle", {
          class: "vt-event", cx: Math.max(0, ev.frame) + 0.75,
          cy: y + LANE_H / 2, r: 3,
        }, svgEl("title", {},
          `f${ev.frame} FIRED ${ev.rule_type}${ev.detail?.direction ? ` (${ev.detail.direction})` : ""}`)));
      }
      kids.push(svg);
      const s = result.summary || {};
      const counts = Object.entries(s.fired_by_rule || {})
        .map(([k, v]) => `${k}×${v}`).join(", ");
      kids.push(h("p", { class: "muted text-xs", "data-role": "vt-summary" },
        `${s.total_events ?? 0} fire(s): ${counts || "none"} · trace entries: ${trace.length}${result.truncated ? " (truncated at cap)" : ""}`));
    }
    render(out, kids);
  }

  return { out, fileInput, useDraft, runBtn, draw,
    setError(msg) { lastError = msg; draw(); },
    setResult(r) { result = r; draw(); } };
}

/** Full card: fixture picker + run button + timeline, wired to POST /api/rules/test. */
export function verdictTimelineCard(cam, getRules) {
  const t = verdictCard(cam, getRules);
  const runBtn = t.runBtn;

  async function run() {
    t.setError(null);
    let fx = null;
    const file = t.fileInput.files && t.fileInput.files[0];
    if (file) {
      try {
        fx = JSON.parse(await file.text());
      } catch {
        t.setError("fixture file is not valid JSON");
        return;
      }
    }
    if (!fx || !Array.isArray(fx.frames) || !fx.frames.length) {
      t.setError("pick a fixture JSON with a non-empty frames array");
      return;
    }
    // Rules source: the editor's live draft (default — verify before save) or
    // the fixture's own rules block.
    const rules = t.useDraft.checked ? getRules() : (fx.rules || []);
    if (!Array.isArray(rules) || !rules.length) {
      t.setError(useDraftText(t.useDraft.checked));
      return;
    }
    runBtn.disabled = true;
    runBtn.textContent = "Replaying…";
    try {
      t.setResult(await api("/api/rules/test", {
        method: "POST",
        body: JSON.stringify({
          camera_id: cam.id, rules, frames: fx.frames,
          expect: Array.isArray(fx.expect) ? fx.expect : undefined,
        }),
      }));
    } catch (err) {
      t.setError(err.message || "replay request failed");
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = "Run replay";
    }
  }

  function useDraftText(checked) {
    return checked
      ? "no rules in the editor — add one first (or untick \"use editor rules\")"
      : "fixture carries no rules";
  }

  runBtn.addEventListener("click", run);

  return h("div", { class: "card", "data-role": "verdict-card" },
    h("h3", {}, "Replay & verdict"),
    h("p", { class: "muted text-xs" },
      "Pick a fixture JSON (tests/replays/ format) and run it against the editor's current rules — nothing is saved or alerted."),
    h("div", { class: "form-row" },
      h("label", { class: "field-hint", for: "vt-fixture" }, "Fixture JSON", t.fileInput),
      h("label", { class: "field-hint", for: "vt-draft" }, t.useDraft, " Use editor's current rules"),
      runBtn),
    t.out,
  );
}
