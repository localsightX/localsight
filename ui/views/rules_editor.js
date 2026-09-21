// Rules editor — per-type forms with inline validation (Wave 3).
//
// Rule specs mirror packages/ai/rules.py rule_from_dict():
//   line_cross: {a:[x,y], b:[x,y], direction?} — a/b in 0..1 video coords
//   intrusion:  {zone:[[x,y]…], min_dwell_sec?}
//   loitering:  {zone, dwell_sec (default 30)}
//   object_left:{zone, stationary_sec (default 30)}
//   crowd:      {zone, threshold (default 10)}
// PUT /api/cameras/{id}/rules re-validates server-side; the 400 detail names
// the first bad rule. The editor validates client-side too so most mistakes
// never leave the form.

import { h, render, svgEl } from "../core/dom.js";
import { api, can } from "../core/api.js";
import { toast } from "../core/toast.js";
import { navigate } from "../core/router.js";

const TYPES = [
  { id: "line_cross", label: "Line crossing", geometry: "line", needs: { a: true, b: true },
    hint: "Fires when a track crosses the drawn line (optionally one direction)." },
  { id: "intrusion", label: "Zone intrusion", geometry: "zone", needs: { zone: true },
    hint: "Fires when a track enters the polygon (with optional minimum dwell)." },
  { id: "loitering", label: "Loitering", geometry: "zone", needs: { zone: true, dwell_sec: true },
    hint: "Fires when a track stays inside the zone longer than the dwell time." },
  { id: "object_left", label: "Object left behind", geometry: "zone", needs: { zone: true },
    hint: "Fires when an object is stationary in the zone." },
  { id: "crowd", label: "Crowd count", geometry: "zone", needs: { zone: true, threshold: true },
    hint: "Fires when more than N tracks are inside the zone." },
];

const SVG_W = 640;
const SVG_H = 360;

function specOf(rule, i = 0) {
  // Normalize a stored rule spec for the form.
  return {
    type: rule.type,
    // Preserve the stored id, or synthesize a stable one. The grammar enforces
    // uniqueness over the EFFECTIVE id and two id-less rules of the same type
    // collide, so dropping ids here would make a second loitering zone
    // unsavable (the API correctly answers 400).
    rule_id: rule.rule_id || `${rule.type}-${i + 1}`,
    a: rule.a ? [...rule.a] : null,
    b: rule.b ? [...rule.b] : null,
    zone: rule.zone ? rule.zone.map((p) => [...p]) : null,
    direction: rule.direction || "",
    dwell_sec: rule.dwell_sec ?? 30,
    min_dwell_sec: rule.min_dwell_sec ?? 0,
    stationary_sec: rule.stationary_sec ?? 30,
    threshold: rule.threshold ?? 10,
    labels: rule.labels || [],
  };
}

function validPt(p) { return Array.isArray(p) && p.length === 2
  && p.every((n) => typeof n === "number" && n >= 0 && n <= 1); }
function validZone(z) { return Array.isArray(z) && z.length >= 3 && z.every(validPt); }

/** Client-side mirror of rule_from_dict — returns an error string or null. */
function validate(rule) {
  if (!TYPES.some((t) => t.id === rule.type)) return `unknown rule type: ${rule.type}`;
  if (rule.type === "line_cross") {
    if (!validPt(rule.a) || !validPt(rule.b)) return "line needs two points a and b (numbers 0..1)";
    return null;
  }
  if (!validZone(rule.zone)) return "zone needs at least 3 points (numbers 0..1)";
  if (rule.type === "crowd" && !(Number(rule.threshold) > 0)) return "threshold must be > 0";
  if (rule.type === "loitering" && !(Number(rule.dwell_sec) > 0)) return "dwell seconds must be > 0";
  return null;
}

export function rulesEditor(body, cam) {
  const editable = can("rules:configure");
  let rules = Array.isArray(cam.rules) ? cam.rules.map((r, i) => specOf(r, i)) : [];
  let draft = null; // {type, geometry in progress}
  let drawing = false;

  // Legacy non-list rules (old seed data / hand-edited rows): surfaced as
  // a read-only warning. Saving replaces them with the editor's list — the
  // operator sees exactly what that means before clicking Save.
  const legacy = cam.legacyRules ? JSON.stringify(cam.legacyRules) : null;

  // ── shared canvas: snapshot + zone/line drawing ─────────────────────
  const statusEl = h("p", { class: "muted" }, editable
    ? "Pick a rule type, draw its geometry on the snapshot (click to place points; the polygon closes itself), then save."
    : "Rules apply to this camera; your role can view but not change them.");
  const stage = h("div", { class: "mask-stage", "data-role": "rules-stage" });
  // <img> loads can't carry the bearer token; mint the signed snapshot
  // URL ONCE (fetching inside drawShapes would re-render in a loop).
  let snapshotSrc = "";
  let snapshotFailed = false; // set once, never re-announced (the img
  // element is recreated on every drawShapes, so its onError would fire
  // again and duplicate the notice for every point placed)
  const markSnapshotFailed = () => {
    if (snapshotFailed) return;
    snapshotFailed = true;
    statusEl.textContent += " (Snapshot unavailable — drawing still works on the plain canvas.)";
  };
  api(`/api/cameras/${cam.id}/snapshot-url`)
    .then((r) => { snapshotSrc = r.url; drawShapes(); })
    .catch(markSnapshotFailed);

  function drawShapes() {
    const shapes = [];
    for (const r of rules) {
      if (r.type === "line_cross" && validPt(r.a) && validPt(r.b)) {
        shapes.push(svgEl("line", {
          x1: r.a[0] * SVG_W, y1: r.a[1] * SVG_H,
          x2: r.b[0] * SVG_W, y2: r.b[1] * SVG_H,
          class: "rule-line",
        }, svgEl("title", {}, `Line crossing ${r.direction ? `(${r.direction})` : ""}`)));
      } else if (validZone(r.zone)) {
        shapes.push(svgEl("polygon", {
          points: r.zone.map((p) => `${p[0] * SVG_W},${p[1] * SVG_H}`).join(" "),
          class: "rule-zone",
        }, svgEl("title", {}, `${r.type}`)));
      }
    }
    if (draft && draft.pts && draft.pts.length) {
      if (draft.geometry === "line" && draft.pts.length === 2) {
        shapes.push(svgEl("line", {
          x1: draft.pts[0][0] * SVG_W, y1: draft.pts[0][1] * SVG_H,
          x2: draft.pts[1][0] * SVG_W, y2: draft.pts[1][1] * SVG_H,
          class: "rule-line draft",
        }));
      } else if (draft.geometry === "zone" && draft.pts.length >= 1) {
        const pts = draft.pts.map((p) => `${p[0] * SVG_W},${p[1] * SVG_H}`);
        if (draft.pts.length >= 2) pts.push(pts[0]); // visually closed
        shapes.push(svgEl("polyline", {
          points: pts.join(" "), class: "rule-zone draft",
        }));
        for (const p of draft.pts) {
          shapes.push(svgEl("circle", { cx: p[0] * SVG_W, cy: p[1] * SVG_H, r: 4, class: "rule-point" }));
        }
      }
    }
    // The snapshot <img> is created once and kept: re-rendering it per
    // redraw makes the browser re-request the (expiring) signed URL and
    // re-fires onError — the message appended once per placed point.
    let img = stage.querySelector("img.mask-snapshot");
    if (!img && snapshotSrc) {
      img = h("img", {
        src: snapshotSrc,
        alt: `Snapshot from ${cam.name}`, class: "mask-snapshot",
        onError: (e) => { e.currentTarget.classList.add("hidden"); markSnapshotFailed(); },
      });
      stage.append(img);
    }
    const overlay = stage.querySelector("[data-role='rules-overlay']")
      || (() => {
        const sv = svgEl("svg", {
          viewBox: `0 0 ${SVG_W} ${SVG_H}`, class: "mask-overlay",
          "data-role": "rules-overlay", preserveAspectRatio: "none",
        });
        stage.append(sv);
        return sv;
      })();
    render(overlay, ...shapes);
  }

  // ── rule rows ──────────────────────────────────────────────────────
  function renderRules() {
    const listEl = body.querySelector("[data-role=rule-list]");
    const rows = rules.map((r, i) => {
      const t = TYPES.find((x) => x.id === r.type) || { label: r.type };
      const where = r.type === "line_cross"
        ? `line (${r.a?.map((n) => (n * 100).toFixed(0)).join("%,")}%) → (${r.b?.map((n) => (n * 100).toFixed(0)).join("%,")}%)`
        : `${r.zone?.length ?? 0}-point zone`;
      const extra = r.type === "loitering" ? ` · dwell ${r.dwell_sec}s`
        : r.type === "crowd" ? ` · threshold ${r.threshold}`
        : r.type === "intrusion" && r.min_dwell_sec ? ` · min dwell ${r.min_dwell_sec}s`
        : r.type === "object_left" ? ` · stationary ${r.stationary_sec}s`
        : r.direction ? ` · ${r.direction}` : "";
      return h("li", { class: "mask-row", "data-rule": String(i) },
        h("span", { class: "pill info" }, t.label),
        h("span", { class: "mask-desc" },
          h("strong", {}, where),
          h("span", { class: "muted text-xs" }, `${extra || ""} ${r.labels?.length ? `· ${r.labels.join(", ")}` : ""}`.trim())),
        editable ? h("button", {
          class: "ghost", "data-rule-del": String(i), "aria-label": `Delete rule ${i + 1}`,
          onClick: () => { rules.splice(i, 1); renderRules(); drawShapes(); },
        }, "Remove") : null,
      );
    });
    render(listEl, h("ul", { class: "mask-rows" },
      rows.length ? rows : h("li", { class: "muted" }, "No rules — this camera only records presence.")));
  }

  // ── form for the draft rule ────────────────────────────────────────
  const typeSel = h("select", { id: "rule-type", "data-field": "type", required: true,
    onChange: () => { draft = null; drawShapes(); } },
    TYPES.map((t) => h("option", { value: t.id }, t.label)));
  const hintEl = h("p", { class: "muted text-xs", "data-role": "type-hint", "aria-live": "polite" },
    TYPES[0].hint);
  typeSel.addEventListener("change", () => {
    const t = TYPES.find((x) => x.id === typeSel.value);
    hintEl.textContent = t ? t.hint : "";
  });

  const numField = (name, labelText, val, { min = 0, step = 1 } = {}) =>
    h("label", { class: "field-hint", for: `rf-${name}` }, labelText,
      h("input", { id: `rf-${name}`, "data-field": name, class: "mono",
        type: "number", min: String(min), step: String(step), value: String(val) }));

  const extras = h("div", { class: "form-row", "data-role": "rule-extras" });

  function refreshExtras() {
    const t = TYPES.find((x) => x.id === typeSel.value);
    const kids = [];
    if (t?.id === "line_cross") {
      kids.push(h("label", { class: "field-hint", for: "rf-dir" }, "Direction (optional)",
        h("select", { id: "rf-dir", "data-field": "direction" },
          h("option", { value: "" }, "any"),
          h("option", { value: "left_to_right" }, "left → right"),
          h("option", { value: "right_to_left" }, "right → left"))));
    }
    if (t?.id === "loitering") kids.push(numField("dwell_sec", "Dwell seconds", 30, { min: 1 }));
    if (t?.id === "intrusion") kids.push(numField("min_dwell_sec", "Minimum dwell seconds", 0));
    if (t?.id === "object_left") kids.push(numField("stationary_sec", "Stationary seconds", 30, { min: 1 }));
    if (t?.id === "crowd") kids.push(numField("threshold", "Track threshold", 10, { min: 1 }));
    render(extras, kids);
  }
  typeSel.addEventListener("change", refreshExtras);

  body.append(h("div", { class: "card" },
    h("h3", {}, "Detection rules"),
    legacy ? h("p", { class: "confirm-zone", "data-role": "legacy-rules" },
      "This camera carries a legacy rules object the new editor can't display. Saving below will REPLACE it with the rule list you build here.") : null,
    statusEl,
    stage,
    editable ? h("form", {
      class: "form-col", "data-form": "rule",
      onSubmit: (e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const t = TYPES.find((x) => x.id === typeSel.value);
        // A fresh unique id: the editor allows a second rule of the same type,
        // and the API rejects duplicate effective ids (they would merge engine
        // state silently).
        const rule = { type: t.id, rule_id: `${t.id}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}` };
        if (t.geometry === "line") {
          if (!draft || draft.geometry !== "line" || draft.pts.length !== 2) {
            return toast("Draw the line first: click two points on the snapshot", { tone: "warn" });
          }
          rule.a = draft.pts[0]; rule.b = draft.pts[1];
          const dir = form.querySelector("[data-field=direction]")?.value;
          if (dir) rule.direction = dir;
        } else {
          if (!draft || draft.geometry !== "zone" || draft.pts.length < 3) {
            return toast("Draw the zone first: click at least 3 points on the snapshot", { tone: "warn" });
          }
          rule.zone = draft.pts;
          for (const f of ["dwell_sec", "min_dwell_sec", "stationary_sec", "threshold"]) {
            const el = form.querySelector(`[data-field=${f}]`);
            if (el && el.value !== "") rule[f] = Number(el.value);
          }
        }
        const err = validate(rule);
        if (err) return toast(err, { tone: "error" });
        rules.push(rule);
        draft = null;
        renderRules();
        drawShapes();
        toast(`${t.label} added — remember to save`, { tone: "ok" });
      },
    },
      h("div", { class: "form-row" },
        h("label", { class: "field-hint", for: "rule-type" }, "Type", typeSel),
        h("button", { class: "ghost", type: "button", "data-act": "clear-draft",
          onClick: () => { draft = null; drawShapes(); } }, "Clear drawing")),
      hintEl, extras,
      h("button", { class: "primary", type: "submit" }, "Add rule"),
    ) : null,
    h("ul", { class: "mask-rows", "data-role": "rule-list" }),
    editable ? h("button", {
      class: "primary", "data-act": "save-rules",
      onClick: async (e) => {
        const btn = e.currentTarget;
        btn.disabled = true;
        try {
          await api(`/api/cameras/${cam.id}/rules`, {
            method: "PUT", body: JSON.stringify({ rules }),
          });
          toast(`Saved ${rules.length} rule${rules.length === 1 ? "" : "s"}`, { tone: "ok" });
        } catch (err) {
          toast(err.message || "Save rejected — check each rule", { tone: "error", timeout: 6000 });
        } finally { btn.disabled = false; }
      },
    }, "Save rules to camera") : null,
  ));

  renderRules();
  drawShapes();
  refreshExtras();

  if (!editable) return;

  // Click-to-place drawing on the overlay.
  body.querySelector("[data-role=rules-stage]").addEventListener("click", (e) => {
    const overlay = e.target.closest("[data-role=rules-overlay]");
    if (!overlay) return;
    const r = overlay.getBoundingClientRect();
    const p = [Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)),
      Math.min(1, Math.max(0, (e.clientY - r.top) / r.height))];
    const t = TYPES.find((x) => x.id === typeSel.value);
    if (!t) return;
    if (t.geometry === "line") {
      draft = draft && draft.geometry === "line" ? draft : { geometry: "line", pts: [] };
      draft.pts = draft.pts.length === 2 ? [p] : [...draft.pts, p];
    } else {
      draft = draft && draft.geometry === "zone" ? draft : { geometry: "zone", pts: [] };
      draft.pts.push(p);
    }
    drawShapes();
  });
}
