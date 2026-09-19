// Events view — Wave 1: the investigation list.
//
// Row click opens the detail drawer; ↑/↓ walk rows and Enter opens;
// filters serialize into the URL hash so an investigation is shareable
// (router.js owns view state now — the old JS-only state is gone).

import { h, render } from "../core/dom.js";
import { api, can } from "../core/api.js";
import { toast } from "../core/toast.js";
import { navigate, replace } from "../core/router.js";
import { skeletonRows, emptyState, errorState } from "../core/states.js";
import { fmtTime, fmtDateTime, fmtIso, fmtRelative, fmtDuration, shortId, label, tone }
  from "../core/format.js";

const PAGE = 25;
let cameraNames = null;
let offset = 0;
let sortKey = "timestamp";     // M1/E-1: server-side sort state
let sortDir = "desc";
let lastItems = [];
let selected = new Set();      // M3/E-3: bulk selection (this result set)
let cursor = -1; // keyboard selection index
let listWrap = null;

async function names() {
  if (cameraNames) return cameraNames;
  try {
    const cams = await api("/api/cameras");
    cameraNames = new Map((Array.isArray(cams) ? cams : cams.items || []).map((c) => [c.id, c.name]));
  } catch { cameraNames = new Map(); }
  return cameraNames;
}

function openEvent(id) {
  navigate("events", currentFilters(), id);
}

function currentFilters() {
  const cameraId = document.getElementById("ev-camera").value.trim();
  const status = document.getElementById("ev-status").value;
  return { ...(cameraId ? { camera: cameraId } : {}), ...(status ? { status } : {}) };
}

function applyFiltersToInputs(params) {
  document.getElementById("ev-camera").value = params.camera || "";
  document.getElementById("ev-status").value = params.status || "";
}

function eventRow(e, nameMap, idx) {
  const camName = nameMap.get(e.camera_id) || `camera ${shortId(e.camera_id)}`;
  const durSec = (new Date(e.timestamp_end) - new Date(e.timestamp_start)) / 1000;
  return h("tr", {
    class: "event-row",
    dataset: { eventId: e.id, idx: String(idx) },
    onClick: () => openEvent(e.id),
  },
    // E-3: bulk select — stopPropagation so the checkbox doesn't open the row
    h("td", { class: "bulk-col" },
      h("input", {
        type: "checkbox", "aria-label": `Select event ${shortId(e.id)}`,
        "data-bulk": e.id,
        ...(selected.has(e.id) ? { checked: true } : {}),
        onClick: (ev) => ev.stopPropagation(),
        onChange: (ev) => {
          if (ev.currentTarget.checked) selected.add(e.id);
          else selected.delete(e.id);
          const sel = document.getElementById("ev-bulk-all");
          if (sel) sel.checked = lastItems.length > 0
            && lastItems.every((it) => selected.has(it.id));
          paintBulkBar();
        },
      })),
    h("td", {}, camName),
    h("td", {}, e.identity_id
      ? h("span", { class: `pill ${tone(e.identity_status)}` }, label(e.identity_status))
      : h("span", { class: "pill" }, "—")),
    h("td", {}, label(e.event_type)),
    h("td", { class: "mono" },
      fmtTime(e.timestamp_start),
      h("div", { class: "muted" }, fmtRelative(e.timestamp_start)),
    ),
    h("td", { class: "mono" }, Number.isFinite(durSec) ? fmtDuration(durSec) : "—"),
    h("td", { class: "mono" }, e.confidence.toFixed(2)),
    h("td", {},
      h("span", { class: "media-flags" },
        e.has_snapshot ? h("span", { class: "media-flag", title: "Has snapshot" }, "◉") : null,
        e.has_video ? h("span", { class: "media-flag", title: "Has video" }, "▶") : null,
        (!e.has_snapshot && !e.has_video) ? h("span", { class: "muted" }, "—") : null,
      ),
    ),
  );
}

function moveCursor(delta) {
  if (!lastItems.length || !listWrap) return;
  cursor = Math.min(Math.max(cursor + delta, 0), lastItems.length - 1);
  const rows = listWrap.querySelectorAll("tr.event-row");
  rows.forEach((r) => r.classList.toggle("cursor", Number(r.dataset.idx) === cursor));
  const sel = rows[cursor];
  if (sel) sel.scrollIntoView({ block: "nearest" });
}

export async function loadEvents(wrapEl, { resetOffset = false, params = {} } = {}) {
  listWrap = wrapEl;
  // Deep-linkable sort (E-10): hash params override module defaults
  if (params.sort) sortKey = params.sort;
  if (params.direction) sortDir = params.direction;
  // Export gate runs on every load — can() is only live after /api/auth/me,
  // so a boot-time toggle would hide the button for entitled roles.
  const eb = document.getElementById("ev-export");
  if (eb) eb.classList.toggle("hidden", !can("events:export"));
  applyFiltersToInputs(params);
  if (resetOffset) offset = 0;
  cursor = -1;
  const filters = currentFilters();
  skeletonRows(wrapEl, 6);
  try {
    const [data, nameMap] = await Promise.all([
      api(`/api/events?${new URLSearchParams({
        limit: PAGE, offset, sort: sortKey, direction: sortDir,
        ...(filters.camera ? { camera_id: filters.camera } : {}),
        ...(filters.status ? { identity_status: filters.status } : {}),
      })}`),
      names(),
    ]);
    lastItems = data.items || [];
    const rows = lastItems.map((e, i) => eventRow(e, nameMap, i));

    // M1/E-1: sortable headers. aria-sort announces state; the arrow is
    // CSS (::after on .sorted-asc/.sorted-desc). Clicking toggles direction.
    const th = (key, text) => {
      const active = sortKey === key;
      return h("th", {
        "aria-sort": active ? (sortDir === "asc" ? "ascending" : "descending") : "none",
        class: active ? (sortDir === "asc" ? "sorted-asc" : "sorted-desc") : "",
        scope: "col",
        ...(key ? { onClick: () => {
          if (sortKey === key) sortDir = sortDir === "asc" ? "desc" : "asc";
          else { sortKey = key; sortDir = key === "timestamp" ? "desc" : "asc"; }
          offset = 0;
          // keep the hash in sync so Copy Link stays honest (E-10);
          // replace() not navigate(): sorting refines, doesn't navigate
          replace("events", { ...currentFilters(), sort: sortKey, direction: sortDir });
          loadEvents(wrapEl);
        } } : {}),
      }, text);
    };

    const allHere = new Set(lastItems.map((e) => e.id));
    const allSelected = lastItems.length > 0 && lastItems.every((e) => selected.has(e.id));

    render(wrapEl, rows.length
      ? h("div", { class: "table-scroll" },
          h("table", { id: "events-table" },
            h("thead", {}, h("tr", {},
              h("th", { scope: "col", class: "bulk-col" },
                h("input", {
                  type: "checkbox", id: "ev-bulk-all", "aria-label": "Select all events on this page",
                  ...(allSelected ? { checked: true } : {}),
                  onChange: (e) => {
                    if (e.currentTarget.checked) allHere.forEach((id) => selected.add(id));
                    else allHere.forEach((id) => selected.delete(id));
                    loadEvents(wrapEl);
                  },
                })),
              th("camera", "Camera"), th("identity", "Identity"), th("type", "Type"),
              th("timestamp", "Start"), th("duration", "Duration"), th("confidence", "Conf"),
              th(null, "Media"),
            )),
            h("tbody", {}, rows),
          ),
        )
      : emptyState({
          icon: "◌", title: "No events match",
          hint: "Adjust the filters — or clear them to see all events.",
        }));
    document.getElementById("ev-page").textContent =
      `${Math.floor(offset / PAGE) + 1}${data.total ? ` / ${Math.ceil(data.total / PAGE)}` : ""}`;
    document.getElementById("ev-prev").disabled = offset <= 0;
    document.getElementById("ev-next").disabled = !lastItems.length || lastItems.length < PAGE;
    paintBulkBar();
  } catch (err) {
    render(wrapEl, errorState(err, { noun: "events", onRetry: () => loadEvents(wrapEl, { params }) }));
  }
}

function paintBulkBar() {
  const bar = document.getElementById("ev-bulk-bar");
  if (!bar) return;
  bar.classList.toggle("hidden", selected.size === 0);
  const n = document.getElementById("ev-bulk-count");
  if (n) n.textContent = String(selected.size);
}

// ── R2 forensic search (B1 attributes / B2 plates / B8 saved) ───────────────
// The card is investigative, so it's permission-gated (`search:view`; saving
// needs `search:save`) and every save/delete is audited server-side. Results
// never carry plate material — the plate tab shows *where*, not *what*.

function fsKind() {
  const el = document.getElementById("fs-kind");
  return el ? el.value : "attributes";
}

function fsToggleKind() {
  const kind = fsKind();
  document.getElementById("fs-key").classList.toggle("hidden", kind !== "attributes");
  document.getElementById("fs-value").classList.toggle("hidden", kind !== "attributes");
  document.getElementById("fs-plate").classList.toggle("hidden", kind !== "plates");
}

function fsParams() {
  const camera = document.getElementById("ev-camera").value.trim();
  if (fsKind() === "plates") {
    return { kind: "plates", q: document.getElementById("fs-plate").value.trim(), camera };
  }
  return {
    kind: "attributes",
    key: document.getElementById("fs-key").value.trim(),
    value: document.getElementById("fs-value").value.trim(),
    camera,
  };
}

function fsResultRow(r, kind, nameMap) {
  const camName = nameMap.get(r.camera_id) || `camera ${shortId(r.camera_id)}`;
  const when = r.ts || r.last_seen || "";
  const action = h("button", {
    class: "ghost linklike",
    onClick: () => {
      if (kind === "plates" && r.event_id) { openEvent(r.event_id); return; }
      // attribute hit: scope the event list to that camera so the operator
      // lands in the surrounding footage instead of a dead end
      const cam = document.getElementById("ev-camera");
      if (cam) cam.value = r.camera_id;
      document.getElementById("ev-search").click();
    },
  }, kind === "plates" ? "Open event" : "Show in events");
  const attrCell = kind === "plates"
    ? h("td", { class: "mono" }, Number.isFinite(r.confidence) ? r.confidence.toFixed(2) : "—")
    : h("td", {}, Object.entries(r.attributes || {})
        .filter(([k]) => !k.endsWith("_conf"))
        .map(([k, v]) => h("span", { class: "chip" }, `${k}: ${v === true ? "yes" : String(v)}`)));
  return h("tr", {},
    h("td", {}, camName),
    h("td", { class: "mono" }, when ? fmtDateTime(when) : "—"),
    attrCell,
    h("td", {}, action),
  );
}

async function runForensic() {
  const out = document.getElementById("fs-results");
  if (!out) return;
  const { kind, q, key, value, camera } = fsParams();
  if (kind === "plates" ? !q : !key) {
    render(out, emptyState({
      icon: "⌕", title: "Nothing to search yet",
      hint: kind === "plates"
        ? "Type a plate — spaces and dashes are normalized for you."
        : "Type an attribute, e.g. jacket or color.",
    }));
    return;
  }
  skeletonRows(out, 4);
  const qs = new URLSearchParams();
  if (kind === "plates") qs.set("q", q);
  else { qs.set("key", key); if (value) qs.set("value", value); }
  if (camera) qs.set("camera_id", camera);
  try {
    const [data, nameMap] = await Promise.all([
      api(`/api/search/${kind === "plates" ? "plates" : "attributes"}?${qs}`),
      names(),
    ]);
    const items = data.results || [];
    render(out, items.length
      ? h("div", { class: "table-scroll" },
          h("table", {},
            h("thead", {}, h("tr", {},
              h("th", { scope: "col" }, "Camera"),
              h("th", { scope: "col" }, "When"),
              h("th", { scope: "col" }, kind === "plates" ? "Confidence" : "Attributes"),
              h("th", { scope: "col" }, ""),
            )),
            h("tbody", {}, items.map((r) => fsResultRow(r, kind, nameMap))),
          ))
      : emptyState({
          icon: "◌", title: "No matches",
          hint: "Widen the window (clear the camera filter), or check the spelling — plate search is exact by design.",
        }));
  } catch (err) {
    render(out, errorState(err, { noun: "search", onRetry: runForensic }));
  }
}

let savedSearches = [];

async function loadSaved() {
  const wrap = document.getElementById("fs-saved");
  if (!wrap) return;
  try {
    savedSearches = (await api("/api/searches")).items || [];
  } catch {
    savedSearches = []; // card keeps working even if the listing fails
  }
  render(wrap, savedSearches.map((s) => h("span", { class: "chip", role: "listitem" },
    h("button", {
      class: "ghost linklike", title: "Run this saved search",
      onClick: () => applySaved(s),
    }, s.name),
    h("button", {
      class: "ghost linklike", "aria-label": `Delete saved search ${s.name}`,
      onClick: async () => {
        try {
          await api(`/api/searches/${s.id}`, { method: "DELETE" });
          toast("Saved search deleted", { tone: "ok" });
          loadSaved();
        } catch (err) {
          toast(err.status === 403 ? "Your role can't manage saved searches"
            : "Delete failed — try again", { tone: "error" });
        }
      },
    }, "✕"),
  )));
}

function applySaved(s) {
  const p = s.params || {};
  document.getElementById("fs-kind").value = s.kind;
  fsToggleKind();
  if (s.kind === "plates") document.getElementById("fs-plate").value = p.q || "";
  else {
    document.getElementById("fs-key").value = p.key || "";
    document.getElementById("fs-value").value = p.value || "";
  }
  runForensic();
}

async function saveCurrent() {
  const nameEl = document.getElementById("fs-save-name");
  const name = (nameEl.value || "").trim();
  const { kind, q, key, value } = fsParams();
  if (!name) { toast("Name the search before saving", { tone: "warn" }); nameEl.focus(); return; }
  const params = kind === "plates" ? { q } : { key, value };
  const btn = document.getElementById("fs-save");
  btn.disabled = true;
  try {
    await api("/api/searches", {
      method: "POST",
      body: JSON.stringify({ name, kind, params }),
    });
    nameEl.value = "";
    toast(`Saved “${name}” — find it in the chips above`, { tone: "ok" });
    loadSaved();
  } catch (err) {
    toast(err.status === 409 ? "A saved search with that name exists"
      : err.status === 403 ? "Your role can't save searches"
      : "Save failed — try again", { tone: "error" });
  } finally {
    btn.disabled = false;
  }
}

export function wireEventsView(wrapEl) {
  listWrap = wrapEl;
  document.getElementById("ev-search").addEventListener("click", () => {
    // E-10: the URL carries the whole investigation — filters + sort
    navigate("events", { ...currentFilters(), sort: sortKey, direction: sortDir });
  });
  const bulkExport = document.getElementById("ev-bulk-export");
  if (bulkExport && !bulkExport.dataset.wired) {
    bulkExport.dataset.wired = "1";
    bulkExport.addEventListener("click", async () => {
      if (!selected.size) return;
      bulkExport.disabled = true;
      const old = bulkExport.textContent;
      bulkExport.textContent = "Exporting…";
      try {
        const f = currentFilters();
        const qs = new URLSearchParams({
          ...(f.camera ? { camera_id: f.camera } : {}),
          ...(f.status ? { identity_status: f.status } : {}),
          ids: [...selected].join(","),
        });
        const csv = await api(`/api/events/export.csv?${qs}`);
        const blob = new Blob([csv], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `events-selected-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        toast(`Exported ${selected.size} selected event(s)`, { tone: "ok" });
      } catch (err) {
        toast(err.status === 403 ? "Your role can't export events" : "Export failed — try again",
          { tone: "error" });
      } finally {
        bulkExport.disabled = false;
        bulkExport.textContent = old;
      }
    });
  }
  const bulkClear = document.getElementById("ev-bulk-clear");
  if (bulkClear && !bulkClear.dataset.wired) {
    bulkClear.dataset.wired = "1";
    bulkClear.addEventListener("click", () => {
      selected.clear();
      loadEvents(wrapEl);
    });
  }

  const copyBtn = document.getElementById("ev-link");
  if (copyBtn && !copyBtn.dataset.wired) {
    copyBtn.dataset.wired = "1";
    copyBtn.addEventListener("click", () => {
      // "send me what you see" without a screenshot (E-10)
      const url = `${location.origin}${location.pathname}#/events?` +
        new URLSearchParams({
          ...currentFilters(), sort: sortKey, direction: sortDir,
        }).toString();
      navigator.clipboard.writeText(url).then(
        () => toast("Link copied — it reproduces exactly this view", { tone: "ok" }),
        () => toast("Copy failed — the URL bar has the same link", { tone: "warn" }));
    });
  }
  const exportBtn = document.getElementById("ev-export");
  if (exportBtn) exportBtn.classList.toggle("hidden", !can("events:export"));
  if (exportBtn && !exportBtn.dataset.wired) {
    exportBtn.dataset.wired = "1";
    exportBtn.addEventListener("click", async () => {
      // M1/E-2: export the CURRENT result set — same filters + sort the table
      // shows, honored server-side; the export itself is audited. Goes through
      // the shared fetch layer so the auth header rides along, then a blob
      // download hands the file to the operator.
      exportBtn.disabled = true;
      const old = exportBtn.textContent;
      exportBtn.textContent = "Exporting…";
      try {
        const f = currentFilters();
        const qs = new URLSearchParams({
          ...(f.camera ? { camera_id: f.camera } : {}),
          ...(f.status ? { identity_status: f.status } : {}),
          sort: sortKey, direction: sortDir,
        });
        const csv = await api(`/api/events/export.csv?${qs}`);
        const blob = new Blob([csv], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `events-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        toast(`Exported ${csv.split("\n").length - 1} rows — the download is yours`, { tone: "ok" });
      } catch (err) {
        toast(err.status === 403 ? "Your role can't export events" : "Export failed — try again",
          { tone: "error" });
      } finally {
        exportBtn.disabled = false;
        exportBtn.textContent = old;
      }
    });
  }
  document.getElementById("ev-prev").addEventListener("click", () => {
    offset = Math.max(0, offset - PAGE);
    loadEvents(wrapEl);
  });

  // ── R2 forensic search card (B1/B2/B8) — gated per role; can() is live by
  // wire time (same guarantee the export gate above relies on).
  const fsCard = document.getElementById("fs-card");
  if (fsCard) {
    const entitled = can("search:view");
    fsCard.classList.toggle("hidden", !entitled);
    if (entitled) {
      const canSave = can("search:save");
      const saveBtn = document.getElementById("fs-save");
      const nameIn = document.getElementById("fs-save-name");
      saveBtn.classList.toggle("hidden", !canSave);
      nameIn.classList.toggle("hidden", !canSave);
      document.getElementById("fs-kind").addEventListener("change", fsToggleKind);
      document.getElementById("fs-run").addEventListener("click", runForensic);
      if (canSave) saveBtn.addEventListener("click", saveCurrent);
      loadSaved();
    }
  }
  document.getElementById("ev-next").addEventListener("click", () => {
    offset += PAGE;
    loadEvents(wrapEl);
  });

  // Keyboard: ↑/↓ select, Enter opens — active only in the events view
  // and when focus isn't in a filter input.
  document.addEventListener("keydown", (e) => {
    const panel = document.querySelector('[data-panel="events"]');
    if (!panel || panel.classList.contains("hidden")) return;
    if (document.activeElement && ["INPUT", "SELECT"].includes(document.activeElement.tagName)) return;
    if (e.key === "ArrowDown") { e.preventDefault(); moveCursor(1); }
    if (e.key === "ArrowUp") { e.preventDefault(); moveCursor(-1); }
    if (e.key === "Enter" && cursor >= 0 && lastItems[cursor]) {
      e.preventDefault();
      openEvent(lastItems[cursor].id);
    }
  });
}
