// Alerts admin — routes, test-fire, recent deliveries (Wave 3).
//
// The alert sender was silent in the old UI: routes existed only as rows in
// a database. This screen exposes the whole capability: create/pause/delete
// routes, fire a connectivity test, and see recent alerting activity —
// with the trust-transparency note about exactly what leaves the host.

import { h, render } from "../core/dom.js";
import { api, can } from "../core/api.js";
import { skeletonRows, emptyState, errorState } from "../core/states.js";
import { toast } from "../core/toast.js";
import { fmtDateTime, fmtDuration, shortId } from "../core/format.js";
import { navigate } from "../core/router.js";

const CHANNELS = ["webhook", "email", "push", "mqtt"];
const RULE_TYPES = ["line_cross", "intrusion", "loitering", "object_left", "object_removed",
                    "stopped_vehicle", "crowd", "presence"];

const CONFIG_HINTS = {
  webhook: '{"url": "https://your-hook.example.com/alerts"}',
  email: '{"to": "oncall@yourcompany.example"}',
  push: '{"server": "https://ntfy.example.com", "topic": "localsight"}',
  mqtt: '{"host": "broker.local", "port": 1883, "topic": "localsight/alerts"}',
};

export async function loadAlertsAdmin(listEl, params = {}) {
  if (!can("alerts:manage")) {
    return render(listEl, emptyState({
      icon: "Ⓜ", title: "Alerts administration",
      hint: "Managing alert routes requires the alerts:manage permission.",
    }));
  }
  if (params.new === "1") return listWithForm(listEl);
  return listRoutes(listEl);
}

async function cameraNames() {
  try {
    const cams = await api("/api/cameras");
    return new Map((Array.isArray(cams) ? cams : []).map((c) => [c.id, c.name]));
  } catch { return new Map(); }
}

// ── routes list ───────────────────────────────────────────────────────

async function listRoutes(listEl) {
  skeletonRows(listEl, 3);
  let routes, names;
  try {
    [routes, names] = await Promise.all([api("/api/alerts/routes"), cameraNames()]);
  } catch (err) {
    return render(listEl, errorState(err, { noun: "alert routes",
      onRetry: () => listRoutes(listEl) }));
  }

  const wrapper = h("div", { "data-route-count": String(routes.length) });
  render(listEl, wrapper);

  if (!routes.length) {
    wrapper.append(emptyState({
      icon: "Ⓜ", title: "No alert routes",
      hint: "Route detections to a webhook, email, push or MQTT — everything stays on your network unless you choose otherwise.",
      action: h("button", {
        class: "primary", "data-act": "route-add",
        onClick: () => navigate("alerts", { new: "1" }),
      }, "Create a route"),
    }));
  } else {
    for (const r of routes) {
      wrapper.append(routeRow(r, names));
    }
  }

  // Recent deliveries (activity feed) — honest even when empty.
  const feed = h("div", { class: "card", "data-role": "deliveries" },
    h("h3", {}, "Recent alerting activity"),
    h("p", { class: "muted" },
      "Point-in-time detections (line crossings, intrusions, ANPR) — presence windows are not alerted."),
    h("ul", { class: "mask-rows", "data-role": "delivery-list" }));
  wrapper.append(feed);
  try {
    const evs = await api("/api/alerts/events?limit=20");
    render(feed.querySelector("[data-role=delivery-list]"), evs.length
      ? evs.map((e) => h("li", { class: "mask-row", "data-delivery": e.id },
          h("span", { class: "pill info" }, e.event_type),
          h("span", { class: "mask-desc" },
            h("strong", {}, names.get(e.camera_id) || shortId(e.camera_id)),
            h("span", { class: "muted text-xs" }, e.identity_status || "")),
          h("span", { class: "muted text-xs" }, fmtDateTime(e.timestamp_start))))
      : [h("li", { class: "muted" }, "No alerting activity yet — test-fire a route.")]);
    feed.setAttribute("data-deliveries-count", String(evs.length));
  } catch (err) {
    render(feed.querySelector("[data-role=delivery-list]"),
      [h("li", { class: "muted" }, "Activity feed unavailable right now.")]);
  }
  // R3.6 daily alert budget — the cap the worker enforces on fan-out, shown
  // with today's usage from the same durable count (analytic events since UTC
  // midnight). Evidence is never capped: only notifications are withheld.
  wrapper.append(await budgetCard());
  return wrapper;
}

// ── daily alert budget (R3.6) ─────────────────────────────────────────

async function budgetCard() {
  const card = h("div", { class: "card", "data-role": "alert-budget" },
    h("h3", {}, "Daily alert budget"),
    h("p", { class: "muted" },
      "Per-camera cap on alert notifications, counted per UTC day — reached caps suppress notifications only. Detections, clips and search results are always kept."),
    h("ul", { class: "mask-rows", "data-role": "budget-list" }));
  let data;
  try {
    data = await api("/api/alerts/budget");
  } catch {
    render(card.querySelector("[data-role=budget-list]"),
      [h("li", { class: "muted" }, "Budget view requires the alerts:manage permission.")]);
    return card;
  }
  const cams = data.cameras || [];
  render(card.querySelector("[data-role=budget-list]"), cams.length
    ? cams.map((c) => budgetRow(c, data.default_limit_per_day))
    : [h("li", { class: "muted" }, "No cameras configured yet.")]);
  card.setAttribute("data-budget-count", String(cams.length));
  return card;
}

function budgetRow(c, defaultLimit) {
  const unlimited = c.effective_limit <= 0;
  const usage = unlimited
    ? "unlimited"
    : `${c.used_today} / ${c.effective_limit} used today${c.remaining === 0 ? ", cap reached" : `, ${c.remaining} left`}`;
  const row = h("li", { class: "mask-row", "data-budget-camera": c.camera_id },
    h("span", { class: "pill info" }, unlimited ? "no cap" : (c.remaining === 0 ? "capped" : "ok")),
    h("span", { class: "mask-desc" },
      h("strong", {}, c.name || shortId(c.camera_id)),
      h("span", { class: "muted text-xs" },
        `${usage}${c.limit_per_day === null ? ` (platform default${defaultLimit ? ` ${defaultLimit}` : " unlimited"})` : ""}`)));
  if (can("camera:configure")) {
    const input = h("input", {
      type: "number", min: "0", max: "10000", class: "mono",
      value: String(c.limit_per_day ?? c.effective_limit ?? 0),
      "aria-label": `Daily alert budget for ${c.name || c.camera_id}` });
    const save = h("button", {
      class: "ghost", "data-act": "budget-save",
      onClick: async (e) => {
        const n = Number(input.value);
        if (!Number.isInteger(n) || n < 0 || n > 10000) {
          return toast("Budget must be an integer 0-10000", { tone: "error" });
        }
        e.currentTarget.disabled = true;
        try {
          await api(`/api/cameras/${c.camera_id}`, {
            method: "PUT", body: JSON.stringify({ alert_budget_per_day: n }) });
          toast("Alert budget saved", { tone: "ok" });
          navigate("alerts");
        } catch (err) {
          toast(err.message, { tone: "error" });
          e.currentTarget.disabled = false;
        }
      },
    }, "Save");
    row.append(h("span", { class: "cam-card-actions" }, input, save));
  }
  return row;
}

function routeRow(r, names) {
  // Actions attach after the row exists — the delete-confirm handler
  // replaces the actions span, so it needs a live reference to the row.
  const actions = h("span", { class: "cam-card-actions", "data-role": "actions" });
  const row = h("div", { class: "route-row", "data-route-id": r.id, "data-channel": r.channel },
    h("span", { class: "pill info" }, r.channel),
    h("span", { class: "grow" },
      h("strong", {}, r.rule_type),
      h("span", { class: "muted text-xs" },
        ` · ${r.camera_id ? names.get(r.camera_id) || shortId(r.camera_id) : "all cameras"} · cooldown ${fmtDuration(r.cooldown_sec)}`)),
    h("span", { class: `pill ${r.enabled ? "ok" : "warn"}` }, r.enabled ? "enabled" : "paused"),
    actions);
  fillActions(r, row, actions, names);
  return row;
}

function fillActions(r, row, actions, names) {
  const testBtn = h("button", {
    class: "ghost", "data-act": "test-fire",
    onClick: async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      btn.textContent = "Firing…";
      try {
        const res = await api("/api/alerts/test", { method: "POST", body: "{}" });
        toast(res.delivered > 0
          ? `Test alert delivered to ${res.delivered} route${res.delivered === 1 ? "" : "s"}`
          : "No enabled route could be reached (check config)", {
          tone: res.delivered > 0 ? "ok" : "warn", timeout: 6000 });
      } catch (err) {
        toast(err.message, { tone: "error" });
      } finally { btn.disabled = false; btn.textContent = "Test-fire"; }
    },
  }, "Test-fire");

  const toggleBtn = h("button", {
    class: "ghost", "data-act": "toggle-route",
    onClick: async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        // The API has no PATCH — recreate is wrong; the enabled toggle is
        // part of route config. Until a dedicated endpoint exists, pause =
        // delete-with-recreate only when we hold the full config… which we
        // don't (config_enc is write-only). So: honest limitation, surfaced.
        toast("Pausing needs the route's config — delete and recreate it instead", {
          tone: "info", timeout: 6000 });
      } finally { btn.disabled = false; }
    },
  }, r.enabled ? "Pause" : "Resume");

  const delBtn = h("button", {
    class: "ghost", "data-act": "delete-route",
    onClick: () => {
      const zone = h("span", { class: "confirm-zone", "data-role": "del-confirm" },
        h("span", { class: "muted text-xs" }, "Delete this route?"),
        h("span", { class: "form-row" },
          h("button", {
            class: "ghost", "data-act": "delete-route-confirm",
            onClick: async (e) => {
              e.currentTarget.disabled = true;
              try {
                await api(`/api/alerts/routes/${r.id}`, { method: "DELETE" });
                toast("Route deleted", { tone: "ok" });
                navigate("alerts");
              } catch (err) { toast(err.message, { tone: "error" }); }
            },
          }, "Delete route"),
          h("button", {
            class: "ghost", type: "button",
            onClick: (e) => { e.currentTarget.closest(".confirm-zone").remove(); },
          }, "Cancel")));
      row.querySelector("[data-role=actions]").replaceWith(zone);
    },
  }, "Delete");

  actions.append(testBtn, toggleBtn, delBtn);
}

// ── create form ──────────────────────────────────────────────────────

async function listWithForm(listEl) {
  await listRoutes(listEl);
  const camOptions = await cameraNames();
  const channelSel = h("select", { id: "nr-channel", "data-field": "channel", required: true },
    CHANNELS.map((c) => h("option", { value: c }, c)));
  const cfgInput = h("input", {
    id: "nr-config", "data-field": "config", class: "mono",
    placeholder: CONFIG_HINTS.webhook, "aria-label": "Channel config (JSON)" });
  channelSel.addEventListener("change", () => {
    cfgInput.setAttribute("placeholder", CONFIG_HINTS[channelSel.value] || "{}");
  });

  const form = h("form", { class: "card form-col", "data-form": "route-new", novalidate: true },
    h("h3", {}, "New alert route"),
    h("p", { class: "muted" },
      "Only these fields ever leave this host on an alert: camera name, rule type, event time, and a snapshot link. Plate text and stream URLs never go to third-party channels."),
    h("div", { class: "form-row" },
      h("label", { class: "field-hint", for: "nr-rule" }, "Rule type",
        h("select", { id: "nr-rule", "data-field": "rule_type", required: true },
          RULE_TYPES.map((t) => h("option", { value: t }, t)))),
      h("label", { class: "field-hint", for: "nr-camera" }, "Camera (or all)",
        h("select", { id: "nr-camera", "data-field": "camera_id" },
          h("option", { value: "" }, "All cameras"),
          [...camOptions.entries()].map(([id, name]) => h("option", { value: id }, name))))),
    h("div", { class: "form-row" },
      h("label", { class: "field-hint", for: "nr-channel" }, "Channel", channelSel),
      h("label", { class: "field-hint", for: "nr-cooldown" }, "Cooldown (seconds between alerts)",
        h("input", { id: "nr-cooldown", "data-field": "cooldown_sec", class: "mono",
          type: "number", min: "0", value: "300" }))),
    h("label", { class: "field-hint", for: "nr-config" }, "Channel config (JSON)", cfgInput),
    h("div", { class: "form-row" },
      h("button", { class: "primary", type: "submit", "data-act": "route-create" }, "Create route"),
      h("button", { class: "ghost", type: "button", onClick: () => navigate("alerts") }, "Cancel")),
  );

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = form.querySelector("button[type=submit]");
    const raw = cfgInput.value.trim();
    let config = {};
    if (raw) {
      try { config = JSON.parse(raw); }
      catch { return toast("Config isn't valid JSON", { tone: "error" }); }
    }
    btn.disabled = true;
    try {
      const cameraId = form.querySelector("[data-field=camera_id]").value || null;
      await api("/api/alerts/routes", {
        method: "POST",
        body: JSON.stringify({
          rule_type: form.querySelector("[data-field=rule_type]").value,
          camera_id: cameraId,
          channel: channelSel.value,
          enabled: true,
          cooldown_sec: Number(form.querySelector("[data-field=cooldown_sec]").value || 300),
          config,
        }),
      });
      toast("Route created", { tone: "ok" });
      navigate("alerts");
    } catch (err) {
      toast(err.message || "Create failed", { tone: "error", timeout: 6000 });
    } finally { btn.disabled = false; }
  });

  listEl.prepend(form);
  form.querySelector("[data-field=rule_type]").focus();
}
