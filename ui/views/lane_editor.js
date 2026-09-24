// Lane editor — gate access (R4.1) — the "Gate access" tab of camera detail.
//
// Binds apps/api/routers/lanes.py to the operator UI. A camera armed as a lane
// matches its ANPR reads against a keyed-HMAC plate whitelist inside an allow
// window and fires one barrier OPEN per plate+cooldown. Deny by default: a
// plate that is not whitelisted inside its window is logged and NEVER reaches
// the relay. Every open/deny is audited with the plate HASH, never the plate.
//
// Security posture mirrored from the Streams tab + Alerts admin (the two
// precedents for privileged side effects and write-only secrets):
//
//  - The barrier destination is a write-only secret: envelope-encrypted at
//    rest and never returned by the API (only the boolean "configured"). The
//    lane PUT replaces it wholesale, so an ARMED lane needs the destination
//    re-entered on every save — the placeholder says so out loud instead of
//    offering a fictional "keep" tick. Without a destination the worker logs
//    "OPEN suppressed" and the gate stays shut; hiding that behind a keep-tick
//    would arm a lane that can never open (the exact silent fail R4.1's
//    fail-closed validation exists to prevent).
//  - SSRF rejections come back as 400 detail from the SAME validator the alert
//    routes use; that text is surfaced verbatim next to the field because it
//    IS the guard speaking ("unsafe webhook: ...").
//  - Whitelist rows carry plate_hash only. The plate an operator enrolls is
//    echoed once in the toast (their own input, normalized — the same rule as
//    GET /api/search/plates) and is never stored, re-shown, or logged here.
//
// RBAC: the tab needs lanes:view (ADMIN / SECURITY_OPERATOR / ANALYST). Only
// lanes:manage (ADMIN / SECURITY_OPERATOR) gets the forms — arming a barrier
// is deliberately narrower than camera:configure, so a camera admin who must
// not touch access control still cannot arm a gate.

import { h, render } from "../core/dom.js";
import { api, ApiError, can } from "../core/api.js";
import { skeletonRows, errorState } from "../core/states.js";
import { toast } from "../core/toast.js";
import { fmtDateTime, shortId } from "../core/format.js";
import { navigate } from "../core/router.js";

const CHANNELS = ["webhook", "mqtt"];
const DAYS = [["Mon", 1], ["Tue", 2], ["Wed", 3], ["Thu", 4], ["Fri", 5], ["Sat", 6], ["Sun", 7]];

export async function laneEditor(body, cam) {
  const editable = can("lanes:manage");
  skeletonRows(body, 3);
  let lane = null;
  try {
    // 404 = "camera has no lane configured" — the honest not-a-lane state,
    // not an error the operator needs to retry out of.
    lane = await api(`/api/cameras/${cam.id}/lane`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      lane = null;
    } else {
      return render(body, errorState(err, { noun: "lane policy",
        onRetry: () => laneEditor(body, cam) }));
    }
  }
  render(body,
    laneSummaryCard(cam, lane),
    laneFormCard(cam, lane, editable),
    whitelistCard(cam, lane, editable),
    removeLaneCard(cam, lane, editable),
  );
}

// ── summary ─────────────────────────────────────────────────────────────

function laneSummaryCard(cam, lane) {
  if (!lane) return null; // nothing to summarise — the form card explains
  const armed = Boolean(lane.enabled);
  return h("div", { class: "card", "data-role": "lane-summary" },
    h("div", { class: "cam-card-head" },
      h("div", {},
        h("h3", {}, "Lane status"),
        h("div", { class: "muted text-xs" },
          lane.name ? `Lane “${lane.name}”` : `Unnamed lane on ${cam.name}`),
      ),
      h("span", { class: `pill ${armed ? "ok" : "warn"}` },
        h("span", { class: `dot ${armed ? "ok" : "warn"}`, "aria-hidden": "true" }, ""),
        armed ? "Armed — evaluating plate reads" : "Disarmed — lane is paused"),
    ),
    h("dl", { class: "kv-grid" },
      h("div", {}, h("dt", {}, "Barrier channel"),
        h("dd", {}, lane.barrier_channel)),
      h("div", {}, h("dt", {}, "Barrier destination"),
        h("dd", {}, lane.barrier_configured
          ? h("span", { class: "muted" }, "configured — encrypted, never shown")
          : h("span", { class: "tone-warn" }, "not configured — gate cannot open"))),
      h("div", {}, h("dt", {}, "Allow window"),
        h("dd", {}, windowSummary(lane.allow_window, cam.timezone))),
      h("div", {}, h("dt", {}, "Cooldown"),
        h("dd", {}, `${lane.cooldown_sec}s between opens per plate`)),
      h("div", {}, h("dt", {}, "Whitelisted plates"),
        h("dd", {}, String((lane.whitelist || []).length))),
      h("div", {}, h("dt", {}, "Armed by"),
        h("dd", { class: "mono" }, shortId(lane.armed_by))),
    ),
    h("p", { class: "muted text-xs" },
      "A plate read on this camera is matched against the whitelist, checked against the allow window, and — only on a match — sends one OPEN to the barrier. "
      + "A miss is logged as a gate_deny event and never reaches the relay. Revoking a plate takes effect on the next read."),
  );
}

// ── policy form ──────────────────────────────────────────────────────────

function laneFormCard(cam, lane, editable) {
  if (!editable) {
    return h("div", { class: "card" },
      h("h3", {}, "Lane configuration"),
      lane
        ? h("p", { class: "muted" },
            "Read-only for your role — arming or changing a lane needs the lanes:manage permission.")
        : h("p", { class: "muted" },
            "This camera is not configured as a lane. Arming one needs the lanes:manage permission."),
    );
  }

  const creating = !lane;
  const win = (lane && lane.allow_window) || {};
  const errSlot = h("div", { class: "form-error", "data-role": "lane-error", role: "alert" });
  const setErr = (msg) => { errSlot.textContent = msg || ""; };

  // Allow-window inputs: type="time" emits exactly the HH:MM the server-side
  // _parse_hhmm expects, so no client-side format translation is needed.
  const startIn = h("input", {
    id: `lw-start-${cam.id}`, "data-window": "start", type: "time",
    value: win.start || "", "aria-label": "Allow window start",
  });
  const endIn = h("input", {
    id: `lw-end-${cam.id}`, "data-window": "end", type: "time",
    value: win.end || "", "aria-label": "Allow window end",
  });
  const tzIn = h("input", {
    id: `lw-tz-${cam.id}`, "data-window": "tz", class: "mono",
    value: win.tz || "", placeholder: cam.timezone || "UTC",
    "aria-label": "Allow window timezone (IANA)",
  });

  // Weekday chips: ISO 1..7. Empty selection = every day (no `days` key), so
  // the default stays permissive rather than a silent deny-all.
  const selected = new Set(Array.isArray(win.days) ? win.days : []);
  const dayChips = DAYS.map(([name, n]) => {
    const chip = h("button", {
      type: "button", class: `lane-day${selected.has(n) ? " on" : ""}`,
      "data-day": String(n), "aria-pressed": String(selected.has(n)),
      onClick: () => {
        if (selected.has(n)) selected.delete(n);
        else selected.add(n);
        const now = selected.has(n);
        chip.classList.toggle("on", now);
        chip.setAttribute("aria-pressed", String(now));
      },
    }, name);
    return chip;
  });

  // Barrier destination (write-only; the field group swaps with the channel).
  const channelSel = h("select", {
    id: `lb-channel-${cam.id}`, "data-field": "channel",
    "aria-label": "Barrier channel",
  }, CHANNELS.map((c) => h("option", {
    value: c, selected: lane ? lane.barrier_channel === c : c === "webhook",
  }, c)));

  const destNote = h("p", { class: "muted text-xs" },
    lane && lane.barrier_configured
      ? "A destination is stored (encrypted — never shown back). Re-enter it below: saving an armed lane with an empty destination clears it, and the gate will not open."
      : "Stored encrypted at rest and never shown again. Validated against the egress allowlist before it is saved.");

  const urlIn = h("input", {
    id: `lb-url-${cam.id}`, "data-dest": "url", class: "mono",
    type: "password", autocomplete: "new-password",
    placeholder: "https://barrier-controller.example.local/open",
    "aria-label": "Barrier webhook URL",
  });
  const hostIn = h("input", {
    id: `lb-host-${cam.id}`, "data-dest": "host", class: "mono",
    type: "password", autocomplete: "new-password",
    placeholder: "broker.example.local", "aria-label": "MQTT broker host",
  });
  const portIn = h("input", {
    id: `lb-port-${cam.id}`, "data-dest": "port", class: "mono",
    type: "number", min: "1", max: "65535", value: "1883",
    "aria-label": "MQTT broker port",
  });
  const topicIn = h("input", {
    id: `lb-topic-${cam.id}`, "data-dest": "topic", class: "mono",
    placeholder: "localsight/barrier/open (optional)", "aria-label": "MQTT topic",
  });

  const webhookFields = h("div", { class: "form-col lane-dest", "data-dest-group": "webhook" },
    h("label", { class: "field-hint", for: `lb-url-${cam.id}` },
      "Webhook URL (POSTed on every granted plate)", urlIn));
  const mqttFields = h("div", { class: "form-col lane-dest hidden", "data-dest-group": "mqtt" },
    h("label", { class: "field-hint", for: `lb-host-${cam.id}` }, "MQTT broker host", hostIn),
    h("div", { class: "form-row" },
      h("label", { class: "field-hint", for: `lb-port-${cam.id}` }, "Port", portIn),
      h("label", { class: "field-hint", for: `lb-topic-${cam.id}` }, "Topic", topicIn)));
  channelSel.addEventListener("change", () => {
    const isWeb = channelSel.value === "webhook";
    webhookFields.classList.toggle("hidden", !isWeb);
    mqttFields.classList.toggle("hidden", isWeb);
  });

  const enabledIn = h("input", {
    id: `lb-enabled-${cam.id}`, "data-field": "enabled", type: "checkbox",
  });
  // Set the property directly: h() maps `checked` to an attribute, which only
  // seeds defaultChecked — a stale value would survive the first toggle read.
  enabledIn.checked = lane ? Boolean(lane.enabled) : true;

  const form = h("form", {
    class: "form-col", "data-form": "lane-policy", novalidate: true,
    onSubmit: async (e) => {
      e.preventDefault();
      const btn = form.querySelector("button[type=submit]");
      setErr(null);

      // Allow window: both times or neither — a half window is malformed and
      // the server fail-closes it with a 400, so name it here first.
      const start = startIn.value;
      const end = endIn.value;
      if ((start && !end) || (end && !start)) {
        setErr("Set both start and end for the allow window, or clear both for no schedule (24/7).");
        return;
      }
      let allowWindow = null;
      if (start && end) {
        allowWindow = { start, end };
        const tz = tzIn.value.trim();
        if (tz) allowWindow.tz = tz;
        if (selected.size) allowWindow.days = [...selected];
      }

      // Barrier destination. Required to ARM — a lane with no destination can
      // never open, and the worker's "OPEN suppressed" log is not a UI state.
      const channel = channelSel.value;
      const barrierConfig = readBarrierConfig(form, channel);
      const enabled = enabledIn.checked;
      if (enabled && !barrierConfig) {
        setErr("Enter the barrier destination to arm this lane, or uncheck “Armed” to save a disarmed lane — a lane with no destination can never open.");
        return;
      }

      btn.disabled = true;
      try {
        await api(`/api/cameras/${cam.id}/lane`, {
          method: "PUT",
          body: JSON.stringify({
            name: form.querySelector("[data-field=name]").value.trim(),
            barrier_channel: channel,
            barrier_config: barrierConfig,
            allow_window: allowWindow,
            cooldown_sec: Number(form.querySelector("[data-field=cooldown]").value || 30),
            enabled,
          }),
        });
        toast(enabled ? "Lane armed — plate reads are now evaluated" : "Lane saved (disarmed)", { tone: "ok" });
        // Re-read so the summary, the `configured` flag and the whitelist
        // re-render from the source of truth rather than a local guess.
        navigate("cameras", { id: cam.id, tab: "gate-access" });
      } catch (err) {
        // err.detail is the SSRF guard / window validator speaking — show it
        // inline next to the fields it concerns, not as a generic toast.
        setErr(err.message || "Could not save the lane");
      } finally {
        btn.disabled = false;
      }
    },
  },
    h("h3", {}, creating ? "Arm this camera as a lane" : "Lane configuration"),
    h("p", { class: "muted" },
      "An armed lane evaluates every plate read against the whitelist and the allow window below, and sends one OPEN per plate per cooldown. The worker ignores this camera entirely while the lane is disarmed."),
    h("label", { class: "field-hint", for: `ln-name-${cam.id}` },
      "Lane name (optional — defaults to the camera name)",
      h("input", {
        id: `ln-name-${cam.id}`, "data-field": "name",
        value: (lane && lane.name) || "", placeholder: cam.name,
        autocomplete: "off",
      })),
    h("div", { class: "form-row" },
      h("label", { class: "field-hint", for: `lb-cooldown-${cam.id}` },
        "Cooldown (seconds between opens per plate)",
        h("input", {
          id: `lb-cooldown-${cam.id}`, "data-field": "cooldown", class: "mono",
          type: "number", min: "0", max: "3600",
          value: String((lane && lane.cooldown_sec) ?? 30),
        })),
      h("label", { class: "field-hint", for: `lb-enabled-${cam.id}` },
        "Armed", enabledIn)),
    h("div", {},
      h("div", { class: "field-hint" }, "Allow window (blank both = 24/7)"),
      h("div", { class: "form-row" },
        h("label", { class: "field-hint", for: `lw-start-${cam.id}` }, "Start", startIn),
        h("label", { class: "field-hint", for: `lw-end-${cam.id}` }, "End", endIn)),
      h("label", { class: "field-hint", for: `lw-tz-${cam.id}` },
        "Timezone (blank = camera timezone)", tzIn),
      h("div", { class: "lane-days", role: "group",
        "aria-label": "Restrict to weekdays (all off = every day)" }, dayChips)),
    h("div", {},
      h("div", { class: "field-hint" }, "Barrier destination"),
      h("div", { class: "form-row" },
        h("label", { class: "field-hint", for: `lb-channel-${cam.id}` }, "Channel", channelSel)),
      destNote,
      webhookFields,
      mqttFields),
    errSlot,
    h("div", { class: "form-row" },
      h("button", { class: "primary", type: "submit", "data-act": "lane-save" },
        creating ? "Arm lane" : "Save lane"),
      h("button", {
        class: "ghost", type: "button",
        onClick: () => navigate("cameras", { id: cam.id }),
      }, "Done")),
  );
  return h("div", { class: "card" }, form);
}

function readBarrierConfig(form, channel) {
  const q = (f) => form.querySelector(`[data-dest="${f}"]`);
  if (channel === "webhook") {
    const url = (q("url").value || "").trim();
    return url ? { url } : null;
  }
  const host = (q("host").value || "").trim();
  if (!host) return null;
  const cfg = { host, port: Number((q("port").value || "1883").trim()) };
  const topic = (q("topic").value || "").trim();
  if (topic) cfg.topic = topic;
  return cfg;
}

// ── whitelist ───────────────────────────────────────────────────────────

function whitelistCard(cam, lane, editable) {
  const items = (lane && lane.whitelist) || [];
  const card = h("div", { class: "card", "data-role": "lane-whitelist" },
    h("h3", {}, "Whitelisted plates"),
    h("p", { class: "muted" },
      "Only the keyed plate digest is stored — the plate you enroll is normalized, matched against future reads as a hash, and never kept in plaintext. Cross-reference a row against a gate event by its digest."),
  );

  if (!editable) {
    card.append(
      items.length
        ? h("ul", { class: "mask-rows" }, items.map(whitelistRowReadonly))
        : h("p", { class: "muted" }, "No plates whitelisted."));
    return card;
  }

  // Enroll: the plate is echoed once (normalized, the operator's own input) so
  // the operator sees how it normalized; it is not stored or re-shown by the UI.
  const enrollErr = h("div", { class: "form-error", "data-role": "enroll-error", role: "alert" });
  const plateIn = h("input", {
    id: `wl-plate-${cam.id}`, "data-field": "plate",
    placeholder: "AB12 CDE", autocomplete: "off", required: true,
    "aria-label": "Plate to enroll",
  });
  const labelIn = h("input", {
    id: `wl-label-${cam.id}`, "data-field": "label",
    placeholder: "Optional note (e.g. “delivery van”) — not the plate",
    autocomplete: "off", "aria-label": "Optional note",
  });
  const enrollForm = h("form", {
    class: "form-col", "data-form": "lane-whitelist", novalidate: true,
    onSubmit: async (e) => {
      e.preventDefault();
      const btn = enrollForm.querySelector("button[type=submit]");
      enrollErr.textContent = "";
      const plate = plateIn.value.trim();
      if (!plate) { enrollErr.textContent = "Enter a plate."; return; }
      btn.disabled = true;
      try {
        const res = await api(`/api/cameras/${cam.id}/lane/whitelist`, {
          method: "POST",
          body: JSON.stringify({ plate, label: labelIn.value.trim(), allow_window: null }),
        });
        toast(`Enrolled ${res.query.plate}`, { tone: "ok" });
        navigate("cameras", { id: cam.id, tab: "gate-access" });
      } catch (err) {
        // 400 covers a plate with no alphanumerics or a note that duplicates
        // the plate (a plaintext-plate store with a worse name); 409 = dup.
        enrollErr.textContent = err.message || "Could not enroll the plate";
      } finally {
        btn.disabled = false;
      }
    },
  },
    h("div", { class: "form-row" },
      h("label", { class: "field-hint", for: `wl-plate-${cam.id}` }, "Plate", plateIn),
      h("label", { class: "field-hint", for: `wl-label-${cam.id}` }, "Note", labelIn)),
    h("div", { class: "form-row" },
      h("button", { class: "primary", type: "submit", "data-act": "whitelist-enroll" },
        "Enroll plate")),
    enrollErr,
  );
  card.append(enrollForm);

  if (!items.length) {
    card.append(h("p", { class: "muted" },
      "No plates whitelisted yet — every read is denied and logged until a plate is enrolled."));
  } else {
    card.append(h("ul", { class: "mask-rows", "data-role": "whitelist-rows" },
      items.map((e) => whitelistRowEditable(e, cam))));
  }
  return card;
}

function whitelistRowReadonly(e) {
  return h("li", { class: "mask-row", "data-entry": e.id },
    h("span", { class: "mask-swatch", "aria-hidden": "true" }),
    h("span", { class: "mask-desc" },
      h("span", { class: "mono", title: e.plate_hash }, shortId(e.plate_hash)),
      h("span", { class: "muted text-xs" }, e.label || "no note")),
    // Only render the cell when a per-entry window exists (the enroll form
    // sends none; per-entry windows are set through the API).
    e.allow_window ? h("span", { class: "muted text-xs" }, windowSummary(e.allow_window)) : null,
    h("span", { class: "muted text-xs" }, fmtDateTime(e.created_at)),
  );
}

function whitelistRowEditable(e, cam) {
  const row = h("li", { class: "mask-row", "data-entry": e.id },
    h("span", { class: "mask-swatch", "aria-hidden": "true" }),
    h("span", { class: "mask-desc" },
      h("span", { class: "mono", title: e.plate_hash }, shortId(e.plate_hash)),
      h("span", { class: "muted text-xs" }, e.label || "no note")),
    e.allow_window ? h("span", { class: "muted text-xs" }, windowSummary(e.allow_window)) : null,
    h("span", { class: "muted text-xs" }, fmtDateTime(e.created_at)),
    h("span", { class: "form-row", "data-role": "actions" },
      h("button", {
        class: "ghost", "data-act": "whitelist-revoke",
        onClick: () => {
          // Revoke denies access on the next read — confirm in place, the same
          // reveal-then-confirm pattern as deleting an alert route.
          const zone = h("span", { class: "confirm-zone", "data-role": "revoke-confirm" },
            h("span", { class: "muted text-xs" }, "Revoke this plate?"),
            h("span", { class: "form-row" },
              h("button", {
                class: "ghost", "data-act": "whitelist-revoke-confirm",
                onClick: async (ev) => {
                  ev.currentTarget.disabled = true;
                  try {
                    await api(`/api/lanes/whitelist/${e.id}`, { method: "DELETE" });
                    toast("Plate revoked — the next read is denied", { tone: "ok" });
                    navigate("cameras", { id: cam.id, tab: "gate-access" });
                  } catch (err) {
                    toast(err.message || "Could not revoke the plate", { tone: "error", timeout: 6000 });
                  }
                },
              }, "Revoke"),
              h("button", {
                class: "ghost", type: "button",
                onClick: (ev) => { ev.currentTarget.closest(".confirm-zone").remove(); },
              }, "Cancel")));
          row.querySelector("[data-role=actions]").replaceWith(zone);
        },
      }, "Revoke")),
  );
  return row;
}

// ── removal ──────────────────────────────────────────────────────────────
// Destroys the policy AND the whole whitelist (cascade) and disarms the
// camera. Reveal-then-confirm like the alerts route delete: one click is not
// enough to erase every enrolled plate, but typed-confirm (as camera removal
// uses) would be overkill for a re-armable object.

function removeLaneCard(cam, lane, editable) {
  if (!lane || !editable) return null;
  const zone = h("div", { class: "confirm-zone hidden", "data-role": "remove-confirm" },
    h("span", { class: "muted text-xs" },
      "This removes the lane and every whitelisted plate. The camera stops evaluating plate reads immediately."),
    h("div", { class: "form-row" },
      h("button", {
        class: "ghost", "data-act": "lane-remove-confirm",
        onClick: async (e) => {
          e.currentTarget.disabled = true;
          try {
            await api(`/api/cameras/${cam.id}/lane`, { method: "DELETE" });
            toast("Lane removed — camera disarmed", { tone: "ok" });
            navigate("cameras", { id: cam.id, tab: "gate-access" });
          } catch (err) {
            toast(err.message || "Could not remove the lane", { tone: "error", timeout: 6000 });
          }
        },
      }, "Remove lane and whitelist"),
      h("button", {
        class: "ghost", type: "button", "data-act": "lane-remove-cancel",
        onClick: () => zone.classList.add("hidden"),
      }, "Cancel")));
  return h("div", { class: "card", "data-role": "remove-lane" },
    h("h3", {}, "Remove this lane"),
    h("p", { class: "muted" },
      "Disarms the camera and deletes the lane policy and its whole whitelist. Gate events already recorded stay in the audit trail; the lane itself cannot be restored (re-arming creates a fresh one)."),
    h("button", {
      class: "ghost", "data-act": "lane-remove",
      onClick: () => { zone.classList.remove("hidden"); },
    }, "Remove lane…"),
    zone,
  );
}

// ── formatting ───────────────────────────────────────────────────────────

function windowSummary(win, defaultTz) {
  if (!win || !win.start || !win.end) return "Any time (24/7)";
  const tz = win.tz || defaultTz || "camera tz";
  const days = Array.isArray(win.days) && win.days.length
    ? win.days.slice().sort((a, b) => a - b)
        .map((n) => (DAYS.find((d) => d[1] === n) || [String(n)])[0]).join(", ")
    : "every day";
  return `${win.start}–${win.end} ${tz} · ${days}`;
}





