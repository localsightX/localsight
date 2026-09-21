# UI Wave-3 conventions brief (for parallel view modules)

Every view module in this wave MUST follow these rules — they come from
`AGENTS.md` (CSP, XSS, sessions), the design tokens in `ui/tokens.css`
(the visual system), and established patterns in the existing views.

## Hard constraints (violations = rewrite)

1. **CSP**: server sends `style-src 'self'` — NO inline `style=`, no `<style>`,
   no `element.style.foo =`. Data-driven geometry uses **SVG attributes** (`x`,
   `width`, `points`) or **CSS classes**. Canvas drawing (mask editor) sets
   `.width/.height` **properties** (not styles) — that is CSP-legal.
2. **XSS**: build ALL DOM via `ui/core/dom.js` (`h()`, `svgEl()`, `render()`).
   The `html` prop is forbidden. Event props are lowercased (`onClick` → click
   listener). `render(el, ...children)` is variadic — wrap sibling lists in an
   array: `render(el, [a, b, c])`.
3. **No third-party assets.** hls.js is the only allowed vendor file (already
   vendored). No chart libraries — SVG/canvas by hand.
4. **Sessions**: every fetch via `api()` from `core/api.js` (silent 401 refresh
   included). Never use raw fetch/XHR. RBAC via `can("perm")` — hide what the
   role can't do; where a whole view is read-only for the role, say so in text.
5. **Honest states everywhere**: loading (skeletons from `core/states.js`),
   empty (with the ONE action that fixes it), error (banner + Retry), partial
   ("2 of 5 cameras unreachable" — don't hide the good 3). Never a spinner
   with no context; never a silently-empty panel.
6. **One color per meaning**: use `tone()` from `core/format.js` → classes
   `ok` / `warn` / `bad` / `info`. Camera NAMES (not hex ids) in primary
   text; ids only in `.mono .muted` secondary lines.
7. **Keyboard**: every interactive thing is a real `<button>`/`<a>`/`<input>`
   (focusable, Enter-activatable). Drawers: Escape closes, focus trapped,
   focus restored on close (copy `views/event_drawer.js` pattern).
8. **Double-submit guard (C-13)**: disable the submit button on submit,
   re-enable in `finally`. Show API errors inline near the field or as a
   toast — never alert().
9. **Forms + secrets**: stream URLs and credentials are write-only —
   password inputs, never echoed back, `autocomplete="new-password"` on
   create forms. The API 400s on unsafe URLs; surface `err.detail` verbatim
   (it's the SSRF guard speaking).
10. **Payload discipline**: lazy-load view data when the view mounts, not at
    app boot. No polling except where Wave 2 already does it (Overview).

## Shared vocabulary (import from `core/`)

- `h(tag, props, ...kids)`, `svgEl(tag, props, ...kids)`, `render(el, ...kids)`
  — DOM builders. `$("sel")` is in `core/dom.js` too.
- `api(path, {method, body})` — fetch layer; throws `ApiError` (has `.status`,
  `.detail`).
- `can(perm)`, `getMe()` — RBAC + session info.
- `toast(msg, {tone, timeout})` — transient notices.
- `skeletonRows(el, n)`, `skeletonCards(el, n)`, `emptyState({icon,title,hint,action})`,
  `errorState(err, {noun, onRetry})`, `errorBanner(msg, {onRetry})` — states.
- `fmtTime, fmtDateTime, fmtRelative, fmtBytes, fmtDuration, label, tone, shortId`
  — formatting; NEVER hand-roll a date string.
- `navigate(view, params)`, `replace()`, `onView()` — router. Camera detail =
  `navigate("cameras", {id: cameraId, tab: "masks"})` style params (the
  cameras view reads `params.id` to decide list vs detail).

## CSS (append to `components.css` under a `/* ── Wave 3 … ── */` header)

- Tokens exist: `--radius-s/l`, `--sp-1..10`, `--shadow-1/2`, text sizes
  `--text-xs..3xl`. NEVER hardcode a hex/px that a token already provides.
- Existing classes you can reuse: `.card`, `.pill`, `.dot`, `.table-scroll`,
  `.toolbar`, `.form-row`, `.ghost`/`.primary` buttons, `.muted`, `.mono`,
  `.field-hint`, `.drawer`, `.drawer-scrim`, `.drawer-head/body/foot`,
  `.tabs` (add if missing — tab bar with `.active`).
- New classes get `w3-` or domain prefixes (`.cam-grid`, `.mask-editor`,
  `.route-row`, `.wz-step`) to avoid collisions; keep them in the Wave-3
  section so the diff reads as one unit.

## Backend endpoints available (all JSON unless noted)

- Cameras: `GET /api/cameras`, `GET|PUT|DELETE /api/cameras/{id}`,
  `GET /api/cameras/{id}/snapshot` (JPEG bytes; 404/409/503 honest),
  `GET|PUT /api/cameras/{id}/rules`, `POST /api/onvif/discover`
  `{timeout?:5}` → `{devices:[{ip, port, manufacturer, model, ...}]}`,
  `POST /api/onvif/streams` (probe profiles), `POST /api/cameras`
  (create with stream_url/substream_url, name…),
  `POST /api/cameras/presets/vendor-presets` (known-vendor URL builders).
- Rules (per camera): `{"camera_id", "rules":[{type,rule_id?,a?,b?,zone?,direction?,dwell_sec?,min_dwell_sec?,stationary_sec?,threshold?,labels?}]}`.
  Types: `line_cross` (a,b points 0..1), `intrusion`/`loitering`/`object_left`/`crowd`
  (zone = [[x,y],…] polygon). PUT validates each spec server-side; 400 detail
  explains the first bad rule. The editor always sends a unique `rule_id`
  (stored ids preserved, new ones generated): uniqueness is enforced over the
  effective id, so two id-less rules of the same type would collide and be
  rejected.
- Persons: `GET /api/persons` (now with `faces_enrolled`), `POST /api/persons`,
  `DELETE /api/persons/{id}` (cascade), `GET /api/persons/{id}/references`
  → `{image_bytes_retained:false, references:[{id,model_version,dimension,
  quality_score,created_at}]}`, `POST /api/persons/{id}/references`
  (multipart `file`, ≤10MB, image only).
- Alerts: `GET|POST /api/alerts/routes` (RouteCreate: rule_type, camera_id?,
  channel: webhook|email|push|mqtt, enabled, cooldown_sec, config{}),
  `DELETE /api/alerts/routes/{id}`, `POST /api/alerts/test` (test-fire),
  `GET /api/alerts/events?limit=` (delivery log), `GET /api/alerts/budget`
  (R3.6 per-camera daily budget; usage comes from the same analytic-event
  count the worker seeds from). Budget writes go through
  `PUT /api/cameras/{id}` with `alert_budget_per_day` (null = platform
  default, 0 = unlimited, 1-10000).
- Users: `GET /api/users` ({id,email,full_name,role,is_active,mfa_enabled}),
  `POST /api/users` (email, password ≥12, role ∈ ADMIN|SECURITY_OPERATOR|
  ANALYST|VIEWER, full_name), `DELETE /api/users/{id}`.
- System/privacy: `GET /api/system/health`, `GET /api/timeline`
  (recording coverage), settings knobs via retention days on cameras
  (`retention: {days}` per camera).

## Personas to respect

- SECURITY_OPERATOR: no `user:manage` — Users nav item hidden, Alerts
  admin visible, can enroll people.
- ANALYST: no `person:enroll`, no `camera:configure` — read-only cameras
  (mask/rules editors replaced by a read-only note), Live view visible.
- ADMIN: everything.

## Definition of done per module

- `node --check` clean; no console errors on its flows;
- probe-able via `[data-…]` attributes on key elements (the Wave-3 probe
  will click through: card → detail tab → editor → save → toast);
- states tested by actually stopping the dev server (error banner with Retry);
- `components.css` additions inside the Wave-3 section only.
