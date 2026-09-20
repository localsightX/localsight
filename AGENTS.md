# AGENTS.md — LocalSight Engineering Agent Guide

This document orients any engineering agent (AI or human) working in this
repository: what the system is, where things live, the invariants that must
never be violated, and the workflow expected of every change.

## What this system is

LocalSight is a **local-first video intelligence platform**: cameras on a
private LAN, AI inference on the customer's own hardware, no cloud dependency.
The security posture (local processing, envelope encryption, privacy by
design) is the product — treat regressions against it as functional bugs, not
style issues.

```
apps/api/        FastAPI app: routers, bootstrap (runtime), config, deps
apps/worker/     per-camera AI pipelines, recorder, retention, alert fan-out
packages/domain/ ORM models, schemas, timeutil, events
packages/security/ passwords, JWT, RBAC, crypto (envelope), SSRF, rate-limit, MFA, audit
packages/ai/     detector/tracker/face/matcher interfaces + reference impls + pipeline
                 detectors.py (ONNX/TensorRT/OpenVINO/TFLite + COCO→platform label
                 map), face_onnx.py (staged SCRFD detector + ArcFace embedder),
                 registry.py (SHA-256 model staging), rules.py, anpr.py, vlm.py
packages/video/  frame sources, safe FFmpeg argv builder, stream gateway,
                 onvif, presets, tplink.py (VIGI/Tapo URL builders), recorder
packages/storage/ StorageProvider ABC + local + S3 implementations, signed URLs
packages/notify/ webhook/email/push/MQTT alert channels + routing
packages/observability/ metrics registry + structured logging
ui/              vanilla-JS dashboard (served at /): views/ (dashboard, live +
                 dvr_scrubber, events, timeline, cameras + mask/rules editors +
                 wizard, analytics, people, alerts admin, users, audit, privacy,
                 account, login) and core/ (dom, api, router, palette, density,
                 shortcuts, telemetry, toast, states, format)
models/          registry.json (name/path/SHA-256/source/license). staged/
                 weights are operator-provided and gitignored (BYOM):
                 yolo11n-detect.onnx, faces/det_500m.onnx, faces/w600k_mbf.onnx
infrastructure/  Dockerfile, compose stack, nginx, monitoring
docs/            architecture, security, operations, integrations, api, reviews
scripts/         gen_env.py, capacity.py, seed_dev_data.py, local_cctv_rig.py,
                 ui_audit.py / ui_design_metrics.py / ui_maturity_scan.py /
                 ui_probe_flows.py / ui_probe_wave1..4.py (Playwright)
tests/           unit + security + API + integration; tests/ui = Playwright e2e
```

## Architectural rules (do not break)

1. **Dependency direction**: `apps/` → `packages/`, never `packages/` → `apps/`.
   Cross-package work happens through interfaces (`StorageProvider`, `Detector`,
   `Notifier`), which are ABCs — implement ALL abstract methods in any new
   backend, and add new abstract methods only with default-free care (see
   `verify_signed_url`/`put_stream` on StorageProvider for why completeness is
   enforced).

2. **Secrets never leave the host in plaintext**:
   - RTSP URLs, plate text, embeddings → envelope-encrypted via `CryptoBox`
     before storage.
   - Media delivery → app-relative signed URLs (`/api/video/...?exp=...&sig=...`),
     HMAC-SHA256 over `key:exp` with the master key. Never return absolute S3
     URLs to a client; the app proxies remote objects. Signed-URL TTLs are
     **capped at 1 h on both sign and verify** (`max(1, min(expires_sec, 3600))`
     and `exp ≤ now+3660`) — a signed URL is a bearer credential, not a public
     link; a leaked signer must not be able to mint permanent URLs. Media bytes
     stream through `StorageProvider.size()` + `read_range()` (HTTP Range,
     206/416) — never buffer a segment into the heap.
   - Alert route destinations (webhook/mqtt/push/smtp) are SSRF-gated at
     **create time** (`_validate_route_destination`): webhooks through the full
     URL validator, host-bearing channels through a synthetic `https://host`
     probe. No fixture carve-outs — 127.0.0.1 is rejected unless the operator
     explicitly allowlists loopback.
   - Webhook/email/MQTT payloads → filter `Event.detail` through
     `_ALERT_DETAIL_KEYS` (worker) — ciphertext (`plate_enc`) never goes to
     third-party channels.

3. **Frontend is CSP-native and XSS-proof by construction** (`ui/`):
   - The server sends `style-src 'self'` — inline `style=` and `<style>` are
     BLOCKED. Data-driven geometry (timeline, charts) must use **SVG
     attributes** (`x`, `width`) or CSS classes, never inline styles. The old
     timeline rendered 0-width segments for exactly this reason (audit C-1).
   - No `innerHTML` with user/API data, ever. Build DOM via `ui/core/dom.js`
     (`h()`, `svgEl()`, `render()`); the `html` prop is forbidden by design.
     Stored XSS via person labels was live before this (audit C-2).
   - No build step, no framework: ES modules served statically. One allowed
     third-party asset: ui/vendor/hls.light.min.js (LL-HLS in Chromium,
     lazy-loaded only on Live view; Safari uses native HLS). Keep total
     payload small; performance on edge hardware is a product feature.
   - Session handling: access token in memory ONLY; refresh token in
     `sessionStorage` (rotates server-side on every use). Never persist an
     access token to `localStorage`. `ui/core/api.js` is the single fetch
     layer — all API calls go through it (silent refresh-on-401 included).

4. **Subprocess safety**: FFmpeg/ffprobe are invoked with argv lists built
   in-code (`packages/video/ffmpeg.py`), never `shell=True`, and every
   operator-supplied URL passes `validate_egress_url` first. Two load-bearing
   details from the RTSP end-to-end fix: `build_args` **re-validates with the
   deploy-time allowlist** (defense in depth — validating without it made a
   private-network camera fail inside ffmpeg and the worker thread die silently
   after its reconnect budget), and the decoder's stderr goes to `DEVNULL` (a
   chatty ffmpeg on an undrained 64 KB pipe deadlocks mid-encode). Default
   transport is `-rtsp_transport tcp`. Always `terminate()` **and** `wait()` —
   an unreaped child is a zombie (see `sources.py`, `recorder.py`).

5. **Storage streaming**: large media moves through `put_stream` — never read
   a recording into the heap. A 4 Mbps 300 s segment is ~150 MB; high-bitrate
   NVRs exceed 1 GB per segment.

6. **Privacy masks are load-bearing**: `Camera.privacy_masks` (normalized
   `{x,y,w,h}` rectangles) suppress detections whose center falls in the mask
   or with ≥50% bbox overlap (`CameraPipeline._is_masked`). If you touch the
   detection path, masks must still be applied BEFORE tracking, and
   `test_privacy_masks_suppress_detections` must pass.

7. **Retention is compliance**: the worker's `_sweep_retention` enforces every
   declared knob (recordings, events, snapshots, embeddings, audit) plus
   expired refresh tokens. New persistent data classes must join this sweep
   or get their own documented lifecycle.

8. **Deletion cascades are DB-enforced**: person → embeddings (GDPR erasure),
   user → refresh tokens, camera → detections/tracks/events/segments. New
   child tables of existing entities get `ondelete=` on the FK plus storage
   cleanup where media objects are involved (see `delete_camera`).

9. **Models are supply-chain artifacts**: weights are staged by an operator
   into `models/staged/` and declared (name, version, path, SHA-256, source,
   license) in `models/registry.json`. `ModelRegistry.verify` refuses a hash
   mismatch and **nothing is ever fetched from a URL at runtime**. Model-backed
   backends fail closed (`build_detector` raises, per `make_detector`); an
   *optional* capability (the face chain) logs a downgrade to the reference
   implementation instead of killing the worker. Staged COCO detectors are
   wrapped by `_LabelMappedDetector` so rules/tracks/alerts/analytics only ever
   see the platform vocabulary (`person`/`vehicle`/`bicycle`/`motorcycle`/`bus`/
   `truck`/`animal`/`bag`/`package`) — COCO-only classes are dropped.
   Enroll and recognize must use the *same* embedder model version: vectors are
   only compared within a version, so mixing them silently never matches.

10. **Playback is signed-URL only, from the archive**: the live-view DVR
    (`ui/views/dvr_scrubber.js`) resolves a wall-clock moment through
    `GET /api/cameras/{id}/recordings` and `/recordings/at` (both `video:view`,
    both issuing short-lived signed URLs) and swaps the `<video>` src to the
    recorded segment — it never touches the RTSP URL, and `VideoSegment` rows
    are only listed once their file actually landed (`size_bytes > 0`), so a
    scrub can never land in a hole that 404s.

## Key runtime facts

- **Dev**: SQLite, tests run against an in-memory-ish session-scoped app
  (`conftest.py`); `.venv` at repo root; `pytest tests/ -q` must pass
  (**currently 125 tests**, up from 111 — `test_surveillance.py` carries 68 of
  them). The UI e2e suite is separate: `pytest tests/ui -m ui` collects 45
  more (170 total) — it boots a real uvicorn server + seeded throwaway DB and
  drives it with Playwright (needs `playwright`, `pytest-playwright`,
  chromium, ffmpeg); `pytest tests/` never collects it (deselected via the `ui`
  marker, pytest.ini).
- **Dev-parity FK enforcement**: `bootstrap.build` enables
  `PRAGMA foreign_keys=ON` on SQLite so cascade/integrity behavior matches
  PostgreSQL. Never remove this — it's what keeps dev bugs from hiding until
  production.
- **Local CCTV rig** (`scripts/local_cctv_rig.py`, dev-only, stdlib-only):
  turns a MacBook into a one-camera NVR site — FaceTime (or `--source
  synthetic`) → ffmpeg → local `mediamtx` RTSP broker (loopback) → the real
  API + worker. `setup` / `start` / `status` / `verify` / `watch` / `stop`,
  process-managed via PID files under `.rig/` (gitignored). It exports
  `SSRF_ALLOWLIST=127.0.0.0/8` (loopback broker — required for LocalSight to
  dial it), 30 s `RECORD_SEGMENT_SECONDS` for fast evidence, and its own dev
  secrets. Camera URLs use the `127.0.0.1` IP literal, never `localhost`
  (the SSRF allowlist matches hostnames against CIDRs). `verify` is a
  ~15-check end-to-end probe (stream → recording → events → live) — the
  fastest real-feedback loop for anything touching video/AI.
- **Model staging**: `models/registry.json` currently declares three staged,
  hash-verified artifacts — `detector` (YOLO11n, COCO), `face_detector`
  (SCRFD 500M), `face_embedder` (ArcFace MobileFaceNet w600k). All from
  public upstreams with their licenses recorded. Point `AI_DETECTOR` at `onnx`
  (and install `onnxruntime`) to use them; the rig env does this by default.
  See `docs/operations/onnx-detector.md` for the operator staging procedure.
- **Camera liveness is written by the worker**: `persist_camera_status` maps
  gateway transitions onto `Camera.status`/`health`/`last_seen`
  (`ONLINE→streaming`, `RECONNECTING→unstable`, `OFFLINE→unreachable`), and a
  bounded ≤1-per-30 s heartbeat touches `last_seen` while frames flow. Before
  this, nothing wrote those columns after creation, so every camera read
  OFFLINE forever even while streaming.
- **Prod (compose)**: PostgreSQL + pgvector, `DATABASE_URL=postgresql+psycopg://`
  (driver installed via `requirements-prod.txt`), nginx TLS frontend.
- **Security hardening invariants (PR #23)** — these are load-bearing, don't
  soften them:
  - `TRUST_PROXY_HEADERS` (default **false**): `X-Forwarded-For` is
    attacker-controlled input. `client_ip()` keys rate limits and audit
    `source_ip` on the **socket address** unless the flag is set; behind the
    shipped nginx front (which *appends* the socket addr to any incoming
    header) set `TRUST_PROXY_HEADERS=1` to use the **last** hop — never the
    first, which the client itself controls.
  - SSRF validation normalizes before deciding: exotic IPv4 spellings
    (decimal `2130706433`, hex `0x7f.0.0.1`, octal `0177.0.0.1`, short
    inet_aton forms) are canonicalized to dotted-quad, and IPv4-mapped IPv6
    literals (`::ffff:10.0.0.5`) are unwrapped (`_normalize_ip_literal` /
    `_canonical` in `packages/security/ssrf.py`) — both would otherwise
    bypass the private-range blocklist. Literal IPs are pre-checked even when
    the local resolver maps them elsewhere (macOS/Windows resolve
    `0177.0.0.1` to `177.0.0.1`).
  - Bootstrap admin seeding **refuses to start** without a strong
    `BOOTSTRAP_ADMIN_PASSWORD` (≥12 chars); `scripts/gen_env.py` mints a
    random one and prints it once. There is no default password.
  - The rate limiter caps its bucket table (`max_buckets=10000`) and
    opportunistically evicts fully-refilled buckets — an unauthenticated
    attacker minting distinct source IPs must not grow memory unbounded.
  - Login bodies are length-bounded (`email ≤320`, `password ≤256`,
    `mfa_code ≤16`) — bound the Argon2 verify input.
- **Schema evolution**: `Base.metadata.create_all` + `bootstrap._ensure_columns`
  for additive columns on existing tables. Each ALTER runs in its own
  transaction; only "duplicate column"/"already exists" errors are swallowed.
  Alembic is the intended destination (see docs/reviews report D-5) — additive
  changes must be added to `_ensure_columns` until then.
- **Worker model**: one thread per camera, ffmpeg per thread; SIGTERM sets the
  stop event so recorders flush and children are reaped. The alert sender and
  retention sweeper run on their own daemon threads.
- **Live view**: transcodes are tracked in `_live_streams` with idle/max-age
  reaping; `LOCALSIGHT_LIVE_DIR` sets the shared root for both the ffmpeg
  output and the `/live-media` mount (single source: `apps/api/domain_live_cfg.py`).
  Each live tile also carries the **DVR scrubber** (1 h window, SVG track,
  signed-URL segment swaps) and the event drawer links a clip assembled from
  the same segments (`GET /api/events/{id}/clip`).
- **Rebrand back-compat**: LocalSight was LocalVision. `domain_live_cfg._env`
  honors the legacy `LOCALVISION_*` names when the `LOCALSIGHT_*` name is
  unset (new name wins), so an upgrade never silently resets live config.

## Authentication & authorization quick reference

- Argon2id passwords; JWT access (15 min) + rotating refresh tokens tracked
  server-side; TOTP MFA (stdlib, RFC 6238).
- Login always performs exactly ONE Argon2 verify (fixed `_DUMMY_HASH` for
  nonexistent accounts) — do not "optimize" this into a branch skip; it's the
  user-enumeration defense. **Order matters**: the password verify (or dummy
  verify) runs BEFORE the lockout report — computing `locked` first and
  returning 423 pre-verify leaked account existence (fast 401 vs slow 423).
  Login/refresh/logout bodies are length-bounded (`email ≤320`,
  `password ≤256`, `mfa_code ≤16`).
- Account lifecycle endpoints (all backing the Account view, wave M2):
  `POST /api/auth/password` (rotates, revokes other sessions),
  `GET /api/auth/sessions` + `POST /api/auth/sessions/{token_id}/revoke`,
  `POST /api/auth/mfa/setup` + `/mfa/verify`. Every one is audited and
  rate-limited (`login` 1/s burst 10, `refresh` 2/s burst 20, `password`
  0.2/s burst 5).
- Admin-side (`user:manage`): `GET /api/users/{id}/sessions`,
  `POST /api/users/{id}/sessions/revoke-all`, `POST /api/users/{id}/mfa-reset`
  (the latter two are typed-confirm in the Users view); users can never revoke
  another user's sessions. Deleting a user is typed-email confirm.
- RBAC: roles → permissions (`packages/security/rbac.py`); endpoints declare
  `require_permission("...")`. Permission names live in the RBAC tables.
- Rate limiting: in-process token bucket keyed by `client_ip()` — the socket
  address by default; the **last** `X-Forwarded-For` hop only when
  `TRUST_PROXY_HEADERS=1` (the shipped nginx appends the socket addr, so the
  last entry is the only client-unspoofable one). The bucket table is capped
  at 10000 entries with eviction of fully-refilled buckets (memory-bound
  under source-IP rotation).

## Quality gates

- `pytest tests/ -q` — all green (**172 passed**, 45 deselected) in ~60 s.
- `pytest tests/ui -m ui` — the browser suite (Wave 5 + maturity waves); run it
  before merging UI changes (needs chromium via `playwright install`, ffmpeg).
  45 tests: journeys (12), a11y/axe, CSP console, design tokens, flows,
  perf budgets, 12-state visual regression.
- `ruff check .` — `ruff.toml` defines the rule set; keep changed files clean,
  don't mass-reformat untouched files.
- `mypy packages apps --ignore-missing-imports` — keep new code typed
  (`Mapped[]`, `| None` unions).
- `python scripts/local_cctv_rig.py verify` — end-to-end video/recording/AI/live
  probe on a real box (the only gate that exercises ffmpeg + RTSP + storage
  together); use it for anything on the video path.
- `python scripts/ui_maturity_scan.py` — read-only 19-state scan; each M-wave
  adds assertions so the gaps it found can't return.
- CI (`.github/workflows/ci.yml`, 10 jobs): `lint`, `test` (unit, SQLite),
  `integration` (PostgreSQL), `security-deps` (pip-audit + Safety),
  `sast-codeql`, `sast-semgrep`, `container-scan` (Trivy), `docker` (build/push
  on main), the merge-blocking `ui-e2e` job (journeys, a11y/axe, CSP console
  gate, visual regression, perf budgets), and `quality-gate` which needs all of
  them green.

## Workflow for any change

1. Branch from `main` (`fix/...`, `feat/...`, `docs/...`).
2. Read the relevant module top-to-bottom before editing; docstrings carry
   the security rationale (e.g. why argv lists, why dummy hashes).
3. Write the fix + the test that would have caught the bug. The existing
   suite missed real production defects because paths were unexercised —
   regression tests for any fix are mandatory (see the F-01 tests).
4. Run the full suite; check `git status` for accidental artifacts (dbs,
   coverage files, `ui_e2e_artifacts_*/`, `ui_maturity/` — all gitignored).
5. Update docs for user-visible changes: README capabilities, `docs/api/` when
   endpoints change, `docs/operations/runbook.md` for ops procedures, and
   `docs/USER_GUIDE.md` (with a real screenshot) for operator-facing changes.
   Anything touching the video/AI path also updates
   `docs/operations/onnx-detector.md` or `docs/integrations/` as applicable.
6. UI changes: run the matching wave probe (`scripts/ui_probe_wave*.py`) plus
   the maturity scan assertions for the view you touched — a redesign gate you
   eyeballed is a gate that regresses.
7. Conventional Commits (`fix:`, `feat:`, `security:`, `perf:`, `docs:`, ...).

## AI backends: real vs. reference (know which one you're looking at)

The interfaces are the contract; implementations are swapped, never "improved".

**Real, staged, hash-verified (operator-staged; the repo ships no weights):**

- **Object detection** — `ONNXDetector` running a staged Ultralytics YOLO11n
  export (`models/staged/yolo11n-detect.onnx`, AGPL-3.0; gitignored BYOM
  artifact — hash-declared in `models/registry.json`) via
  lazy `onnxruntime` (CUDA auto-detected; CoreML on Apple Silicon). Enable with
  `AI_DETECTOR=onnx` + `AI_MODEL_NAME=detector`. Both ultralytics export layouts
  are supported (row-major and the transposed v8/v11 head) and COCO labels are
  remapped into the platform vocabulary by `_LabelMappedDetector`. The local
  CCTV rig runs this by default.
- **Identity recognition** — `packages/ai/face_onnx.py`: SCRFD 500M face
  detector + ArcFace MobileFaceNet embedder (`build_face_chain`: 5-point
  landmark alignment, 112×112, 512-d L2-normalized vectors, cosine band ~0.4–0.5),
  gated behind `AI_IDENTITY_RECOGNITION_ENABLED` (default **false** — biometric;
  lawful basis required). `bootstrap.build` loads the staged chain for
  *enrollment* regardless of the flag, so enroll→recognize vectors are
  comparable even when recognition is switched on later (vectors only compare
  within a model version — mixing embedders silently never matches). The
  staged face weights come from the InsightFace model zoo, whose banner reads
  "ALL models are available for non-commercial research purposes only" —
  recorded verbatim in `models/registry.json`; commercial production use of
  the face chain needs a license-cleared checkpoint swap (BYOM).

**Reference placeholders (deterministic, not production-accurate):**

- `ReferenceMotionDetector` — CPU frame-differencing that emits `person` only;
  the default `AI_DETECTOR` and the no-model fallback.
- `ReferenceFaceDetector` / `ReferenceEmbedder` — a deterministic image-hash
  embedding used when staged face models are absent (the worker logs a
  downgrade rather than failing).
- ANPR OCR (`anpr.py`), VLM/CLIP semantic search (`vlm.py`), and appearance
  ReID (tracking is SORT-style motion prediction only).

Do NOT "fix" a reference implementation to be smarter — stage a model and swap
it via the interfaces (rule 9). `docs/operations/onnx-detector.md` documents the
operator staging procedure and the backend table.

## Where the bodies are buried

`docs/reviews/CODE_ANALYSIS_REPORT.md` is the full architectural review with
evidence, impact, and fix rationale for every recent change (F-01 … F-14,
D-1 … D-7, M-1 … M-38). Read it before large refactors; it explains why the
code looks the way it does now.

The UI/UX layer has its own regression contract in `tests/ui/` (real-browser
pytest suite: journeys, per-view axe-core scans, zero-console-errors under the
live CSP, token/design assertions, refresh-on-401/empty/error/double-submit
flows, 12-state visual regression against committed baselines in
`ui_audit/baselines/` with `UPDATE_BASELINES=1` to regenerate, and perf budgets
— TTI < 3s, JS < 300KB, view latency < 2.5s). CI's `ui-e2e` job runs it on
every PR and it is merge-blocking via the quality gate. The suite caught its
first defect during its own build (a `<dt>/<dd>` outside a `<dl>`) — the gate
works. Opt-in UI marks: `ui/core/telemetry.js` (local ring buffer, default OFF,
Privacy view toggle, JSON download — nothing leaves the browser tab).

Per-view Playwright probes reproduce any finding and assert the fixed ones stay
fixed: `scripts/ui_probe_flows.py`, `ui_probe_wave1.py`, `ui_probe_wave2.py`,
`ui_probe_wave3.py`, `ui_probe_wave4.py` — run the matching probe for any view
you touch; they are self-provisioning (create their own throwaway users). The
Wave-4 probe embeds the axe gate: `scripts/vendor/axe.min.js` is a PROBE-ONLY
asset (never served, never shipped — the app's one vendor dependency remains
hls.js); keep new views clean by running the probe, not by eyeballing contrast.
The audit scripts reproduce any finding: `scripts/ui_audit.py`,
`scripts/ui_design_metrics.py`, `scripts/ui_probe_flows.py`.

`scripts/ui_maturity_scan.py` is the read-only 19-state console scan
(screenshots + computed-style telemetry into `ui_maturity/`, gitignored) and
doubles as a gate: it asserts the data-surface and density affordances that
matter operationally — sortable-table headers, bulk-selection boxes, CSV
export, the single `#toast` aria-live host, "Copy link" filters, the Ctrl-K
command palette (`ui/core/palette.js`), and drawer labelling
(`bulk_boxes`/`toast_host`/`copy_link`/`palette_wired`/`drawer_labelled`), so
regressions can't return. Frontend conventions for new views live in
`ui/WAVE3_CONVENTIONS.md` (CSP-safe SVG geometry, h()/render() DOM
construction, RBAC gating, honest empty/error states, write-only credentials,
typed-confirm deletes).

**Supporting docs:** `docs/USER_GUIDE.md` is the operator-facing manual
(every section shows a real screenshot from `docs/img/`); the engineering-agent
orientation is this file; `docs/operations/onnx-detector.md` stages a detector;
`docs/operations/runbook.md` and `docs/operations/ci-cd-pipeline.md` cover ops
and the 10-job pipeline; `docs/integrations/tplink-vigi.md` covers TP-Link
VIGI/Tapo/NVR; `docs/security/SECURITY.md` and `docs/architecture/*` (system,
ERD, ADRs, threat model) round out the design record.
