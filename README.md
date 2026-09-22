# LocalSight

Local-first, privacy-by-design video intelligence platform. Continuously ingests
RTSP/RTSPS/ONVIF streams from NVRs/IP cameras, runs **local** AI detection, tracking,
behavior analytics, and (optional) ANPR, records the main stream on-prem, and serves
a secure web dashboard for searching, reviewing, alerting, and live viewing.

Designed for 24/7 on-premises operation: **no video leaves the site by default**,
everything runs fully offline, and every security-sensitive action is encrypted at
rest and audited.

## Principles (non-negotiable)

1. **Local-first / cloud-optional** — all AI inference is local. Cloud is opt-in only.
2. **Privacy by design** — embeddings/plates/identities are encrypted; recognition is off by default.
3. **Minimum video movement** — AI runs on the low-res substream; the main stream is recorded.
4. **Security-first** — Argon2id, RBAC, envelope encryption, SSRF guard, audit log, signed URLs.
5. **Fail safe** — one camera dying never takes down the platform; automatic reconnect + backoff.

## The console, in practice

Real screenshots of the running product (demo dataset, admin role):

| | |
|---|---|
| ![Overview](docs/img/overview.png) | ![Events](docs/img/events-bulk.png) |
| **Overview** — NOC screen: cameras, events, health, alert feed | **Events** — sortable, bulk-select, audited CSV export |
| ![Drawer](docs/img/event-drawer.png) | ![Account](docs/img/account.png) |
| **Evidence drawer** — playback, context, signed clip export | **Account** — password, TOTP MFA, sessions, timezone |

More in [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) (every section shows its
screen) and the [product tour on the project site](https://jatinkray.github.io/localsight.github.io/).

## Capabilities

| Area | Status | Notes |
|------|--------|-------|
| Auth / RBAC / MFA / audit | ✅ production | Argon2id, JWT rotation, TOTP MFA, lockout, RBAC, immutable audit log |
| Envelope encryption (at rest) | ✅ production | Stream URLs, embeddings, snapshots, plate data, alert config, MQTT credentials |
| SSRF egress guard | ✅ production | Blocks private/loopback/metadata unless `SSRF_ALLOWLIST` set |
| Person/object detection | ✅ production | `reference` backend = CPU motion proxy (person-only). `onnx` backend for multi-class (person/vehicle/bicycle/motorcycle/bus/truck/animal/bag/package) via staged ONNX model; lazy `onnxruntime`, GPU auto-detected. Both ultralytics export layouts supported (row-major + transposed v8/v11), COCO labels mapped to the platform vocabulary |
| Tracking | ✅ production | SORT-style motion-prediction tracker for stable IDs; appearance ReID needs a staged embedding model |
| Behavior analytics (rules) | ✅ production | Line-cross, intrusion, loitering, object-left/removed, crowd — per-camera JSON |
| ANPR / LPR | ✅ pipeline; ⚙️ model-dependent | Cropped + throttled + deduped; plate values encrypted at rest. Real OCR needs a staged plate detector+OCR model |
| Continuous recording | ✅ production | Main-stream segmented MP4 → StorageProvider; `VideoSegment` rows; requires FFmpeg |
| Live view | ✅ production | Authorized LL-HLS gateway (ffmpeg transcode of substream); requires FFmpeg |
| Alerts | ✅ production | Webhook / email / MQTT / push routed per rule_type+camera via `AlertRoute`; per-route cooldown to prevent alert storms; webhook URLs SSRF-validated |
| Analytics / BI | ✅ production | People counting, occupancy trend, dwell, event breakdown, heatmaps |
| VLM semantic search | ✅ endpoint; ⚙️ model-dependent | `GET /api/analytics/search` (reference embedder unless a CLIP/VLM model is staged) |
| Camera compatibility | ✅ ONVIF + presets | TP-Link VIGI/Tapo + ONVIF discovery + multi-vendor presets (Axis, Hanwha, Hikvision, Dahua, Reolink, Bosch, GB/T 28181) |

⚙️ = works out of the box with a deterministic **reference** implementation; swap in a
staged model via the `ModelRegistry` for production accuracy. There are no insecure
defaults and no network calls to third parties.

## Quick start (local, zero infra)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/gen_env.py        # writes .env with fresh random secrets
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
# open http://localhost:8000  (dashboard served at /)
```

The app **refuses to start** if `JWT_SECRET` / `MASTER_ENCRYPTION_KEY` are missing or
still placeholders — there are no insecure defaults.

Default DB is SQLite (`sqlite:///./localsight.db`); switch to PostgreSQL by setting
`DATABASE_URL=postgresql+psycopg://...` (see compose for a pgvector setup).

Run the AI/video worker (separate process) in another shell:

```bash
python -m apps.worker          # processes cameras; records + analyzes when streams are configured
```

The worker also runs the **retention sweeper** (deletes expired recordings/events/
snapshots) and the **alert sender** (fans analytic events out to configured channels)
as background services.

> Recording and live view require **FFmpeg** on `PATH`. The Docker image bundles it;
> for local installs install `ffmpeg` (e.g. `apt-get install ffmpeg`).

## Local CCTV rig (test-drive on a MacBook)

`scripts/local_cctv_rig.py` turns a MacBook into a one-camera NVR site — real
FaceTime footage end-to-end through the exact operator path (RTSP broker →
LocalSight → recording + AI + live view):

```bash
python scripts/local_cctv_rig.py setup          # brew: ffmpeg + mediamtx; .venv deps
python scripts/local_cctv_rig.py start          # boot the rig (camera permission required)
python scripts/local_cctv_rig.py verify         # 15-point end-to-end check
python scripts/local_cctv_rig.py status         # processes / streams / camera state
python scripts/local_cctv_rig.py watch          # tail all rig logs
python scripts/local_cctv_rig.py stop           # tear down cleanly
```

The rig sets `SSRF_ALLOWLIST=127.0.0.0/8` (loopback broker), 30 s recording
segments, and its own dev secrets under `.rig/` (gitignored). Grant Camera
permission to your terminal when macOS prompts, or use `start --source synthetic`
for a moving test pattern. Details: `python scripts/local_cctv_rig.py --help`.

The rig runs the **staged YOLO11n detector** (registry-verified ONNX, CoreML
on Apple Silicon) when `onnxruntime` is installed — real multi-class detection
on the live feed. Remove the `AI_DETECTOR` line in the rig env (or uninstall
`onnxruntime`) to fall back to the reference motion detector. The staged model
lives in `models/staged/` with its SHA-256 in `models/registry.json` — the
operator-side staging path any production model takes.

## Tests

```bash
pip install -r requirements.txt
pip install pytest pytest-cov httpx numpy
rm -f test_localsight.db
pytest -q                       # 274 tests: auth, RBAC, SSRF, encryption, analytics, pipeline, API, live, alerts, forensic search, ONNX detector, perf gates, review regressions, rule grammar + replay tester + alert budgets
```

Coverage report: `pytest --cov=packages --cov=apps --cov-fail-under=50` (currently 78%).

The suite includes regression tests from the architectural review
(`docs/reviews/CODE_ANALYSIS_REPORT.md`): `Event.detail` round-trips through the
ANPR/alerts/search endpoints, privacy-mask suppression, FK cascade deletes,
detection write-gating, and live-stream stop/reap.

## CI/CD

Every push to `main` and every PR runs a 10-job GitHub Actions pipeline:

- **lint** — ruff + mypy
- **unit tests** — pytest against SQLite (274 tests, ~60s)
- **integration** — pytest against PostgreSQL + pgvector
- **dependency audit** — pip-audit (OSV/PyPI) + Safety (pyup.io)
- **CodeQL SAST** — GitHub code scanning for Python
- **Semgrep SAST** — community + OWASP + secrets rules
- **container scan** — Trivy SARIF, CRITICAL/HIGH CVE check
- **docker build** — multi-platform (amd64/arm64) push to GHCR
- **quality gate** — blocks merge on lint/test failures

All security tools are free tier. SBOM (SPDX) is generated per release.
See `docs/operations/ci-cd-pipeline.md` for the full pipeline reference and
`CONTRIBUTING.md` for branch/commit/PR conventions.

## Capacity planning

```bash
python scripts/capacity.py --cameras 8 --main-bitrate-mbps 4 --sub-bitrate-mbps 0.4 --ai-fps 5
```

## Deployment (Docker Compose)

```bash
python scripts/gen_env.py
docker compose -f infrastructure/compose/docker-compose.yml --env-file .env up --build
```

Brings up PostgreSQL+pgvector, the API, the AI worker, and an nginx TLS proxy.

## Configuration reference

All config is via environment (see `.env.example`). Highlights:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AI_DETECTOR` | `reference` | `reference` \| `onnx` \| `tensorrt` \| `openvino` \| `tflite`. Multi-class needs a staged model. |
| `AI_MODEL_NAME` / `AI_MODEL_VERSION` | `detector` / `latest` | ModelRegistry lookup for the staged detector. |
| `AI_INFERENCE_FPS` | `5` | Substream frames per second fed to the detector. |
| `AI_CONFIDENCE_THRESHOLD` | `0.45` | Min detection confidence. |
| `AI_IOU_THRESHOLD` | `0.50` | Tracker association threshold. |
| `AI_IDENTITY_RECOGNITION_ENABLED` | `false` | Face identification (biometric) — opt-in, lawful-basis required. |
| `AI_RULES_ENABLED` | `true` | Behavior-analytics rule engine. |
| `AI_ANPR_ENABLED` | `false` | ANPR/LPR pipeline. |
| `RECORD_ENABLED` | `true` | Main-stream recording. |
| `RECORD_SEGMENT_SECONDS` | `300` | Segment length. |
| `RETENTION_RECORDINGS_DAYS` | `7` | Recording retention (auto-swept). |
| `RETENTION_EVENTS_DAYS` | `30` | Analytic-event retention (auto-swept). |
| `RETENTION_SNAPSHOTS_DAYS` | `14` | Snapshot retention (auto-swept). |
| `RETENTION_EMBEDDINGS_DAYS` | `90` | Enrollment-embedding retention. |
| `RETENTION_AUDIT_DAYS` | `365` | Audit-log retention. |
| `SSRF_ALLOWLIST` | `""` | Comma-separated CIDRs (e.g. `192.168.0.0/16`) permitted for camera/webhook egress. |
| `STORAGE_BACKEND` | `local` | `local` \| `s3`. |
| `STORAGE_LOCAL_ROOT` | `./data/storage` | Local recording/snapshot store. |
| `ALERT_WEBHOOK_URL` | `""` | Optional global fallback webhook for all events. |
| `ALERT_BUDGET_PER_CAMERA_PER_DAY` | `0` | Per-camera alert-notification cap per UTC day (`0` = unlimited); overridable per camera. Notifications only — events/clips are always stored. |
| `LOCALSIGHT_LIVE_DIR` | `./data/live` | Directory for transcoded live HLS segments (served at `/live-media`). |

## Camera / NVR compatibility

LocalSight is RTSP/ONVIF-native.

- **TP-Link VIGI / Tapo** work out of the box — `POST /api/cameras/from-nvr` provisions a
  whole VIGI NVR (all channels) in one call; `GET /api/cameras/presets` returns vendor
  URL templates. See `docs/integrations/tplink-vigi.md`.
- **ONVIF discovery** — `POST /api/cameras/onvif/discover` finds devices on the LAN;
  `POST /api/cameras/onvif/streams` returns RTSP URIs for a device profile. Both are
  SSRF-validated and audited.
- **Multi-vendor presets** — `GET /api/cameras/presets` includes Axis, Hanwha, Hikvision
  (ISAPI), Dahua (CGI), Reolink, Bosch, ONVIF, and GB/T 28181 templates. Use
  `POST /api/cameras/presets/build` to construct a URL (credentials are never echoed back).
- **Remove a camera** — `DELETE /api/cameras/{id}` (or **Remove camera** on the camera's
  dashboard page) deletes the camera and cascades its recordings, events, snapshots,
  detections and tracks, stops its live transcode immediately, and the worker stops
  ingesting within ~30 s. Audited, typed-confirm in the UI, gated on `camera:configure`.

Cameras must be reachable from the server (isolated VLAN recommended). The SSRF guard
blocks private/loopback/cloud-metadata destinations unless their CIDR is in
`SSRF_ALLOWLIST`.

## Behavior analytics (rules)

Configure per camera via `PUT /api/cameras/{id}/rules`:

```json
[
  {"type": "line_cross", "rule_id": "r1", "a": [0.5, 0.0], "b": [0.5, 1.0], "direction": 1},
  {"type": "intrusion", "rule_id": "z1", "zone": [[0.4,0.4],[0.6,0.4],[0.6,0.6],[0.4,0.6]]},
  {"type": "loitering", "rule_id": "l1", "zone": [[0.0,0.0],[1.0,0.0],[1.0,1.0],[0.0,1.0]], "dwell_sec": 10},
  {"type": "object_left", "rule_id": "o1", "zone": [[0.0,0.0],[1.0,0.0],[1.0,1.0],[0.0,1.0]], "stationary_sec": 20},
  {"type": "crowd", "rule_id": "c1", "zone": [[0.0,0.0],[1.0,0.0],[1.0,1.0],[0.0,1.0]], "threshold": 5}
]
```

Coordinates are normalized `[0,1]` frame coordinates. Matched events become
`Event` rows (typed `event_type`) and are fanned out to alert channels.

## Alerts

Create delivery routes per analytic event type and (optionally) camera:

```bash
curl -s -X POST http://localhost:8000/api/alerts/routes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"rule_type":"intrusion","channel":"webhook","config":{"url":"https://hooks.example.com/lv"}}'
# channels: webhook | email | push ; "*" matches all event types
```

- Webhook URLs are SSRF-validated before any outbound call.
- `ALERT_WEBHOOK_URL` (env) is a global fallback for all events.
- All route changes are audited; secret config is encrypted at rest and never returned to clients.
- `POST /api/alerts/test` sends a synthetic test alert to verify delivery (no camera needed).

## Live view

1. `POST /api/live/ticket` issues a short-lived, encrypted, camera-scoped ticket.
2. `GET /api/live/{camera_id}/play?ticket=...` validates the ticket and starts an
   ffmpeg LL-HLS transcode of the camera substream; it returns the manifest at
   `/live-media/{camera_id}/index.m3u8`. The RTSP URL and credentials are never exposed.
3. Point an HLS player at the manifest. The media gateway honors only valid tickets.
4. Transcodes are lifecycle-managed: idle streams (no playback for
   `LOCALSIGHT_LIVE_IDLE_TIMEOUT_SEC`, default 300 s) and streams older than
   `LOCALSIGHT_LIVE_MAX_DURATION_SEC` (default 4 h) are reaped automatically;
   `POST /api/live/{camera_id}/stop` stops one explicitly (dashboard control).

## Privacy masks

`PUT /api/cameras/{id}` accepts `privacy_masks`: normalized `{x, y, w, h}`
rectangles designating zones excluded from ALL processing. Detections whose
center falls inside a mask — or with ≥50% bbox overlap — are suppressed
before tracking, so masked geometry produces no detections, no tracks, no
snapshots, and no events. Masks are stored with the camera and enforced in
the worker pipeline (`CameraPipeline._is_masked`).

## Analytics & BI

All require `analytics:view`. Example:

```bash
curl -s "http://localhost:8000/api/analytics/people-count?camera_id=$CAM&start=2026-03-01T08:00:00Z&end=2026-03-01T10:00:00Z" -H "Authorization: Bearer $TOKEN"
# also: /api/analytics/occupancy, /api/analytics/dwell, /api/analytics/breakdown, /api/analytics/heatmap
```

### Semantic (NL) search

```bash
curl -s "http://localhost:8000/api/analytics/search?q=person%20near%20the%20gate&camera_id=$CAM" -H "Authorization: Bearer $TOKEN"
```

Ranks archived events by cosine similarity to the query. A real CLIP/VLM backend drops
in behind the same interface for image-aware search.

## Privacy & compliance

- Face identification is **off by default**; enable only with a documented lawful basis.
- Event analytics are light-touch (no biometric retention by default).
- Plates and embeddings are **encrypted at rest**; plate events store an encrypted blob
  plus an anonymized hash.
- An immutable audit log records every sensitive action (camera changes, alert routes,
  live-ticket issuance, ONVIF discovery/streams).

## Repository layout

```
apps/
  api/        FastAPI app: routers, config, db, bootstrap, dependencies
  worker/     AI/video worker: per-camera pipelines, stream gateway, retention + alert sender
packages/
  domain/     ORM models, Pydantic schemas, event aggregation, analytics/BI
  security/   passwords, JWT, RBAC, crypto, SSRF, rate-limit, MFA, audit, headers
  ai/         Detector/Tracker/Face/Embedder/Matcher + reference impls + pipeline
              detectors.py (ONNX/TensorRT/OpenVINO/TFLite), rules.py, anpr.py, vlm.py
  video/      frame sources, safe FFmpeg invocation, resilient stream gateway,
              onvif.py (discovery/streams), presets.py (vendors), recorder.py (segmented MP4)
  storage/    StorageProvider (local + S3), signed expiring URLs, path-traversal safe
  notify/     alert channels (webhook / email / push) + routing
  observability/  Prometheus metrics + structured JSON logging
infrastructure/  docker, compose, nginx, monitoring
docs/             architecture, security, operations, integrations, api
scripts/          gen_env.py, capacity.py
ui/               static dashboard (served at /)
tests/            unit + security + integration (274 tests)
```

## Status

Implemented and tested: auth (Argon2id, JWT rotation, MFA, lockout), RBAC, envelope
encryption, immutable audit log, SSRF egress guard (camera + webhook + ONVIF), signed
media URLs, path-traversal-safe storage, event aggregation, pluggable AI pipeline,
**multi-class detector backends (ONNX/TensorRT/OpenVINO/TFLite) + reference fallback**,
**SORT-style tracker**, **behavior rule engine**, **ANPR pipeline (encrypted plates)**,
**continuous main-stream recording**, **LL-HLS live view**, **webhook/email/push alerts
with DB routing + per-camera daily alert budgets**, **analytics/BI endpoints**, **VLM semantic search endpoint**, camera/NVR
management (TP-Link + ONVIF discovery + multi-vendor presets), persons/enrollment, events
search, timeline, capacity model, Docker Compose, and a runnable dashboard.

Reference (swappable, not production-tuned) until a model is staged: detection is a
CPU motion proxy emitting `person` only by default; ANPR OCR and VLM embedding are
deterministic placeholders; appearance-based ReID is not yet implemented (motion
prediction only). Drop in YOLO/RT-DETR (ONNX), a plate detector+OCR, and a CLIP/VLM model
via the `ModelRegistry` to reach production accuracy — the interfaces are unchanged.

See `docs/` for architecture decision records, threat model, ERD, security controls, and
the operations runbook. Operator-facing usage documentation is in
`docs/USER_GUIDE.md`; engineering-agent orientation (invariants, workflow)
is in `AGENTS.md`; the full architectural review with evidence and fix
rationale is in `docs/reviews/CODE_ANALYSIS_REPORT.md`.
