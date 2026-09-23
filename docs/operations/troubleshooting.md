# Troubleshooting

Symptom → likely cause → fix, organized by area. Start with
[gathering facts](#gathering-facts-first) — most issues resolve in two minutes
once you know which layer is wrong.

If you're setting up for the first time, [installation.md](installation.md)
has the step-by-step path and a post-install verification checklist.

---

## Gathering facts first

```bash
# Layer 1 — is the API process up? (unauthenticated)
curl -s http://localhost:8000/health/live
# => {"status": "alive", ...}

# Layer 2 — is the DB + storage reachable? (unauthenticated)
curl -s http://localhost:8000/health/ready
# => {"status": "ready", "components": {"database": {"status":"ok"}, "storage": {"status":"ok"}}}
# "degraded" tells you WHICH component is down — read the "detail" string.

# Layer 3 — component statuses, model names, live transcodes (authed)
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@localsight.local","password":"YOUR_PASSWORD"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s http://localhost:8000/api/system/health -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8000/api/live/streams  -H "Authorization: Bearer $TOKEN"
```

Where the logs are:

| Install | How to read logs |
|---------|------------------|
| Bare metal | The `uvicorn` and `python -m apps.worker` consoles. Add `LOG_LEVEL=DEBUG` to `.env` and restart for verbose output. |
| Docker Compose | `docker compose -f infrastructure/compose/docker-compose.yml logs -f api worker postgres nginx` |
| Local rig | `python scripts/local_cctv_rig.py watch`, or read `.rig/logs/{api,worker,broker,capture}.log` |

The worker logs the per-camera pipeline startup, model load/downgrade
decisions, reconnect attempts, and retention sweeps — start there for any
ingestion question.

---

## Startup & boot

### The app refuses to start: "JWT_SECRET … missing or placeholder"
`gen_env.py` was skipped or `.env` isn't loaded. The app treats a missing,
empty, or `CHANGE_ME_*` secret as a hard failure rather than inventing one.

```bash
python scripts/gen_env.py        # writes .env with fresh random secrets
```

If `.env` already exists it **refuses to overwrite** — delete it first only if
you truly want new secrets (this invalidates all sessions and encrypted data).

### The app refuses to start: "BOOTSTRAP_ADMIN_PASSWORD … too short (min 12 chars)"
The bootstrap admin password must be **≥12 characters** — there is no default.
Set a strong value in `.env` (or let `gen_env.py` mint a random one) and
restart. This only applies on first boot (the admin is created only when no
users exist); on an initialized DB, change the password via the **Account**
view or the `user:manage` API.

### `Address already in use` on port 8000
Another process (often a stale LocalSight, or the local rig's API) holds the
port.

```bash
lsof -i :8000                    # find the PID
# macOS:  kill <PID>
# Linux:  kill <PID>   (or fuser -k 8000/tcp)
```

If it's a stale rig instance, tear it down properly instead:
`python scripts/local_cctv_rig.py stop` (SIGTERM lets the worker flush
in-flight recorder segments and reap its ffmpeg children — a blunt `kill -9`
can truncate evidence and leave zombies).

### Python `ModuleNotFoundError: psycopg` / `pgvector`
You set `DATABASE_URL=postgresql+psycopg://...` without the driver. Production
installs should use `requirements-prod.txt`:

```bash
pip install -r requirements-prod.txt    # psycopg[binary], psutil, onnxruntime
```

### Login fails on a fresh install
Almost always one of: the bootstrap password was never recorded (regenerate by
deleting `.env` **and** the DB, since the admin only seeds when no users
exist); the account is locked after `MAX_LOGIN_ATTEMPTS` (5) failed tries —
wait `LOCKOUT_MINUTES` (15); or you're hitting the API through a proxy that
strips the `Authorization` header. The error message distinguishes "Incorrect
email or password" from "Account temporarily locked".


---

## Cameras & ingestion

### Camera stays OFFLINE / `unreachable`
The worker writes camera liveness (`ONLINE→streaming`,
`RECONNECTING→unstable`, `OFFLINE→unreachable`), so a stuck `offline` means
the worker never got a frame. In order:

1. **Is the worker running?** `ps aux | grep apps.worker` — the API alone will
   never ingest.
2. **SSRF allowlist** — the guard blocks private/loopback/metadata
   destinations by default. A LAN camera is rejected until its CIDR is listed:
   `SSRF_ALLOWLIST=192.168.0.0/16`. Note the **worker** needs this too (it's
   the process that dials the camera) — in compose, both services carry it.
3. **URL correctness** — the dashboard's **+ Add camera → verify** step pulls
   one real frame before committing; use it to catch typos, wrong channel
   numbers, and dead credentials up front.
4. **Exotic IP spellings** — `2130706433`, `0x7f.0.0.1`, `0177.0.0.1` and
   IPv4-mapped IPv6 (`::ffff:10.0.0.5`) are canonicalized before the
   allowlist check, so they can't sneak past it — but they can confuse *you*
   when eyeballing logs. Use dotted-quad.
5. **Camera side** — RTSP enabled? ONVIF enabled? Correct port (554)? Digest
   auth algorithm (some VIGI firmware is picky — see
   [`docs/integrations/tplink-vigi.md`](../integrations/tplink-vigi.md))?

### Camera flaps ONLINE → RECONNECTING repeatedly
Network loss between the host and the camera, or the camera can't sustain two
streams. The gateway reconnects with backoff automatically. Check switch/NVR
uptime, and confirm the **substream** (not just the main stream) is configured
— AI runs on the substream. Reduce `AI_INFERENCE_FPS` if the camera is
starved.

### "stream unreachable" (503) in the add-camera wizard
The verify step actually pulled a frame and failed — this is the feature
working. Re-check the URL/credentials; for ONVIF devices, use
`POST /api/cameras/onvif/streams` to get a known-good RTSP URI first.

### No detections / events at all
- **Detector mode** — `AI_DETECTOR=reference` emits `person` only and uses a
  motion gate; a still scene with no movement produces nothing by design.
- **Motion gate** — `AI_MOTION_GATE_ENABLED=true` with
  `AI_MOTION_THRESHOLD=0.004` skips frames below a mean delta. For dim indoor
  scenes, lower the threshold; for noisy outdoor scenes, raise it.
- **Privacy masks** — a detection whose center is inside a mask (or whose box
  overlaps ≥50%) is dropped *before* tracking. Check the camera's Masks tab.
- **Confidence** — lower `AI_CONFIDENCE_THRESHOLD` (default 0.45) if the
  detector is under-reporting.
- **Rules** — `AI_RULES_ENABLED=true`? Individual rules have their own
  enabled/cooldown state in the rules editor; replay a fixture through
  **Replay & verdict** (or `POST /api/rules/test`) to confirm the engine sees
  your tracks.

### ONNX detector logs a "downgrade to reference"
Expected when no model is staged, or when `onnxruntime` isn't installed. It's
an *optional* capability degrading loudly, not a crash. To use real
multi-class detection, stage a model and set `AI_DETECTOR=onnx` — see
[onnx-detector.md](onnx-detector.md). If you *did* stage one and still see a
downgrade, check that `AI_MODEL_NAME`/`AI_MODEL_VERSION` match the registry
entry and that the SHA-256 in `models/registry.json` matches the file on disk

---

## Recording, live view & media

### No recordings / empty Timeline
Recording needs **FFmpeg on `PATH`** *and* a configured **main stream** URL.
`VideoSegment` rows are only listed once their file actually landed
(`size_bytes > 0`), so a scrub can never land in a hole that 404s — but it also
means a half-written segment is invisible until complete.

```bash
ffmpeg -version | head -1        # must resolve
curl -s http://localhost:8000/api/cameras/{id}/recordings -H "Authorization: Bearer $TOKEN"
```

Confirm `RECORD_ENABLED=true` (default) and that the camera has a
`stream_url` (main stream). In Docker the image bundles FFmpeg; on bare metal
install it (`brew install ffmpeg` / `apt-get install ffmpeg`).

### Live tile says "Stream unavailable" / `running: false` with PID 0
The live gateway transcodes the **substream** via ffmpeg. Check
`GET /api/live/streams` — a `pid: 0` / `running: false` entry means ffmpeg
never started: usually ffmpeg missing from PATH, or the camera has no
`substream_url`. Install ffmpeg or set the substream; stop and restart the
tile (or `POST /api/live/{camera_id}/stop` then reload).

### Live transcodes accumulate / CPU stays high
They shouldn't — the reaper stops any transcode with no viewer for
`LOCALSIGHT_LIVE_IDLE_TIMEOUT_SEC` (300 s) or older than
`LOCALSIGHT_LIVE_MAX_DURATION_SEC` (4 h), and the API stops all of them on
shutdown. If they persist:

```bash
curl -s http://localhost:8000/api/live/streams -H "Authorization: Bearer $TOKEN"  # check idle_sec
curl -X POST http://localhost:8000/api/live/{camera_id}/stop -H "Authorization: Bearer $TOKEN"
```

Still stuck? Check the API logs for reaper-thread errors. Live CPU is meant to
be proportional to *actual viewing*, not camera count.

### Event clip returns no segments
The event's time window has no overlapping `VideoSegment` rows — either
recording was off/disabled at that moment, the camera was offline, or the
segments aged out past retention. Confirm `RECORD_ENABLED=true` and that the
Timeline shows coverage for that hour.

### Signed URL / media 403 or "expired"
Signed URLs are HMAC-SHA256 over `key:exp`, capped at **1 hour** on both sign
and verify. They're bearer credentials, not permanent links — don't archive
them. A 403 on a fresh URL usually means the server's `MASTER_ENCRYPTION_KEY`
rotated since the URL was issued, or the URL was minted by a different
deployment.

---

## Alerts

### Alerts not arriving at all
1. **Is a route configured?** `GET /api/alerts/routes` — no routes, no
   notifications.
2. **Is the rule type matched?** A route targets a `rule_type` (or `*` for
   all). A route for `intrusion` won't carry `anpr` events.
3. **Camera scope** — a route scoped to one camera ignores the others.
4. **Daily budget** — `GET /api/alerts/budget`. A camera at its cap stops
   *notifying* but still stores every event/clip/snapshot (evidence is never a
   budget item). `0` = unlimited.
5. **Is the worker running?** The alert sender is a worker background thread.
6. **Test delivery**: `POST /api/alerts/test` pushes a synthetic alert through
   every route and reports `{"delivered": N}` — the fastest end-to-end check.

### Webhook route: delivery fails / route creation rejected
Route destinations are SSRF-validated **at create time** — a webhook pointing
at private/loopback/metadata space is refused outright (127.0.0.1 is rejected
unless you explicitly allowlist loopback). For an internal receiver, add its
CIDR to `SSRF_ALLOWLIST`. If a previously-working webhook stops delivering,
the receiving host moved to a blocked range.

### Alert storms / the same alert firing repeatedly
Set `cooldown_sec` on the route — within the window, the same
(channel × rule_type × camera_id) key suppresses re-firing. `0` disables
suppression. For a per-camera daily ceiling, set `alert_budget_per_day`
(Alerts screen) or the platform default `ALERT_BUDGET_PER_CAMERA_PER_DAY`.

### MQTT not connecting
Verify broker reachability, credentials, and a valid topic template
(`{camera_id}` / `{rule_type}` expand). An **unreachable broker is silently
skipped** — it never crashes the worker — so check the deliveries feed and
worker logs rather than expecting a stack trace.

### ntfy push not working
Check the `server` URL, the `topic` name, and that `auth_token` is set for
private topics. An unreachable server returns `0 delivered` (visible via
`POST /api/alerts/test`).

### Email not working
Port 465 = implicit TLS (SMTPS); 587 = STARTTLS — both handled automatically.
Confirm SMTP credentials and that the account isn't rate-limited by the
provider. Test with `POST /api/alerts/test`.


---

## Storage, retention & performance

### Disk filling up / "storage full" alerts
Disk-pressure pre-alarms fire at `DISK_WARN_PCT` (0.80) and
`DISK_CRITICAL_PCT` (0.90) so a full disk never eats evidence silently. The
worker's retention sweeper deletes expired recordings/events/snapshots/
embeddings/audit/refresh-tokens **and their storage objects** hourly, in
chunked transactions. So:

- **Keep the worker running** — no worker, no sweeping, and both DB and disk
  grow unbounded.
- Shorten retention (`RETENTION_RECORDINGS_DAYS` etc., or per-camera
  `retention`), or add capacity: `python scripts/capacity.py --cameras N ...`.

### Prometheus scrape returns 401
`/api/system/metrics` needs either a user session or the static
`METRICS_SCRAPE_TOKEN`. Set it on the api service **and** mirror it in
`infrastructure/monitoring/prometheus.yml` (`authorization.credentials`) —
they must match — then restart both.

### High CPU / slow dashboard
- Lower `AI_INFERENCE_FPS` (default 5) — the biggest single lever; inference
  runs per camera on the substream.
- Keep `AI_MOTION_GATE_ENABLED=true` so still frames skip detection.
- Pin `AI_ORT_INTRA_THREADS` when many cameras share one CPU box — ORT's
  default pool over-subscribes and slows *every* camera down.
- A GPU/NPU engages automatically when a real backend is present and a model
  is staged; the `reference` detector never needs one.
- Live transcodes cost CPU only while someone is watching.

### SQLite "database is locked"
Dev SQLite runs in WAL + `synchronous=NORMAL` so API reads don't block behind
worker commits. If you still see lock contention under heavy load, that's the
signal to move to PostgreSQL (`DATABASE_URL=postgresql+psycopg://...`) — the
compose stack ships pgvector.

---

## Still stuck?

Gather these before asking for help — they turn a guess into an answer:

1. Output of the three health curls above (`health/live`, `health/ready`,
   `api/system/health`).
2. The **worker** console/log around the problem (it names the camera, the
   model, and the transition).
3. `FFMPEG` presence, `AI_DETECTOR`, `SSRF_ALLOWLIST`, and the install path
   (venv / compose / rig).
4. A redacted `.env` — **never** paste `JWT_SECRET`, `MASTER_ENCRYPTION_KEY`,
   `BOOTSTRAP_ADMIN_PASSWORD`, `DB_PASSWORD`, or camera credentials. Rotate
   any secret you suspect was shared.

File bugs via GitHub Issues with Python version, stack trace, and reproduction
steps. **Security issues must not go in a public issue** — use GitHub Private
Vulnerability Reporting instead.

(`sha256sum models/staged/<file>`).
