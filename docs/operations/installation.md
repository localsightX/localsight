# Installation & Setup

How to get LocalSight running for the first time — prerequisites, three install
paths, first-run bootstrap, and a verification checklist. For day-to-day
operations see [runbook.md](runbook.md); for diagnosing problems see
[troubleshooting.md](troubleshooting.md).

LocalSight is **local-first**: the API, the AI worker, the database, and the
recordings all run on one host. Nothing phones home, and the app **refuses to
start** until real secrets are present — there are no insecure defaults.

---

## 1. Prerequisites

| Requirement | Why | Notes |
|--------------|-----|-------|
| **Python 3.12+** | API + worker | The CI-tested version. 3.11 works; 3.9/3.10 are untested. |
| **FFmpeg** (incl. `ffprobe`) on `PATH` | Recording + live view | The only hard external binary. Bundled in the Docker image. |
| **git** | Clone the repo | |
| **~2 GB free disk** | SQLite DB + recordings | Recordings dominate; size to your retention (`scripts/capacity.py`). |
| **A camera or NVR** with RTSP/ONVIF | Something to ingest | Optional for install; required to see detections. |

Optional, depending on your deployment:

| Optional | Unlocks |
|----------|---------|
| PostgreSQL 16 + pgvector | Production DB (compose default). SQLite is the local default. |
| `onnxruntime` | Real multi-class detection (`AI_DETECTOR=onnx`) instead of the reference motion detector |
| `psutil` | CPU/RAM/storage gauges on `/api/system/health` and `/api/system/metrics` |
| `boto3` | `STORAGE_BACKEND=s3` (S3-compatible object storage) |
| NVIDIA GPU / Intel NPU / Coral | Accelerated inference — engaged automatically when a backend is present |

### Install FFmpeg

LocalSight shells out to `ffmpeg` for segmented recording and the LL-HLS live
gateway. Without it, cameras still come online and detections still fire, but
**no recordings and no live view**.

```bash
# macOS (Homebrew)
brew install ffmpeg

# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y ffmpeg

# RHEL / Fedora / Rocky
sudo dnf install -y ffmpeg
```

Verify both binaries resolve:

```bash
ffmpeg -version | head -1
ffprobe -version | head -1
```

> **Docker users**: the image bundles FFmpeg — skip this step.

---

## 2. Choose an install path

| Path | Best for | DB | Effort |
|------|----------|----|--------|
| **A. Python venv** | Local dev, evaluation, bare-metal single host | SQLite | ~5 min |
| **B. Docker Compose** | Production / always-on | PostgreSQL + pgvector | ~10 min |
| **C. Local CCTV rig** | Test-driving on a MacBook with a real end-to-end feed | SQLite (in `.rig/`) | ~10 min |

---

## Path A — Python virtualenv (bare metal, SQLite)

```bash
# 1. Clone
git clone https://github.com/localsightX/localsight.git
cd localsight

# 2. Virtualenv + deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Generate secrets + bootstrap-admin password
python scripts/gen_env.py
```

`gen_env.py` writes `.env` (git-ignored) with cryptographically random
`JWT_SECRET`, `MASTER_ENCRYPTION_KEY`, and a one-time
`BOOTSTRAP_ADMIN_PASSWORD`. **It prints the admin password once and it cannot
be recovered** — record it now. It will also refuse to overwrite an existing
`.env` (delete it first if you really want a fresh one).

```bash
# 4. Start the API (shell 1)
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

# 5. Start the worker (shell 2) — cameras, recording, retention, alerts
python -m apps.worker
```

---

## Path B — Docker Compose (production)

Brings up PostgreSQL+pgvector, the API, the AI worker, and an nginx TLS proxy,
with data on named volumes (`pgdata`, `storage`). Runs fully offline.

```bash
git clone https://github.com/localsightX/localsight.git
cd localsight

python scripts/gen_env.py          # writes .env with fresh random secrets

docker compose -f infrastructure/compose/docker-compose.yml \
     --env-file .env up --build
```

Then:

- The dashboard is served by nginx on **https://localhost** (self-signed cert
  in `infrastructure/nginx/certs/` — replace with your own for production).
- `../../models` is mounted read-only into both containers — that's the
  **BYOM** path: stage model weights into `models/staged/` and declare them in
  `models/registry.json` (see [onnx-detector.md](onnx-detector.md)).
- Edit `.env` and re-run `up --build` to change configuration.

```bash
# Follow logs
docker compose -f infrastructure/compose/docker-compose.yml logs -f api worker

# Stop
docker compose -f infrastructure/compose/docker-compose.yml down
```

Set these in `.env` before a real deployment:

- `SSRF_ALLOWLIST` — the CIDR(s) of your camera VLAN. **Empty blocks every
  private/loopback destination**, so LAN cameras are rejected until you set it.
- `DB_PASSWORD` — a real Postgres password (the placeholder is not for prod).
- `AI_DETECTOR=onnx` + a staged detector — for real multi-class detection.

---

## Path C — Local CCTV rig (test-drive on a MacBook)

`scripts/local_cctv_rig.py` turns a MacBook into a one-camera NVR site: real
FaceTime footage through the exact operator path (local `mediamtx` RTSP broker
→ LocalSight → recording + AI + live view). It uses its own dev secrets and
state under `.rig/` (git-ignored) and leaves your main `.env`/DB alone.

```bash
python scripts/local_cctv_rig.py setup    # brew: ffmpeg + mediamtx; .venv deps
python scripts/local_cctv_rig.py start    # boot the rig (Camera permission prompt)
python scripts/local_cctv_rig.py verify   # ~15-point end-to-end check
python scripts/local_cctv_rig.py status   # processes / streams / camera state
python scripts/local_cctv_rig.py watch    # tail all rig logs
python scripts/local_cctv_rig.py stop     # tear down cleanly (SIGTERM, reap)
```

Notes:

- Grant the **Camera** permission to your terminal when macOS prompts, or use
  `start --source synthetic` for a moving test pattern.
- The rig exports `SSRF_ALLOWLIST=127.0.0.0/8` (the loopback broker), 30 s
  recording segments, and runs the **staged YOLO11n detector** when
  `onnxruntime` is installed.
- To soak a **real LAN camera** instead: export `RIG_CAM_NAME`,
  `RIG_CAM_MAIN_URL` (optional `RIG_CAM_SUB_URL`) and `RIG_SSRF_ALLOWLIST`
  covering the camera's VLAN, then `start --source external` — no local broker
  or capture, API + worker only. See `python scripts/local_cctv_rig.py --help`.



---

## 3. First-run bootstrap

On first boot the API creates a single bootstrap admin from `.env`:

```
BOOTSTRAP_ADMIN_EMAIL=admin@localsight.local
BOOTSTRAP_ADMIN_PASSWORD=<from gen_env.py, or set your own>
```

Two hard rules:

1. The app **refuses to start** if `JWT_SECRET` or `MASTER_ENCRYPTION_KEY` is
   missing, empty, or still a `CHANGE_ME_*` placeholder.
2. The app **refuses to start** if `BOOTSTRAP_ADMIN_PASSWORD` is missing or
   under **12 characters**. There is no default password — `gen_env.py` mints a
   random one.

The bootstrap admin is created **only when no users exist**, so changing the
env later does nothing on an initialized DB. After signing in, create your own
admin account (or rotate the password under **Account**) and record the
bootstrap secret in your password manager.

> **Never reuse the generated dev secrets in production.** Rotate
> `JWT_SECRET` / `MASTER_ENCRYPTION_KEY` before any real deployment — and note
> that rotating `MASTER_ENCRYPTION_KEY` invalidates existing envelope-encrypted
> data (embeddings, plates) and existing signed media URLs.

---

## 4. Post-install verification checklist

Run through these in order — each one isolates a layer.

```bash
# 1. Process alive?
curl -s http://localhost:8000/health/live | head -1     # => {"status":"alive",...}

# 2. DB + storage reachable? (unauthenticated)
curl -s http://localhost:8000/health/ready
# => {"status":"ready","components":{"database":{"status":"ok"},"storage":{"status":"ok"}}}

# 3. Auth works + secrets are valid? (bootstrap admin from .env)
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$BOOTSTRAP_ADMIN_EMAIL\",\"password\":\"$BOOTSTRAP_ADMIN_PASSWORD\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s http://localhost:8000/api/auth/me -H "Authorization: Bearer $TOKEN" | head -c 120

# 4. Component statuses + model names (authed)
curl -s http://localhost:8000/api/system/health -H "Authorization: Bearer $TOKEN"

# 5. FFmpeg is on PATH? (both must resolve)
ffmpeg -version | head -1 && ffprobe -version | head -1
```

Then in the dashboard:

- [ ] **Overview** loads with the camera strip and health panel (refreshes every 15 s).
- [ ] **Cameras** → **+ Add camera** — the wizard's **verify** step pulls one
      real frame before you commit, so a bad URL fails here instead of a day later.
- [ ] After adding a camera: status flips to **online/streaming** within ~30 s
      (the worker writes camera liveness — if it stays `offline`, the worker
      isn't running or the SSRF allowlist is blocking the stream URL).
- [ ] **Live** tile plays (needs FFmpeg + a substream URL).
- [ ] **Events** shows detections within a minute of activity in frame.
- [ ] **Timeline** shows recording coverage as a solid ribbon.

If any step fails, jump to [troubleshooting.md](troubleshooting.md) — it's
organized by the exact symptom you'll see.


---

## 5. Enable real AI (optional, recommended)

Out of the box `AI_DETECTOR=reference` — a deterministic CPU motion detector
that emits `person` only. It needs no model and no GPU, and it's how everything
runs before any weights are staged.

For production-accurate, multi-class detection (person / vehicle / bicycle /
motorcycle / bus / truck / animal / bag / package), stage an ONNX model:

```bash
python scripts/stage_model.py --name detector --path models/staged/yolo11n-detect.onnx \
    --source "Ultralytics YOLO11n (ONNX export)" --license "AGPL-3.0"
```

Then set `AI_DETECTOR=onnx` (`AI_MODEL_NAME=detector`) and restart the worker.
The registry verifies the SHA-256 on load and **refuses a mismatch**; nothing
is fetched from a URL at runtime. Full procedure, plus the optional ANPR /
face / attribute chains: [onnx-detector.md](onnx-detector.md).

---

## 6. Where the data lives (default SQLite install)

| Path | Contents |
|------|----------|
| `localsight.db` | SQLite DB (cameras, events, persons, audit, …). WAL mode. |
| `data/storage/` | Recordings + snapshots (`STORAGE_LOCAL_ROOT`). |
| `data/live/` | Transcoded LL-HLS segments (`LOCALSIGHT_LIVE_DIR`). |
| `models/staged/` | Operator-staged model weights (git-ignored, BYOM). |
| `models/registry.json` | Name / version / path / SHA-256 / source / license per model. |
| `.env` | Secrets (git-ignored). |

Back up `localsight.db`, `data/storage/`, and **`MASTER_ENCRYPTION_KEY`
separately** — encrypted embeddings are useless without it. See
[runbook.md → Backup and restore](runbook.md#backup-and-restore).

---

## 7. Reset / reinstall

```bash
# Stop both processes first, then wipe local state (dev only!)
rm -f localsight.db && rm -rf data/ && rm -f .env
python scripts/gen_env.py     # fresh secrets + new bootstrap admin
```

For the rig: `python scripts/local_cctv_rig.py stop` removes its PID files and
tears everything down; `.rig/` (state, logs, soak reports) can be deleted
manually. Neither touches your main `localsight.db` or `data/`.

---

## Next steps

- **Operate it**: [runbook.md](runbook.md) — health, retention, alert channels,
  backup, capacity, secure-deployment checklist.
- **Use it**: [`docs/USER_GUIDE.md`](../USER_GUIDE.md) — every screen, with
  real screenshots.
- **Something's wrong**: [troubleshooting.md](troubleshooting.md).
- **Wire up cameras**: [`docs/integrations/tplink-vigi.md`](../integrations/tplink-vigi.md)
  and ONVIF discovery / multi-vendor presets.
- **Understand it**: [`docs/architecture/`](../architecture/) and
  [`docs/security/SECURITY.md`](../security/SECURITY.md).

Open <http://localhost:8000> and sign in with the bootstrap admin credentials.

> The worker is a **separate process**. Without it the dashboard works but
> nothing ingests: no frames, no detections, no recordings — and **no retention
> sweeping**, so the DB and storage grow unbounded. Keep it running.
