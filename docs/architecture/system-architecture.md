# System Architecture

## High-level data flow

```
                     ┌──────────────────────────┐
                     │       NVR / Cameras      │  RTSP/RTSPS/ONVIF (camera VLAN)
                     └────────────┬─────────────┘
                                  │  substream (low-res) ──► AI
                                  │  main stream (hi-res) ──► Recording
                                  ▼
                     ┌──────────────────────────┐
                     │      Stream Gateway       │  FFmpeg/GStreamer, hw decode,
                     │  reconnect + backoff      │  bounded queue, frame drop
                     └────────────┬─────────────┘
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
     Main Recording (storage)              AI Substream
              │                                   │
              ▼                                   ▼
       Segmented MP4                    Person/Object Detection (swappable)
       via Recorder                           │
                                                ├─► ONNX / TensorRT / OpenVINO / TFLite
                                                └─► Reference (CPU motion, no model)
                                                      │
                                                Tracking (IOU)
                                                      │
                                        Face detect + embed (optional)
                                                      │
                                        Identity search (vector)
                                                      │
                                        Event / Metadata Engine
                                    (dedup → presence intervals)
                                                      │
                            ┌──────────────────────────┼──────────────────────────┐
                            ▼                          ▼                          ▼
                      PostgreSQL                Object Storage              Vector Index
                      (metadata/refs)          (video/snapshots)          (embeddings)
                            └──────────────────────────┼──────────────────────────┘
                                                      ▼
                                            Alert Dispatcher
                            ┌──────────────────────────┼──────────────────────────┐
                            ▼                          ▼                          ▼
                      Webhook                     MQTT                    Push (ntfy)
                      (HTTP POST)              (publish/subscribe)          │
                            └──────────────────────────┴──────────────────────────┘
                                                      ▼
                                            API / WebSocket
                                                      ▼
                                             Web Dashboard
```

## Security boundaries (each enforces authN/Z, validation, rate-limit, logging)

```
Camera network ──▶ Stream ingestion boundary ──▶ AI processing boundary
         ──▶ Metadata boundary ──▶ Application boundary ──▶ User boundary
```

## Processing pipeline (per camera)

```
RTSP → decode → [motion gate] → frame sampling → object detection (multi-class) →
tracking → face detection (tracked people only) → quality filter →
embedding → identity search (throttled ~1–3s/track) → event aggregation
```

### Behavior Analytics (Rules Engine)

The rules engine evaluates per-frame track data against configured geometry rules:

```
Tracks → LineCrossingRule (directional tripwire)
       → ZoneIntrusionRule (polygon entry)
       → LoiteringRule (dwell time in zone)
       → ObjectLeftRule (stationary object removed)
       → CrowdCountRule (occupancy threshold)
              ↓
         AnalyticEvent → Alert Dispatcher
```

### ANPR Pipeline (optional)

```
Frame → PlateDetection (crop) → OCR (character recognition) → Watchlist match
                                                           → Event (encrypted plate)
```

## State model

- **Camera status** (independent per camera): `ONLINE | DEGRADED | OFFLINE | RECONNECTING`
  with exponential backoff + jitter (1,2,5,10,30,60s) and never hammering the NVR.
- **Track** = ephemeral `camera-01-track-1842`; never the real identity.
- **Event** = aggregated presence window with `first_seen`/`last_seen`, confidence,
  snapshot/video refs, and an explicit `identity_status` of `known|unknown|uncertain`.
- **AlertRoute** = per-channel routing config with cooldown suppression to prevent alert storms.

## Swappable AI backends

The `Detector` interface (`packages/ai/interfaces.py`) is implemented by:

| Backend | Runtime | Model format | Notes |
|---------|---------|-------------|-------|
| `reference` | CPU (no GPU) | None | Frame-differencing fallback; deterministic, no download |
| `onnx` | CPU / CUDA | ONNX (YOLO/RT-DETR) | Lazy `onnxruntime`; GPU auto-detected |
| `tensorrt` | NVIDIA GPU | TensorRT engine | Requires staged `.engine` file |
| `openvino` | Intel CPU/iGPU/NPU | OpenVINO IR | Lazy import |
| `tflite` | ARM / Coral TPU | TFLite | Lazy import |

All model-backed backends load from the `ModelRegistry` (SHA-256 verified). The
`build_detector()` factory selects the backend from `AI_DETECTOR` config.

## Alert routing

The alert system fans out `AnalyticEvent` objects to zero or more channels:

```
AnalyticEvent
    │
    ├─► AlertRoute (rule_type, channel, config, cooldown_sec)
    │         │
    │         ├─► webhook: POST to SSRF-validated URL
    │         ├─► email: SMTP (configurable)
    │         ├─► mqtt: publish to topic (e.g. localsight/{camera_id}/alerts)
    │         └─► push: ntfy.sh (configurable priority/tags)
    │
    └─► CooldownTracker (per route: channel × rule_type × camera_id)
              ↓ (suppresses re-fire within cooldown window)
          Notifier.send()
```

## Timeline & Recording

```
Timeline query (date, camera_id)
    │
    ├─► Events: markers at event timestamps, typed by event_type
    └─► VideoSegments: intervals of continuous recording
              ↓
         Merged chronological timeline
         (events as markers, recording as intervals)
```

## Scaling story (Kubernetes-ready, not required)

- API: stateless, horizontally scalable behind the proxy.
- Worker: one process per host; multiple workers share DB/storage and process
  disjoint camera sets. GPU scheduling is a future bounded scheduler.
- Storage: local disk → S3-compatible; DB: Postgres with partitioning on `events`.

## CI/CD & supply-chain integrity

Every commit goes through a 10-job GitHub Actions pipeline that enforces quality,
security, and operational standards before merge. The pipeline is documented in
detail in `docs/operations/ci-cd-pipeline.md`.

```
   ┌─────────────────────────────────────────────────────────────────┐
   │                       Git Push / PR                                │
   └─────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  Lint  │  Tests  │  Integration  │  CodeQL  │  Semgrep  │ Trivy │
   │  (ruff)  (SQLite)  (PostgreSQL)    (SAST)    (SAST)     (image)│
   └─────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  Dependency audit  │  Container build + push  │  Release tags  │
   │  (pip-audit+Saf.)  │  (multi-platform)        │  (SBOM, GH)   │
   └─────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                      Quality Gate                                │
   │  Blocks merge on lint / test / ui-e2e failures; security         │
   │  findings are warnings tracked in the Security tab               │
   └─────────────────────────────────────────────────────────────────┘
```

### Free CVE / vulnerability sources checked

| Source | Database | Job | Coverage |
|--------|----------|-----|----------|
| pip-audit | OSV / PyPI | `security-deps` | Python package CVEs |
| Safety | pyup.io | `security-deps` | Python package CVEs |
| Trivy | GHSA / TSL / NVD | `container-scan` | OS + Python CVEs in images |
| CodeQL | GitHub code scanning | `sast-codeql` | Python SAST |
| Semgrep | Semgrep registry | `sast-semgrep` | OWASP / secrets / Python |
| Dependabot | Combined | Scheduled PRs | Auto-update deps weekly |

### Container supply chain

- **Multi-platform build**: `linux/amd64` (servers) and `linux/arm64` (Jetson, RPi)
- **SBOM**: SPDX-JSON generated per release via Trivy
- **Provenance**: SLSA-style attestation from `docker/build-push-action@v6`
- **GHCR**: `ghcr.io/localsightx/localsight` (derived from `github.repository` in CI) with auto-tags

### Branch protection recommendations

Enable these required status checks on `main`:
- `lint`
- `Unit Tests (Python 3.12, SQLite)`
- `Integration Tests (PostgreSQL)`
- `Quality Gate`

Security jobs (`CodeQL`, `Semgrep`, `Trivy`) are warnings only; they populate
the Security tab without blocking the merge.
