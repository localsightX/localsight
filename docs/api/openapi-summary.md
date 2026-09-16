# API Summary

Base path `/api`. All responses are JSON. All mutating/protected endpoints require
`Authorization: Bearer <access_token>`. Pagination: `limit` (≤500), `offset`.

## Auth
| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/api/auth/login` | — | email+password(+mfa); rate-limited; returns access+refresh |
| POST | `/api/auth/refresh` | refresh token | rotates token; old refresh revoked |
| POST | `/api/auth/logout` | refresh token | revokes refresh |
| GET | `/api/auth/me` | user | current user + permissions |
| POST | `/api/auth/mfa/setup` | user | returns TOTP secret + otpauth URI |
| POST | `/api/auth/mfa/verify` | user | enables MFA |

## Cameras / NVR
| Method | Path | Permission |
|--------|------|-------------|
| GET/POST | `/api/cameras` | `camera:view` / `camera:configure` |
| GET | `/api/cameras/presets` | `camera:view` (vendor RTSP/ONVIF URL templates, incl. TP-Link) |
| POST | `/api/cameras/from-nvr` | `camera:configure` (provision a VIGI NVR + all channels) |
| GET | `/api/cameras/vendor-presets` | `camera:view` |
| POST | `/api/cameras/presets/build` | `camera:configure` (construct vendor RTSP URL; credentials never echoed) |
| POST | `/api/cameras/onvif/discover` | `camera:configure` (WS-Discovery on LAN; SSRF-validated) |
| POST | `/api/cameras/onvif/streams` | `camera:configure` (get RTSP URIs from ONVIF device) |
| GET/PUT/DELETE | `/api/cameras/{id}` | `camera:view` / `camera:configure` (DELETE removes the camera: cascades its recordings/events/snapshots/detections/tracks, stops its live transcode, and the worker stops ingesting within ~30 s) |
| GET | `/api/cameras/{id}/snapshot-url` | `camera:view` (mint a 300 s signed snapshot URL for <img> loads) |
| GET | `/api/cameras/{id}/snapshot` | session token OR signed URL (one JPEG frame; honest 404/409/503) |
| GET/POST | `/api/nvr` | `camera:configure` |

Camera stream URLs are **SSRF-validated** and **encrypted at rest**; they are never
returned to clients.

### Use case: Provision a VIGI NVR in one call
```bash
curl -X POST http://localhost:8000/api/cameras/from-nvr \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"nvr_ip":"192.168.1.50","nvr_name":"Warehouse NVR","channel_count":8,"retention_days":7}'
# => {"nvr_id": "...", "cameras": [{id, name, main_stream, sub_stream}, ...]}
```

### Use case: Discover cameras on the LAN
```bash
curl -X POST http://localhost:8000/api/cameras/onvif/discover \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"timeout":2.0}'
# => ["rtsp://10.0.0.5/onvif/1", ...]
```

## People / identity
| Method | Path | Permission |
|--------|------|-------------|
| GET/POST | `/api/persons` | `person:view` / `person:enroll` (list includes per-person `faces_enrolled`) |
| DELETE | `/api/persons/{id}` | `person:delete` |
| POST | `/api/persons/{id}/references` | `person:enroll` (upload reference image → local embedding) |
| GET | `/api/persons/{id}/references` | `person:enroll` (reference **metadata** — model, dimension, quality; image bytes are never retained) |

### Use case: Enroll a known person
```bash
curl -X POST http://localhost:8000/api/persons \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"label":"John Smith","role":"staff"}'
# => {"id": "...", "label": "John Smith", ...}

curl -X POST http://localhost:8000/api/persons/$ID/references \
  -H "Authorization: Bearer $TOKEN" -F "image=@john.jpg"
# Uploads face image, generates encrypted embedding, links to person record
```

## Events / search
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/events` | `events:view` (filters: camera/identity/status/time/confidence) |
| GET | `/api/events/{id}` | `events:view` (returns signed snapshot/video URLs) |
| GET | `/api/events/{id}/export` | `events:export` (audited, single signed URL) |
| GET | `/api/events/{id}/clip` | `events:export` (assembles all overlapping recording segments) |
| GET | `/api/timeline?date=&camera_id=` | `events:view` (merged recording intervals + presence + markers) |
| GET | `/api/events` (filtered) | `events:view` |
| GET | `/api/alerts/events` | `events:view` (includes `detail` context per event) |

Event rows carry a `detail` JSON column: rule events include `direction`,
`dwell_sec`, `count`, `zone`; ANPR events include `plate_enc` (envelope-
encrypted plate — decryptable only on the host) and `plate_hash` (anonymized
correlation digest).

### Use case: Search events by camera and time range
```bash
curl "http://localhost:8000/api/events?camera_id=$CAM&start=2026-03-01T08:00:00Z&end=2026-03-01T18:00:00Z" \
  -H "Authorization: Bearer $TOKEN"
# => {"items": [...], "total": 42, "limit": 50, "offset": 0}
```

### Use case: Export event clip (assemble segments into a downloadable video)
```bash
curl http://localhost:8000/api/events/$EVT_ID/clip -H "Authorization: Bearer $TOKEN"
# => {
#   "event_id": "...",
#   "camera_id": "...",
#   "segment_count": 3,
#   "total_size_bytes": 15728640,
#   "segments": [
#     {"id": "...", "start_ts": "...", "end_ts": "...", "duration_sec": 300.0,
#      "url": "/api/video/cam1/2026-03-01/seg-a.mp4?exp=...&sig=..."},
#     ...
#   ],
#   "expires_in": 300
# }
# Each segment URL is signed and expiring; all overlapping segments are included.
```

## Timeline
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/timeline?date=YYYY-MM-DD` | `events:view` |

Returns a merged view of recording intervals + presence windows + analytic event markers
for a given UTC date. One call populates the full 24-hour timeline widget.

### Use case: Load the dashboard timeline for a specific day
```bash
curl "http://localhost:8000/api/timeline?date=2026-03-01" -H "Authorization: Bearer $TOKEN"
# => {
#   "date": "2026-03-01",
#   "timeline": [
#     {"camera_id": "cam1", "label": "John S.", "intervals": [
#       {"start": "2026-03-01T09:00:00Z", "end": "2026-03-01T09:15:00Z", "confidence": 0.92, "identity_status": "known"}
#     ]}
#   ],
#   "recording": [
#     {"camera_id": "cam1", "start": "2026-03-01T00:00:00Z", "end": "2026-03-01T23:59:59Z", "duration_sec": 86400.0}
#   ],
#   "markers": [
#     {"id": "...", "camera_id": "cam1", "event_type": "intrusion", "ts": "2026-03-01T14:23:01Z", "identity_status": "unknown"}
#   ],
#   "limits": {"recording": 500, "markers": 500}
# }
```

## Behavior analytics (rules)
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/cameras/{id}/rules` | `rules:configure` |
| PUT | `/api/cameras/{id}/rules` | `rules:configure` |

Rules are stored as JSON on the camera and evaluated by the AI worker per frame.
Supported rule types:

| Type | Description |
|------|-------------|
| `line_cross` | Directional tripwire crossing (configurable entry/exit direction) |
| `intrusion` | Polygon zone entry detection |
| `loitering` | Dwell time exceeding threshold within a zone |
| `object_left` | Object stationary for `stationary_sec` then disappears |
| `crowd` | Occupancy count exceeding threshold in a zone |

### Use case: Configure a perimeter intrusion zone
```bash
curl -X PUT http://localhost:8000/api/cameras/$CAM/rules \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"rules": [
    {"type": "intrusion", "rule_id": "perimeter-1",
     "zone": [[0.4,0.4],[0.6,0.4],[0.6,0.6],[0.4,0.6]]},
    {"type": "loitering", "rule_id": "gate-loiter",
     "zone": [[0.0,0.0],[1.0,0.0],[1.0,1.0],[0.0,1.0]], "dwell_sec": 10},
    {"type": "line_cross", "rule_id": "entry-tripwire",
     "a": [0.5, 0.0], "b": [0.5, 1.0], "direction": 1}
  ]}'
# direction: 1 = left-to-right, -1 = right-to-left, null = both directions
```

## Live view
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/live/streams` | `live:view` (health of active transcodes) |
| POST | `/api/live/ticket` | `live:view` (issue short-lived camera-scoped ticket) |
| GET | `/api/live/{camera_id}/play` | `live:view` (validate ticket, start LL-HLS transcode) |
| POST | `/api/live/{camera_id}/stop` | `live:view` (stop transcode; dashboard control) |

Transcodes are lifecycle-managed: streams idle for
`LOCALSIGHT_LIVE_IDLE_TIMEOUT_SEC` (default 300 s) or older than
`LOCALSIGHT_LIVE_MAX_DURATION_SEC` (default 4 h) are reaped automatically.

### Use case: Watch a live camera stream
```bash
# Step 1: get a ticket (short-lived, camera-scoped, encrypted)
TICKET=$(curl -s -X POST http://localhost:8000/api/live/ticket \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"camera_id": "'$CAM'", "ttl_sec": 300}' | python3 -c "import sys,json;print(json.load(sys.stdin)['ticket'])")

# Step 2: exchange ticket for HLS manifest (ffmpeg starts transcode in background)
curl "http://localhost:8000/api/live/$CAM/play?ticket=$TICKET" \
  -H "Authorization: Bearer $TOKEN"
# => {"camera_id": "cam1", "hls_manifest": "/live-media/cam1/index.m3u8", "protocols": ["ll-hls"], "ticket": "..."}

# Step 3: point an HLS player at /live-media/cam1/index.m3u8
# The RTSP URL and credentials are never exposed to the client.
```

### Use case: Check which streams are actively transcoding
```bash
curl http://localhost:8000/api/live/streams -H "Authorization: Bearer $TOKEN"
# => {"active": [{"camera_id": "cam1", "running": true, "pid": 18427, "idle_sec": 4}], "count": 1}
```

### Use case: Stop a stream when done watching
```bash
curl -X POST http://localhost:8000/api/live/$CAM/stop -H "Authorization: Bearer $TOKEN"
# => {"camera_id": "cam1", "stopped": true}   (stopped=false when nothing was running)
```

## Analytics / BI
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/analytics/people-count` | `analytics:view` |
| GET | `/api/analytics/occupancy` | `analytics:view` |
| GET | `/api/analytics/dwell` | `analytics:view` |
| GET | `/api/analytics/breakdown` | `analytics:view` |
| GET | `/api/analytics/heatmap` | `analytics:view` |
| GET | `/api/analytics/search` | `analytics:view` (natural-language forensic search) |

All accept `camera_id`, `start`, `end` (ISO 8601) parameters.

### Use case: Get a retail site's hourly occupancy trend
```bash
curl "http://localhost:8000/api/analytics/occupancy?camera_id=$CAM&start=2026-03-01T08:00:00Z&end=2026-03-01T20:00:00Z&bucket_min=60" \
  -H "Authorization: Bearer $TOKEN"
# => {"camera_id": "cam1", "buckets": [
#     {"ts": "2026-03-01T08:00:00Z", "count": 3},
#     {"ts": "2026-03-01T09:00:00Z", "count": 7},
#     ...
#   ]}
```

### Use case: Find "person in red near the gate" using semantic search
```bash
curl "http://localhost:8000/api/analytics/search?q=person%20in%20red%20near%20the%20gate&camera_id=$CAM" \
  -H "Authorization: Bearer $TOKEN"
# => {"query": "person in red near the gate", "results": [
#     {"id": "evt-001", "event_type": "intrusion", "camera_id": "cam1",
#      "ts": "2026-03-01T14:23:01Z", "score": 0.9234},
#     ...
#   ]}
```

## Alerts
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/alerts/routes` | `alerts:manage` |
| POST | `/api/alerts/routes` | `alerts:manage` |
| DELETE | `/api/alerts/routes/{id}` | `alerts:manage` |
| POST | `/api/alerts/test` | `alerts:manage` |
| GET | `/api/alerts/events` | `events:view` |

Channels: `webhook` (HTTP POST), `email` (SMTP), `mqtt` (publish/subscribe), `push` (ntfy.sh).
Routing by `rule_type` (`*` matches all) and optional `camera_id` scope.

### Use case: Route all intrusion alerts to a webhook with 5-minute cooldown
```bash
curl -X POST http://localhost:8000/api/alerts/routes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "rule_type": "intrusion",
    "channel": "webhook",
    "config": {"url": "https://hooks.example.com/localsight"},
    "cooldown_sec": 300
  }'
# => {"id": "...", "channel": "webhook", "rule_type": "intrusion"}
```

### Use case: Route ANPR events to MQTT for LPR search integration
```bash
curl -X POST http://localhost:8000/api/alerts/routes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "rule_type": "anpr",
    "channel": "mqtt",
    "config": {
      "host": "192.168.1.100", "port": 1883,
      "topic": "localsight/{camera_id}/alerts",
      "username": "mqtt_user", "password": "s3cret"
    },
    "cooldown_sec": 60
  }'
# MQTT message payload:
# {"source": "localsight", "rule_id": "...", "rule_type": "anpr",
#  "camera_id": "cam1", "severity": "info", "ts": "2026-03-01T14:23:01Z",
#  "message": "...", "detail": {"direction": ..., "dwell_sec": ...}}
#
# NOTE: `detail` is filtered to third-party-safe keys (direction, dwell_sec,
# count, zone, stationary_sec). Encrypted plate material (plate_enc/plate_hash)
# never leaves the host — only the host-side API can decrypt it.
```

### Use case: Push alerts to ntfy.sh for mobile notifications
```bash
curl -X POST http://localhost:8000/api/alerts/routes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "rule_type": "*",
    "channel": "push",
    "config": {
      "server": "https://ntfy.sh",
      "topic": "localsight-alerts",
      "priority": 4,
      "tags": ["security", "camera"],
      "click": "https://dashboard.example.com/events"
    }
  }'
```

### Use case: Verify alert delivery without touching a camera
```bash
curl -X POST http://localhost:8000/api/alerts/test -H "Authorization: Bearer $TOKEN"
# => {"delivered": 2}  # sent to 2 active routes; 0 if broker unreachable (no crash)
```

## Users (admin)
| Method | Path | Permission |
|--------|------|-------------|
| GET/POST | `/api/users` | `user:manage` |
| DELETE | `/api/users/{id}` | `user:manage` |

## Audit
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/audit` | `audit:view` |

## System
| Method | Path | Auth |
|--------|------|-------|
| GET | `/health/live` | — |
| GET | `/health/ready` | — |
| GET | `/api/system/health` | user |
| GET | `/api/system/metrics` | user (Prometheus text) |

## Media
| Method | Path | Permission |
|--------|------|-------------|
| GET | `/api/video/{key}?exp=&sig=` | URL signature itself (HMAC-signed, expiring ≤300 s, scoped to one object) |

> Media URLs are consumed by `<img>`/`<video>` tags, which cannot send an
> `Authorization` header — so the signature is the authorization. URLs are
> only issued by permissioned endpoints (`events:view`/`events:export`),
> each issuance audited where applicable.

Full interactive docs: `GET /docs` (FastAPI Swagger UI) when running.
