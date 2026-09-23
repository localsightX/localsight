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
returned to clients. `PUT /api/cameras/{id}` also accepts
`alert_budget_per_day` (R3.6): `null` = platform default, `0` = unlimited,
`1-10000` = cap that camera's alert notifications per UTC day.

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
| GET | `/api/search/attributes?key=&value=&camera_id=&start=&end=` | `search:view` (B1: CLIP tags on tracks) |
| GET | `/api/search/plates?q=&camera_id=&start=&end=` | `search:view` (B2: exact keyed-HMAC plate match) |
| GET | `/api/searches` | `search:view` (caller's saved searches) |
| POST | `/api/searches` | `search:save` (audited) |
| DELETE | `/api/searches/{id}` | `search:save` (audited, owner-only) |

Event rows carry a `detail` JSON column: rule events include `direction`,
`dwell_sec`, `count`, `zone`; ANPR events include `plate_enc` (envelope-
encrypted plate — decryptable only on the host) and `plate_hash` (anonymized
correlation digest).

### Use case: Find a person wearing a red jacket (attribute search)
```bash
curl "http://localhost:8000/api/search/attributes?key=color&value=red&camera_id=$CAM" \
  -H "Authorization: Bearer $TOKEN"
# => {"query": {"key": "color", "value": "red"}, "results": [
#      {"track_id": "cam-01-track-1842", "camera_id": "...", "identity_status": "unknown",
#       "last_seen": "2026-09-19T14:02:11Z+00:00", "matched": {"color": "red"},
#       "attributes": {"jacket": true, "color": "red", "jacket_conf": 0.83}}]}
# Searches the Track.detail CLIP tags; omit `value` for has-key semantics.
```

### Use case: Look up a plate (exact match over the keyed HMAC index)
```bash
curl "http://localhost:8000/api/search/plates?q=ab-12%20cd" \
  -H "Authorization: Bearer $TOKEN"
# => {"query": {"plate": "AB12CD"}, "results": [{"event_id": "...", "camera_id": "...",
#      "ts": "...", "confidence": 0.94}]}
# Input is normalized exactly like the OCR pipeline (uppercase, [A-Z0-9]) and
# matched against the master-key HMAC tokens — plaintext plates are never
# stored, returned, or searched. Partial plates are not searchable by design.
```

### Gate-access lanes (R4.1)

Arm a camera as an access-control lane: its ANPR reads are matched against a
whitelist of keyed-HMAC plate tokens inside an allow window, and a granted read
dispatches a barrier OPEN to a webhook/MQTT relay. **Deny by default** — an
unmatched plate is logged as a `gate_deny` event and never touches the barrier.
Everything is off unless `pipeline_flags.lane_access` is set, which the arming
endpoint does for you.

```bash
# Arm the lane (idempotent per camera; lanes:manage).
curl -X PUT http://localhost:8000/api/cameras/$CAM/lane \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "front gate", "barrier_channel": "mqtt",
       "barrier_config": {"host": "broker.lan", "port": 1883, "topic": "gate/open"},
       "allow_window": {"start": "07:00", "end": "19:00", "days": [1,2,3,4,5]},
       "cooldown_sec": 30}'
# => {"id": "...", "barrier_configured": true, "enabled": true, ...}

# Enroll a plate — stored ONLY as the master-key HMAC token the OCR pipeline
# writes to Event.detail.plate_hash, so enrollment and sighting share one index.
curl -X POST http://localhost:8000/api/cameras/$CAM/lane/whitelist \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"plate": "AB12CD", "label": "delivery van"}'
# => {"id": "...", "plate_hash": "…", "query": {"plate": "AB12CD"}}
```

The barrier destination passes the **same SSRF gate as alert routes**
(`_validate_route_destination`) before persist — loopback is refused unless the
operator allowlists it — and relay credentials are envelope-encrypted in
`barrier_config_enc` and never returned (only `barrier_configured` is). Reads
need `lanes:view`. `DELETE /api/cameras/{id}/lane` disarms and removes the
policy + whitelist; `DELETE /api/lanes/whitelist/{entry_id}` revokes one plate.
Every mutation is audit-logged with the plate **hash**, never the plaintext.

### Use case: Save a forensic search for the team shift (audited)
```bash
curl -X POST http://localhost:8000/api/searches \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "red jackets front gate", "kind": "attributes", "params": {"key": "color", "value": "red"}}'
# Saved per user (quota 50, unique name, payload ≤ 2 KB); GET /api/searches lists
# the caller's own searches, DELETE removes one. Save and delete are audit-logged.
```


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
| POST | `/api/rules/test` | `rules:configure` (dry-run replay, no persistence) |

Rules are stored as JSON on the camera and evaluated by the AI worker per frame.
Supported rule types:

| Type | Description |
|------|-------------|
| `line_cross` | Directional tripwire crossing (R3.3: direction from a ≥3-sample trajectory window, so a jittery detection cannot flip it) |
| `intrusion` | Polygon zone entry detection |
| `loitering` | Dwell time exceeding threshold within a zone |
| `object_left` | Object stationary for `stationary_sec`, **only while unattended** (R3.4: an attached person/vehicle means not abandoned; `require_unattended: false` restores stationarity-only) |
| `crowd` | Occupancy count exceeding threshold in a zone |
| `stopped_vehicle` | R3.4: vehicle at/below `max_speed` for `stopped_sec` inside a no-stopping zone |

Writes are validated against **rule grammar v1** (`packages/ai/rulegrammar.py`):
geometry must be normalized `[0,1]`, labels must come from the platform
vocabulary, and numeric knobs are range-checked. An invalid payload returns
`400` with `{"message", "schema_version", "errors": ["rules[0].zone: ..."]}`
field-path errors. Every rule also accepts the engine knobs `cooldown_sec`
(minimum seconds between fires, 0 = unlimited) and `min_size` (normalized
bbox-area floor to ignore tiny/far detections); zone rules additionally accept
`id_switch_grace_sec` (R3.2: dwell state carries across a tracker ID switch
inside the zone, so re-assigned tracks neither reset dwell nor double-fire),
`object_left` accepts `require_unattended` (R3.4) and `stopped_vehicle` accepts
`stopped_sec` / `max_speed` (R3.4).
A zone hit means the detection centroid is inside the polygon OR at least 50%
of the detection box is covered by it — the same coverage semantics as privacy
masks. The audit trail records the grammar `schema_version` with each write.

`POST /api/rules/test` is the R3.5 dry-run replay tester: send draft `rules`
plus recorded `frames` (`{"t": seconds, "tracks": [["id", "label", [x, y, w, h]],
...]}`) and get back the verdict timeline — every evaluated decision per frame
(`fired`, `cooldown_blocked`, `no_zone_hit`, `dwell_warming`, ...) plus the
fired events, a per-rule summary and, when an `expect` block is supplied, the
golden-replay verdict (`pass` / `expect_errors`). Nothing is persisted and no
alert fan-out occurs; the same core backs `scripts/rule_replay.py` (CLI) and
the `tests/replays/` pytest suite. The Rules editor's **Replay & verdict**
card calls this endpoint from the UI: pick a fixture file, replay the
editor's current (unsaved) draft rules, and the PASS/FAIL banner, per-rule
verdict lanes and fire markers render inline.

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
# direction: 1 / -1 = required crossing sign relative to the a->b line vector,
# null = any direction. For the vertical a=[0.5,0] -> b=[0.5,1] line below:
# -1 = left-to-right entry, 1 = right-to-left (verified by tests/replays/).
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
| GET | `/api/alerts/budget` | `alerts:manage` (per-camera daily budget: limit, used today, remaining) |

Channels: `webhook` (HTTP POST), `email` (SMTP), `mqtt` (publish/subscribe), `push` (ntfy.sh).
Routing by `rule_type` (`*` matches all) and optional `camera_id` scope.

The daily alert budget (R3.6) caps **notifications** per camera per UTC day
(`ALERT_BUDGET_PER_CAMERA_PER_DAY`, overridable per camera via
`PUT /api/cameras/{id}`); `used_today` counts the analytic events stored since
UTC midnight, so this view and the worker's enforcement read the same number.
Evidence is never capped: detections, clips and search results are always kept.
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
