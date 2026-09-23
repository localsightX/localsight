# Database ERD

All tables use UUID primary keys (string hex), are UTC-timestamped, and store
*references/metadata*, never large video blobs. Sensitive columns are encrypted by
the application before insert.

## Tables and key relationships

```
User(1) ──< (N) Role(1) ──< (N) Permission          # RBAC
User(1) ──< (N) RefreshToken                        # refresh rotation/revocation
User(1) ──< (N) AuditLog                            # immutable audit

NvrDevice(1) ──< (N) Camera                         # discovered/added cameras
Camera(1) ──< (N) Stream                             # main + sub per camera
Camera(1) ──< (N) Detection                          # raw per-frame detections
Camera(1) ──< (N) Track                              # ephemeral tracked objects
Camera(1) ──< (N) Event                              # aggregated presence/intervals
Camera(1) ──< (N) VideoSegment                       # continuous recording segments
Camera(1) ──< (1) Lane ──< (N) LaneWhitelistEntry    # R4.1 gate-access LPR (1:1)

Person(1) ──< (N) PersonEmbedding                   # encrypted biometric vectors
Person(1) ──< (N) Event(identity_id)               # known identity linkage
Track(identity_id) ── Person(optional)

AlertRoute(1) ──< (N) AuditLog                     # alert route changes are audited

Event ──< Snapshot, VideoSegment                    # media references (encrypted keys)
SystemMetric(ts, name, value, tags)                 # observability
ModelVersion(name, version, hash, source, license)  # AI supply-chain integrity
```

### AlertRoute table

Stores per-channel notification routing for analytic events:

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID | Primary key |
| `rule_type` | string | Event type to match: `line_cross`, `intrusion`, `loitering`, `presence`, `anpr`, `*` (all) |
| `camera_id` | UUID? | Optional scope to a specific camera |
| `channel` | string | Delivery channel: `webhook`, `email`, `mqtt`, `push` |
| `config_enc` | text? | Channel-specific config (URL, credentials), encrypted at rest |
| `enabled` | bool | Route active/inactive |
| `cooldown_sec` | int | Suppress re-fire for this channel×rule×camera within window |

Config is **encrypted at rest** (envelope encryption) and **never returned to API clients**.
The `webhook` channel config stores the URL; `mqtt` stores host/port/topic/credentials;
`email` stores SMTP settings; `push` stores ntfy.sh server/topic/priority.

### Lane / LaneWhitelistEntry tables (R4.1 gate-access LPR)

A camera configured as a *lane* becomes an access-control point: plates read by the
ANPR pipeline are matched against a whitelist and, on a match inside the allow
window, the worker issues a barrier (relay open) command. Deny-by-default — a
whitelist miss is logged as an event and never triggers the barrier.

**Lane** (one per camera, enforced by `uq_lane_camera`):

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID | Primary key |
| `camera_id` | UUID | FK `cameras.id` `ON DELETE CASCADE` |
| `name` | string | Lane label, e.g. "main gate" |
| `barrier_channel` | string | Action channel: `webhook` or `mqtt` |
| `barrier_config_enc` | text? | Relay destination/credentials, envelope-encrypted (like `alert_routes.config_enc`) |
| `allow_window` | JSON? | Lane-level schedule (see below); null = 24/7 |
| `cooldown_sec` | int | Per-plate command idempotency window (default 30) |
| `enabled` | bool | Lane armed/disarmed |
| `armed_by` | UUID? | Operator who armed the lane — audit-logged with every open/close |

**LaneWhitelistEntry** (FK `lanes.id` `ON DELETE CASCADE`):

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID | Primary key |
| `lane_id` | UUID | FK `lanes.id` `ON DELETE CASCADE` |
| `plate_hash` | string(64) | `CryptoBox.hmac_str` token — **the only plate column in the DB** |
| `label` | string | Operator note (e.g. "delivery van"), never the plaintext plate |
| `allow_window` | JSON? | Per-plate override; null = inherit the lane window |
| `enabled` | bool | Entry active/inactive |

`plate_hash` is the *same master-key-bound HMAC token* the ANPR pipeline writes to
`Event.detail.plate_hash`, so a whitelist match is an exact join against the R2 plate
index and **plaintext plates never reach the database**. Rotating `MASTER_ENCRYPTION_KEY`
invalidates every entry by design — treat it as a re-enrollment event.

**Allow-window shape** (`packages.domain.lane.is_within_window`):

```json
{"start": "09:00", "end": "17:00", "days": [1, 2, 3, 4, 5], "tz": "Europe/Berlin"}
```

`start`/`end` are `HH:MM` (inclusive start, exclusive end); `end <= start` wraps past
midnight; `days` are ISO weekday ints (1=Mon .. 7=Sun, empty = all); `tz` is applied to
the timestamp before testing. A missing window means "always allowed"; a **malformed
window denies** — the gate fails closed rather than opening on a config typo.

**`cameras.pipeline_flags`** (JSON, additive): per-camera analytic switches,
`{flag: bool}`, off unless explicitly enabled (`packages.domain.lane.
pipeline_flag_enabled`). Known flags: `anpr`, `lane_access` (this feature),
`speed` (R4.2), `mmr` (R4.3).

## Indexes (hot paths)

- `events(camera_id, timestamp_start)`
- `events(identity_id, timestamp_start)`
- `tracks(camera_id, last_seen)`
- `detections(camera_id, frame_ts)`
- `audit_logs(ts, action)`
- `alert_routes(rule_type, camera_id)`
- `lane_whitelist(plate_hash)` — keyed-HMAC plate equality lookup (unique per lane)

## Encryption scope (application-layer envelope)

Encrypted at rest: `cameras.stream_url_enc`, `cameras.substream_url_enc`,
`nvr_devices.username_enc/password_enc`, `users.mfa_secret_enc`,
`person_embeddings.embedding_enc`, `snapshots.storage_key_enc`,
`events.snapshot_key_enc`, `events.video_segment_key_enc`,
`alert_routes.config_enc`, `lanes.barrier_config_enc`.

The DB stores only ciphertext for these columns; keys never touch the database.
