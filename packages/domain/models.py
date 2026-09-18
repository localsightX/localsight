"""SQLAlchemy ORM models (SQLAlchemy 2.0 style).

Database stores *references and metadata*, never large video blobs. Sensitive
columns (stream URLs, credentials, embeddings, snapshots) are encrypted by the
service layer before insert and decrypted on read — the DB only ever sees
ciphertext. UUIDs are used as primary keys; indexes target the hot query paths
(camera_id, timestamp, identity_id, track_id, event_type).
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return uuid.uuid4().hex


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Encrypted base32 TOTP secret (CryptoBox). Never returned to clients.
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    role: Mapped["Role"] = relationship("Role")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission", secondary="role_permissions", back_populates="roles"
    )


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    roles: Mapped[list["Role"]] = relationship(
        "Role", secondary="role_permissions", back_populates="permissions"
    )


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    permission_id: Mapped[str] = mapped_column(ForeignKey("permissions.id"), primary_key=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    replaced_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class NvrDevice(Base):
    __tablename__ = "nvr_devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=80)
    onvif_supported: Mapped[bool] = mapped_column(Boolean, default=False)
    # Encrypted credentials (CryptoBox).
    username_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Camera(Base):
    __tablename__ = "cameras"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    camera_uid: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    nvr_device_id: Mapped[str | None] = mapped_column(ForeignKey("nvr_devices.id"), nullable=True)
    # Encrypted RTSP URLs (may contain credentials).
    stream_url_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    substream_url_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="OFFLINE", index=True)  # ONLINE/DEGRADED/OFFLINE/RECONNECTING
    health: Mapped[str] = mapped_column(String(16), default="unknown")
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[str] = mapped_column(String(32), default="")
    fps: Mapped[int] = mapped_column(Integer, default=0)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    # JSON: list of {x,y,w,h} rectangles excluded from processing (privacy masks).
    # Suppressed by CameraPipeline when center-in-mask or >=50% bbox overlap.
    privacy_masks: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Per-camera retention overrides (days); null = global policy.
    retention: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Per-camera behavior-analytics rules (line/zone/loitering/object-left/crowd).
    # Stored as JSON; consumed by the worker's RuleEngine. Privacy masks live
    # alongside this as geometry the detector skips.
    rules: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Stream(Base):
    __tablename__ = "streams"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16))  # main | sub
    url_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution: Mapped[str] = mapped_column(String(32), default="")
    fps: Mapped[int] = mapped_column(Integer, default=0)
    codec: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Person(Base):
    __tablename__ = "persons"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    label: Mapped[str] = mapped_column(String(128), unique=True, index=True)  # e.g. employee-001
    display_name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(16), default="known")  # known | disabled
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Deleting a person (GDPR erasure) removes their enrollment embeddings —
    # the biometric data class must not outlive its subject.
    embeddings: Mapped[list["PersonEmbedding"]] = relationship(
        cascade="all, delete-orphan", passive_deletes=True
    )


class PersonEmbedding(Base):
    __tablename__ = "person_embeddings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    person_id: Mapped[str] = mapped_column(
        ForeignKey("persons.id", ondelete="CASCADE"), index=True
    )
    # Encrypted float vector (CryptoBox). Carries its model version.
    embedding_enc: Mapped[str] = mapped_column(Text)
    model_version: Mapped[str] = mapped_column(String(64), index=True)
    dimension: Mapped[int] = mapped_column(Integer)
    quality_score: Mapped[float] = mapped_column(Float, default=0.0)
    source_ref_enc: Mapped[str | None] = mapped_column(Text, nullable=True)  # encrypted snapshot key
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Detection(Base):
    __tablename__ = "detections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.id", ondelete="CASCADE"), index=True
    )
    track_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    frame_ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    label: Mapped[str] = mapped_column(String(32), default="person")
    confidence: Mapped[float] = mapped_column(Float)
    bbox: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Track(Base):
    __tablename__ = "tracks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # camera-01-track-1842
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.id", ondelete="CASCADE"), index=True
    )
    identity_id: Mapped[str | None] = mapped_column(
        ForeignKey("persons.id", ondelete="SET NULL"), nullable=True, index=True
    )
    identity_status: Mapped[str] = mapped_column(String(16), default="unknown")  # known/unknown/uncertain
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    bbox: Mapped[dict] = mapped_column(JSON)  # most recent
    trajectory: Mapped[list] = mapped_column(JSON, default=list)  # sampled centers
    # Appearance/attribute tags sampled per track (CLIP zero-shot, non-biometric):
    # {"jacket": true, "jacket_conf": 0.83, "color": "red", …}. JSON-safe and
    # covered by the retention sweep alongside the track row.
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.id", ondelete="CASCADE"), index=True
    )
    track_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    identity_id: Mapped[str | None] = mapped_column(
        ForeignKey("persons.id", ondelete="SET NULL"), nullable=True, index=True
    )
    identity_status: Mapped[str] = mapped_column(String(16), default="unknown")
    event_type: Mapped[str] = mapped_column(String(32), default="presence", index=True)
    timestamp_start: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    timestamp_end: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    bbox: Mapped[dict] = mapped_column(JSON)
    # Structured, non-indexed context for analytic events: rules carry
    # {direction, dwell_sec, count, zone}, ANPR carries {plate_enc, plate_hash}.
    # Must stay JSON-safe; sensitive values are encrypted by callers.
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    snapshot_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    video_segment_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VideoSegment(Base):
    __tablename__ = "video_segments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.id", ondelete="CASCADE"), index=True
    )
    storage_key: Mapped[str] = mapped_column(Text)  # StorageProvider key
    storage_backend: Mapped[str] = mapped_column(String(16), default="local")
    start_ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    end_ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    duration_sec: Mapped[float] = mapped_column(Float, default=0.0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Snapshot(Base):
    __tablename__ = "snapshots"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    camera_id: Mapped[str] = mapped_column(
        ForeignKey("cameras.id", ondelete="CASCADE"), index=True
    )
    track_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_id: Mapped[str | None] = mapped_column(
        ForeignKey("events.id", ondelete="SET NULL"), nullable=True
    )
    storage_key_enc: Mapped[str] = mapped_column(Text)  # encrypted key
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource: Mapped[str] = mapped_column(String(255), default="")
    result: Mapped[str] = mapped_column(String(16), default="success")  # success | failure
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    request_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    __table_args__ = (Index("ix_audit_ts_action", "ts", "action"),)


class SystemMetric(Base):
    __tablename__ = "system_metrics"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[float] = mapped_column(Float)
    tags: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ModelVersion(Base):
    __tablename__ = "model_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(32))
    hash_sha256: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(255), default="")
    license: Mapped[str] = mapped_column(String(64), default="")
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("name", "version", name="uq_model_name_version"),)


class AlertRoute(Base):
    """Maps an analytic event type (or a specific rule_id) to a notification channel.

    `config_enc` holds channel config (webhook URL, SMTP, recipients) encrypted at
    rest; the channel secret is never returned to clients. Routing is evaluated by
    the alerting layer when an AnalyticEvent is produced.
    """
    __tablename__ = "alert_routes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    rule_type: Mapped[str] = mapped_column(String(32), index=True)  # line_cross | intrusion | ... | anpr | *
    camera_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    channel: Mapped[str] = mapped_column(String(16))  # webhook | email | push
    config_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cooldown_sec: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# Indexes for time-range and identity queries.
Index("ix_events_camera_ts", Event.camera_id, Event.timestamp_start)
Index("ix_events_identity_ts", Event.identity_id, Event.timestamp_start)
Index("ix_tracks_camera_last", Track.camera_id, Track.last_seen)
Index("ix_detections_camera_ts", Detection.camera_id, Detection.frame_ts)
