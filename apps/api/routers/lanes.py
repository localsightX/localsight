"""Gate-access lane configuration API (R4.1).

A camera can be armed as a *lane*: its ANPR stream is bound to an access-control
policy — a whitelist of keyed-HMAC plate tokens, an allow-window schedule, and a
barrier action (a webhook/MQTT relay command). Deny by default: a plate that is
not whitelisted inside its window is logged as an event and NEVER triggers the
barrier (the decision engine is `packages.domain.lane.decide_gate_access`,
driven by the worker — this router only configures policy).

Security posture (load-bearing — the barrier is a new privileged side effect):

* Every write needs `lanes:manage`; reads need `lanes:view`. Arming a barrier is
  narrower than `camera:configure`, so a camera admin who must not touch access
  control still cannot arm a gate.
* Barrier destinations pass the SAME SSRF gate as alert routes
  (`_validate_route_destination`, imported — one copy of a security-critical
  validator, not a fork) BEFORE persist. No fixture carve-outs: loopback is
  refused unless the operator allowlists it, so a persisted internal target can
  never become a standing proxy primitive an attacker fires via a plate read.
* Relay credentials live envelope-encrypted in `barrier_config_enc` (never
  returned to a client), exactly like `alert_routes.config_enc`.
* Whitelist rows store ONLY `plate_hash` — the master-key-bound HMAC token the
  ANPR pipeline writes to `Event.detail.plate_hash` — so enrollment and sighting
  share one index and a plaintext plate never reaches the DB. The `query` echo
  is the only plaintext plate in a response and it is what the operator typed
  themselves (the rule `GET /api/search/plates` already follows).
* Every mutation is audit-logged with the plate HASH (never the plaintext) and
  the operator who armed the lane.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.audit import write_audit
from apps.api.bootstrap import Runtime
from apps.api.dependencies import get_current_user, get_db, get_runtime, require_permission
from apps.api.routers.alerts import _validate_route_destination
from apps.api.routers.search import _normalize_plate
from packages.domain.lane import validate_window
from packages.domain.models import (
    PIPELINE_FLAG_LANE_ACCESS,
    Camera,
    Lane,
    LaneWhitelistEntry,
    User,
)
from packages.domain.timeutil import iso

router = APIRouter(prefix="/api", tags=["lanes"])

# Bound every operator-supplied string so a lane cannot become a storage dump.
_NAME_MAX = 255
_COOLDOWN_MAX = 3600  # 1 h: a longer suppression window would hide a stuck gate
_PLATE_MAX = 32
_LABEL_MAX = 255


class LaneIn(BaseModel):
    name: str = Field(default="", max_length=_NAME_MAX)
    barrier_channel: str = Field(default="webhook", pattern="^(webhook|mqtt)$")
    # Relay destination + credentials — envelope-encrypted at rest, never echoed.
    barrier_config: dict | None = None
    allow_window: dict | None = None
    cooldown_sec: int = Field(default=30, ge=0, le=_COOLDOWN_MAX)
    enabled: bool = True


class WhitelistIn(BaseModel):
    plate: str = Field(min_length=1, max_length=_PLATE_MAX)
    label: str = Field(default="", max_length=_LABEL_MAX)
    allow_window: dict | None = None


def _lane_dto(lane: Lane) -> dict:
    """Public shape of a lane. ``barrier_config_enc`` is never decrypted or
    echoed — only the fact that a destination is configured (so the UI can say
    'barrier not configured' instead of silently making a lane that can't open)."""
    return {
        "id": lane.id,
        "camera_id": lane.camera_id,
        "name": lane.name,
        "barrier_channel": lane.barrier_channel or "webhook",
        "barrier_configured": lane.barrier_config_enc is not None,
        "allow_window": lane.allow_window,
        "cooldown_sec": lane.cooldown_sec,
        "enabled": lane.enabled,
        "armed_by": lane.armed_by,
        "created_at": iso(lane.created_at),
    }


def _entry_dto(entry: LaneWhitelistEntry) -> dict:
    return {
        "id": entry.id,
        "lane_id": entry.lane_id,
        "plate_hash": entry.plate_hash,
        "label": entry.label,
        "allow_window": entry.allow_window,
        "enabled": entry.enabled,
        "created_at": iso(entry.created_at),
    }


def _require_camera(db: Session, camera_id: str) -> Camera:
    cam = db.get(Camera, camera_id)
    if cam is None:
        raise HTTPException(status_code=404, detail="camera not found")
    return cam


def _require_lane(db: Session, camera_id: str) -> tuple[Camera, Lane]:
    cam = _require_camera(db, camera_id)
    lane = db.execute(select(Lane).where(Lane.camera_id == camera_id)).scalar_one_or_none()
    if lane is None:
        raise HTTPException(status_code=404, detail="camera has no lane configured")
    return cam, lane


def _check_window(window: dict | None) -> None:
    """Fail-closed structural validation, mapped to a 400 for the operator."""
    try:
        validate_window(window)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/cameras/{camera_id}/lane",
            dependencies=[Depends(require_permission("lanes:view"))])
def get_lane(camera_id: str, db: Session = Depends(get_db)):
    """The lane policy for a camera with its whitelist (404 if not a lane).

    The response carries `plate_hash` (a keyed digest, never the plaintext plate)
    so an operator can cross-reference a whitelist row against a gate event row.
    """
    _, lane = _require_lane(db, camera_id)
    entries = db.execute(
        select(LaneWhitelistEntry)
        .where(LaneWhitelistEntry.lane_id == lane.id)
        .order_by(LaneWhitelistEntry.created_at.desc())
    ).scalars().all()
    return {**_lane_dto(lane), "whitelist": [_entry_dto(e) for e in entries]}


@router.put("/cameras/{camera_id}/lane",
            dependencies=[Depends(require_permission("lanes:manage"))])
def put_lane(
    camera_id: str,
    body: LaneIn,
    request: Request,
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
    user: User = Depends(get_current_user),
):
    """Create or replace a camera's gate-access lane (idempotent per camera).

    Arming a lane also sets `camera.pipeline_flags.lane_access` — the worker
    evaluates the lane only while that flag is true — so 'the lane exists' and
    'the camera is operating as a lane' can never drift apart. Disarming
    (`enabled: false`) clears the flag and stops evaluation entirely.
    """
    cam = _require_camera(db, camera_id)
    _check_window(body.allow_window)
    if body.barrier_config is not None:
        # SSRF gate BEFORE persist: the worker dials this destination
        # unattended on every whitelisted plate read.
        _validate_route_destination(body.barrier_channel, body.barrier_config,
                                    rt.settings.ssrf_allowlist_cidrs)

    lane = db.execute(select(Lane).where(Lane.camera_id == camera_id)).scalar_one_or_none()
    created = lane is None
    if lane is None:
        lane = Lane(camera_id=camera_id)
        db.add(lane)
        try:
            db.flush()  # materialize the id for the audit resource
        except IntegrityError:  # two concurrent armings of one camera — one wins
            db.rollback()
            lane = db.execute(select(Lane).where(Lane.camera_id == camera_id)).scalar_one()

    lane.name = body.name
    lane.barrier_channel = body.barrier_channel
    lane.barrier_config_enc = (
        rt.crypto.encrypt_json(body.barrier_config) if body.barrier_config else None
    )
    lane.allow_window = body.allow_window
    lane.cooldown_sec = body.cooldown_sec
    lane.enabled = body.enabled
    lane.armed_by = user.id

    # Mirror the analytic switch onto the camera so the worker's
    # pipeline_flag_enabled check agrees with the lane's own state.
    flags = dict(cam.pipeline_flags or {})
    flags[PIPELINE_FLAG_LANE_ACCESS] = body.enabled
    cam.pipeline_flags = flags

    db.flush()
    write_audit(
        db, user=user,
        action="lane.arm" if created else "lane.update",
        resource=f"lanes/{lane.id}",
        request_id=getattr(request.state, "request_id", "-"),
        # No barrier config here — it holds relay credentials.
        detail={"camera_id": camera_id, "channel": lane.barrier_channel,
                "enabled": body.enabled, "cooldown_sec": body.cooldown_sec},
    )
    db.commit()
    return _lane_dto(lane)


@router.delete("/cameras/{camera_id}/lane",
               dependencies=[Depends(require_permission("lanes:manage"))])
def delete_lane(
    camera_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Remove a camera's lane policy and its whole whitelist (cascade).

    Clears `pipeline_flags.lane_access` so the worker stops evaluating the
    camera. A disarmed-but-present lane (PUT with `enabled: false`) is the
    softer control; this is the erasure path.
    """
    cam, lane = _require_lane(db, camera_id)
    db.delete(lane)
    flags = dict(cam.pipeline_flags or {})
    flags.pop(PIPELINE_FLAG_LANE_ACCESS, None)
    cam.pipeline_flags = flags
    write_audit(db, user=user, action="lane.disarm", resource=f"lanes/{lane.id}",
                request_id=getattr(request.state, "request_id", "-"),
                detail={"camera_id": camera_id})
    db.commit()
    return {"ok": True}


@router.get("/cameras/{camera_id}/lane/whitelist",
            dependencies=[Depends(require_permission("lanes:view"))])
def list_whitelist(camera_id: str, db: Session = Depends(get_db)):
    """Whitelisted plates for a lane, newest first (404 if the camera is not a lane)."""
    _, lane = _require_lane(db, camera_id)
    entries = db.execute(
        select(LaneWhitelistEntry)
        .where(LaneWhitelistEntry.lane_id == lane.id)
        .order_by(LaneWhitelistEntry.created_at.desc())
    ).scalars().all()
    return {"lane_id": lane.id, "items": [_entry_dto(e) for e in entries]}


@router.post("/cameras/{camera_id}/lane/whitelist", status_code=201,
             dependencies=[Depends(require_permission("lanes:manage"))])
def enroll_plate(
    camera_id: str,
    body: WhitelistIn,
    request: Request,
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
    user: User = Depends(get_current_user),
):
    """Enroll one plate on a lane.

    The plate is normalized exactly like the OCR pipeline and stored as its
    master-key HMAC token — the identical token space the worker joins against
    `Event.detail.plate_hash`, so an enrolled plate matches a sighting by
    construction and a plaintext plate never reaches the DB. The label is an
    operator note and must not BE the plate (a note that duplicates the plate
    is a plaintext-plate store with a worse name).
    """
    _, lane = _require_lane(db, camera_id)
    plate = _normalize_plate(body.plate)
    if not plate:
        raise HTTPException(status_code=400, detail="plate has no alphanumeric characters")
    if plate in _normalize_plate(body.label):
        raise HTTPException(
            status_code=400,
            detail="label must not contain the plate — it is an operator note, "
                   "not a plaintext-plate store",
        )
    _check_window(body.allow_window)

    token = rt.crypto.hmac_str(plate)
    dup = db.execute(
        select(LaneWhitelistEntry)
        .where(LaneWhitelistEntry.lane_id == lane.id,
               LaneWhitelistEntry.plate_hash == token)
    ).scalar_one_or_none()
    if dup is not None:
        raise HTTPException(status_code=409, detail="plate already whitelisted on this lane")

    entry = LaneWhitelistEntry(
        lane_id=lane.id, plate_hash=token, label=body.label,
        allow_window=body.allow_window, created_by=user.id,
    )
    db.add(entry)
    try:
        db.flush()
    except IntegrityError:  # race with a concurrent enrollment of the same plate
        db.rollback()
        raise HTTPException(
            status_code=409, detail="plate already whitelisted on this lane",
        ) from None

    write_audit(
        db, user=user,
        action="lane.whitelist.add",
        resource=f"lanes/{lane.id}",
        request_id=getattr(request.state, "request_id", "-"),
        detail={"plate_hash": token, "label": body.label},  # hash only, never the plate
    )
    db.commit()
    return {**_entry_dto(entry), "query": {"plate": plate}}


@router.delete("/lanes/whitelist/{entry_id}",
               dependencies=[Depends(require_permission("lanes:manage"))])
def revoke_plate(
    entry_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Remove one whitelist entry (404 if unknown). The next read of that plate
    is denied and logged — revocation takes effect immediately because the
    worker joins the whitelist per read."""
    entry = db.get(LaneWhitelistEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="whitelist entry not found")
    lane_id = entry.lane_id
    db.delete(entry)
    write_audit(db, user=user, action="lane.whitelist.remove",
                resource=f"lanes/{lane_id}",
                request_id=getattr(request.state, "request_id", "-"),
                detail={"plate_hash": entry.plate_hash})
    db.commit()
    return {"ok": True}
