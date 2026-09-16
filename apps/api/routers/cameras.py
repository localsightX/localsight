"""Camera & NVR management.

Security notes:
  * Operator-supplied stream URLs are SSRF-validated before being stored or
    used; private/loopback/metadata destinations are rejected unless explicitly
    allow-listed at deploy time.
  * Stream URLs and NVR credentials are encrypted at rest and NEVER returned to
    API clients (CameraOut omits them by design).
  * All create/update/delete actions are audited.
"""
from __future__ import annotations

import datetime as dt
from urllib.parse import urlparse, urlunparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.audit import write_audit
from apps.api.bootstrap import Runtime
from apps.api.dependencies import get_current_user, get_db, get_runtime, require_permission
from packages.domain.models import Camera, NvrDevice, Snapshot, VideoSegment
from packages.domain.schemas import TPLinkNvrSeed
from packages.domain.timeutil import iso
from packages.security.crypto import CryptoBox
from packages.security.errors import UnsafeUrlError
from packages.security.ssrf import validate_egress_url
from packages.video import presets as vendor_presets
from packages.video import tplink
from packages.video.onvif import OnvifClient

router = APIRouter(prefix="/api", tags=["cameras"])


def _mask_credentials(url: str) -> str:
    """Return the URL with any embedded password replaced by '****' (never echo secrets)."""
    p = urlparse(url)
    if not p.password:
        return url
    user = p.username or ""
    netloc = f"{user}:****@{p.hostname}" + (f":{p.port}" if p.port else "")
    return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))


class NvrBody(BaseModel):
    name: str
    host: str
    port: int = 80
    onvif_supported: bool = False
    username: str | None = None
    password: str | None = None


@router.post("/nvr", dependencies=[Depends(require_permission("camera:configure"))])
def create_nvr(body: NvrBody, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    crypto: CryptoBox = rt.crypto
    nvr = NvrDevice(
        name=body.name,
        host=body.host,
        port=body.port,
        onvif_supported=body.onvif_supported,
        username_enc=crypto.encrypt_str(body.username) if body.username else None,
        password_enc=crypto.encrypt_str(body.password) if body.password else None,
    )
    db.add(nvr)
    db.flush()
    write_audit(db, user=request.state.user, action="nvr.create", resource=nvr.id,
                request_id=getattr(request.state, "request_id", "-"))
    db.commit()
    return {"id": nvr.id, "name": nvr.name, "host": nvr.host, "port": nvr.port,
            "onvif_supported": nvr.onvif_supported}


@router.get("/nvr", dependencies=[Depends(require_permission("camera:configure"))])
def list_nvr(db: Session = Depends(get_db)):
    rows = db.query(NvrDevice).all()
    return [{"id": r.id, "name": r.name, "host": r.host, "port": r.port,
             "onvif_supported": r.onvif_supported} for r in rows]


@router.get("/cameras/presets", dependencies=[Depends(require_permission("camera:view"))])
def stream_presets():
    """Vendor stream URL templates. TP-Link VIGI/Tapo conventions included."""
    return tplink.list_profiles()


@router.get("/cameras/vendor-presets", dependencies=[Depends(require_permission("camera:view"))])
def vendor_stream_presets():
    """Broad vendor RTSP/CGI/ISAPI/ONVIF/GB-T 28181 URL conventions."""
    return vendor_presets.list_profiles()


class PresetBuild(BaseModel):
    vendor: str
    cam_ip: str = ""
    channel: int = 1
    stream: str = "sub"
    user: str | None = None
    password: str | None = None
    port: int = 554


@router.post("/cameras/presets/build", dependencies=[Depends(require_permission("camera:configure"))])
def build_preset(body: PresetBuild):
    try:
        url = vendor_presets.build_url(
            body.vendor, cam_ip=body.cam_ip, channel=body.channel, stream=body.stream,
            user=body.user, password=body.password, port=body.port)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"vendor": body.vendor, "url": _mask_credentials(url)}


class OnvifDiscover(BaseModel):
    timeout: float = 2.0


@router.post("/onvif/discover", dependencies=[Depends(require_permission("camera:configure"))])
def onvif_discover(body: OnvifDiscover, request: Request, db: Session = Depends(get_db),
                   rt: Runtime = Depends(get_runtime)):
    """WS-Discovery for ONVIF devices on the LAN. Returns device XAddrs."""
    xaddrs = OnvifClient.discover(timeout=body.timeout)
    write_audit(db, user=request.state.user, action="onvif.discover", resource="lan",
                request_id=getattr(request.state, "request_id", "-"),
                detail={"count": len(xaddrs)})
    return {"xaddrs": xaddrs}


class OnvifStreams(BaseModel):
    xaddr: str
    user: str | None = None
    password: str | None = None


@router.post("/onvif/streams", dependencies=[Depends(require_permission("camera:configure"))])
def onvif_streams(body: OnvifStreams, request: Request, db: Session = Depends(get_db),
                   rt: Runtime = Depends(get_runtime)):
    """Fetch RTSP stream URIs for an ONVIF device's profiles.

    The operator-supplied `xaddr` is egress-validated before any outbound call.
    """
    try:
        validate_egress_url(body.xaddr, allowlist=rt.settings.ssrf_allowlist_cidrs)
    except UnsafeUrlError as exc:
        raise HTTPException(status_code=400, detail=f"unsafe ONVIF address: {exc}")
    client = OnvifClient(body.xaddr, user=body.user, password=body.password)
    uris = client.stream_uris()
    write_audit(db, user=request.state.user, action="onvif.streams", resource=body.xaddr,
                request_id=getattr(request.state, "request_id", "-"),
                detail={"count": len(uris)})
    return {"xaddr": body.xaddr, "stream_uris": uris}


@router.post("/cameras/from-nvr", dependencies=[Depends(require_permission("camera:configure"))])
def provision_tplink_nvr(body: TPLinkNvrSeed, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    """Create a TP-Link VIGI NVR and one Camera per channel.

    Each camera gets the per-channel RTSP URL rtsp://<nvr>/live/ch/<N>/stream/<1|2>
    (main for recording, sub for AI). All URLs are SSRF-validated and encrypted.
    """
    crypto: CryptoBox = rt.crypto
    nvr = NvrDevice(
        name=body.nvr_name,
        host=body.nvr_ip,
        port=body.onvif_port,
        onvif_supported=True,
        username_enc=crypto.encrypt_str(body.username) if body.username else None,
        password_enc=crypto.encrypt_str(body.password) if body.password else None,
    )
    db.add(nvr)
    db.flush()
    created: list[dict] = []
    for ch in range(body.start_channel, body.start_channel + body.channel_count):
        main_url = tplink.nvr_channel_rtsp_url(body.nvr_ip, ch, stream="main", port=body.rtsp_port,
                                               user=body.username, password=body.password)
        sub_url = tplink.nvr_channel_rtsp_url(body.nvr_ip, ch, stream="sub", port=body.rtsp_port,
                                              user=body.username, password=body.password)
        for label, url in (("stream_url", main_url), ("substream_url", sub_url)):
            try:
                validate_egress_url(url, allowlist=rt.settings.ssrf_allowlist_cidrs)
            except UnsafeUrlError as exc:
                db.rollback()
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"channel {ch} {label}: {exc}") from exc
        cam = Camera(
            name=f"{body.nvr_name} ch{ch}",
            nvr_device_id=nvr.id,
            stream_url_enc=crypto.encrypt_str(main_url),
            substream_url_enc=crypto.encrypt_str(sub_url),
            resolution="",
            fps=0,
            timezone="UTC",
            retention={"days": body.retention_days},
            status="OFFLINE",
        )
        db.add(cam)
        db.flush()
        created.append({"id": cam.id, "name": cam.name, "channel": ch,
                        "main_stream": main_url, "sub_stream": sub_url})
    write_audit(db, user=request.state.user, action="nvr.create", resource=nvr.id,
                request_id=getattr(request.state, "request_id", "-"),
                detail={"channels": body.channel_count, "vendor": "vigi_nvr"})
    write_audit(db, user=request.state.user, action="camera.bulk_create", resource=nvr.id,
                request_id=getattr(request.state, "request_id", "-"),
                detail={"count": len(created)})
    db.commit()
    return {"nvr_id": nvr.id, "nvr_host": nvr.host, "cameras": created}


@router.post("/cameras", dependencies=[Depends(require_permission("camera:configure"))])
def create_camera(body: dict, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    name = body.get("name")
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    main_url = body.get("stream_url")
    sub_url = body.get("substream_url")
    # SSRF guard on egress destinations.
    for label, url in (("stream_url", main_url), ("substream_url", sub_url)):
        if url:
            try:
                validate_egress_url(url, allowlist=rt.settings.ssrf_allowlist_cidrs)
            except UnsafeUrlError as exc:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"{label}: {exc}") from exc

    cam = Camera(
        name=name,
        camera_uid=body.get("camera_uid"),
        nvr_device_id=body.get("nvr_device_id"),
        stream_url_enc=rt.crypto.encrypt_str(main_url) if main_url else None,
        substream_url_enc=rt.crypto.encrypt_str(sub_url) if sub_url else None,
        resolution=body.get("resolution", ""),
        fps=int(body.get("fps", 0) or 0),
        timezone=body.get("timezone", "UTC"),
        privacy_masks=body.get("privacy_masks"),
        retention=body.get("retention"),
        status="OFFLINE",
    )
    db.add(cam)
    db.flush()
    write_audit(db, user=request.state.user, action="camera.create", resource=cam.id,
                request_id=getattr(request.state, "request_id", "-"),
                detail={"name": name})
    db.commit()
    return {"id": cam.id, "name": cam.name, "status": cam.status}


@router.get("/cameras", dependencies=[Depends(require_permission("camera:view"))])
def list_cameras(db: Session = Depends(get_db)):
    rows = db.query(Camera).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "camera_uid": r.camera_uid,
            "nvr_device_id": r.nvr_device_id,
            "status": r.status,
            "health": r.health,
            "last_seen": iso(r.last_seen) if r.last_seen else None,
            "resolution": r.resolution,
            "fps": r.fps,
            "timezone": r.timezone,
            "privacy_masks": r.privacy_masks,
            "retention": r.retention,
        }
        for r in rows
    ]


@router.get("/cameras/{camera_id}", dependencies=[Depends(require_permission("camera:view"))])
def get_camera(camera_id: str, db: Session = Depends(get_db)):
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    return {
        "id": cam.id, "name": cam.name, "camera_uid": cam.camera_uid,
        "nvr_device_id": cam.nvr_device_id,
        "status": cam.status, "health": cam.health,
        "last_seen": iso(cam.last_seen) if cam.last_seen else None,
        "resolution": cam.resolution, "fps": cam.fps, "timezone": cam.timezone,
        "privacy_masks": cam.privacy_masks, "retention": cam.retention,
    }


@router.get("/cameras/{camera_id}/snapshot-url", dependencies=[Depends(require_permission("camera:view"))])
def camera_snapshot_url(camera_id: str, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    """Mint a short-lived signed URL for the snapshot endpoint.

    The mask editor's <img> cannot carry the in-memory bearer token (the
    browser attaches no Authorization header to image loads), so the frame
    is fetched with an HMAC-signed query instead — same scheme the storage
    layer uses for event media (exp + sig over "camera-snapshot:{id}"),
    300 s lifetime, constant-time comparison.
    """
    import hashlib
    import hmac as hmac_mod
    import time as time_mod

    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    key = f"camera-snapshot:{camera_id}"
    exp = int(time_mod.time()) + 300
    msg = f"{key}:{exp}".encode()
    mac = hmac_mod.new(rt.settings.master_encryption_key.encode(), msg, hashlib.sha256)
    return {"url": f"/api/cameras/{camera_id}/snapshot?exp={exp}&sig={mac.hexdigest()}",
            "expires_at": exp}


@router.get("/cameras/{camera_id}/snapshot")
def camera_snapshot(request: Request, camera_id: str, db: Session = Depends(get_db),
                    rt: Runtime = Depends(get_runtime), exp: str = "", sig: str = ""):
    """One JPEG frame from the camera — for the privacy-mask editor canvas,
    add-camera verification, and live-tile posters.

    Reads at most one frame via a one-shot ffmpeg argv (no shell, validated
    URL, terminated AND reaped). Honest failure modes, no fake frames:
      * 404 camera unknown
      * 409 no stream URL configured
      * 503 stream unreachable / ffmpeg missing (or no frame within timeout)

    Auth (either):
      * a session bearer token with camera:view, OR
      * the signed exp/sig pair minted by /snapshot-url — <img> loads can't
        send Authorization headers, so the canvas uses the signed form.
    """
    import hashlib
    import hmac as hmac_mod
    import subprocess
    import time as time_mod

    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")

    # ── auth: session token OR valid signature ──────────────────────────
    authorized = False
    authz = request.headers.get("Authorization", "")
    if authz.startswith("Bearer "):
        try:
            get_current_user(request, db)  # raises 401 itself if invalid
            authorized = "camera:view" in getattr(request.state, "permissions", set())
        except HTTPException:
            authorized = False
    if not authorized and exp and sig:
        try:
            exp_i = int(exp)
        except ValueError:
            raise HTTPException(status_code=400, detail="bad exp") from None
        if exp_i < int(time_mod.time()):
            raise HTTPException(status_code=410, detail="signed URL expired")
        key = f"camera-snapshot:{camera_id}"
        expected = hmac_mod.new(rt.settings.master_encryption_key.encode(),
                                f"{key}:{exp_i}".encode(), hashlib.sha256).hexdigest()
        if hmac_mod.compare_digest(expected, sig):
            authorized = True
    if not authorized:
        raise HTTPException(status_code=401,
                            detail="camera snapshot needs a session or a signed URL")

    url_enc = cam.substream_url_enc or cam.stream_url_enc
    if not url_enc:
        raise HTTPException(status_code=409, detail="no stream URL configured")
    url = rt.crypto.decrypt_str(url_enc)
    # Re-validate on use (the stored URL passed validation at write time; this
    # is the standing defense-in-depth rule for every egress call site).
    try:
        validate_egress_url(url, allowlist=rt.settings.ssrf_allowlist_cidrs)
    except UnsafeUrlError as exc:
        raise HTTPException(status_code=400, detail=f"stream url rejected: {exc}") from exc

    args = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
            "-rtsp_transport", "tcp", "-i", url,
            "-an", "-frames:v", "1",
            "-f", "image2", "-vcodec", "mjpeg", "-"]
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    except OSError as exc:
        raise HTTPException(status_code=503, detail="ffmpeg unavailable") from exc
    try:
        # Bounded wait: an unreachable RTSP host can hold the TCP handshake
        # for minutes; the mask editor needs an answer, not a hung request.
        frame, _ = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait(timeout=5)
        raise HTTPException(status_code=503, detail="camera unreachable (timeout)") from exc
    except Exception as exc:
        proc.kill()
        proc.wait(timeout=5)
        raise HTTPException(status_code=503, detail="snapshot failed") from exc
    # A JPEG starts with the SOI marker; a timeout/unreachable camera yields
    # an empty or non-JPEG buffer.
    if not frame.startswith(b"\xff\xd8"):
        raise HTTPException(status_code=503, detail="camera unreachable (no frame)")
    from fastapi import Response as FastAPIResponse
    return FastAPIResponse(content=frame, media_type="image/jpeg")


@router.put("/cameras/{camera_id}", dependencies=[Depends(require_permission("camera:configure"))])
def update_camera(camera_id: str, body: dict, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    for f in ("name", "resolution", "fps", "timezone", "privacy_masks", "retention"):
        if f in body:
            setattr(cam, f, body[f])
    # UnsafeUrlError is a 400, not a 500: validate_egress_url raises (it doesn't
    # return False), so an uncaught raise here bypassed the 400 handler above
    # and surfaced as an internal error — leaking stack behavior and breaking
    # the API contract that bad destinations are client errors.
    if body.get("stream_url"):
        try:
            validate_egress_url(body["stream_url"], allowlist=rt.settings.ssrf_allowlist_cidrs)
        except UnsafeUrlError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"stream_url: {exc}") from exc
        cam.stream_url_enc = rt.crypto.encrypt_str(body["stream_url"])
    if body.get("substream_url"):
        try:
            validate_egress_url(body["substream_url"], allowlist=rt.settings.ssrf_allowlist_cidrs)
        except UnsafeUrlError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"substream_url: {exc}") from exc
        cam.substream_url_enc = rt.crypto.encrypt_str(body["substream_url"])
    write_audit(db, user=request.state.user, action="camera.update", resource=camera_id,
                request_id=getattr(request.state, "request_id", "-"))
    db.commit()
    return {"id": cam.id, "name": cam.name, "status": cam.status}


@router.delete("/cameras/{camera_id}", dependencies=[Depends(require_permission("camera:configure"))])
def delete_camera(camera_id: str, request: Request, db: Session = Depends(get_db),
                  rt: Runtime = Depends(get_runtime)):
    """Remove a camera from the configuration.

    Removal is immediate and irreversible. The camera row goes, FK cascades
    take its detections, tracks, events, snapshots and recording segments, and
    the media objects those rows point at are deleted best-effort (the rows are
    the source of truth; an unreachable object store must not block a removal).

    Two live resources are torn down as well, so a removed camera stops costing
    CPU, bandwidth and disk:
      * its LL-HLS live transcode, owned by this API process, and
      * its worker pipeline, which notices the row is gone on its next
        heartbeat (<= 30 s) and winds down its frame loop and recorder.

    The audit entry is written before the row is deleted, so the record of WHO
    removed WHICH camera survives the removal.
    """
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")

    # Stop the live transcode BEFORE the row disappears: ffmpeg must not keep
    # writing into a camera id that no longer exists. Imported locally so the
    # routers never become mutually load-bearing at import time.
    from apps.api.routers.live import stop_camera_stream

    live_stopped = stop_camera_stream(camera_id)

    # FK cascades (ondelete) remove the rows; their storage objects would
    # otherwise orphan forever, so collect keys first and delete best-effort.
    seg_keys = [
        row[0] for row in db.query(VideoSegment.storage_key)
        .filter(VideoSegment.camera_id == camera_id).all()
    ]
    snap_keys = []
    for row in db.query(Snapshot.storage_key_enc).filter(Snapshot.camera_id == camera_id).all():
        try:
            snap_keys.append(rt.crypto.decrypt_str(row[0]))
        except Exception:
            continue
    db.delete(cam)
    write_audit(db, user=request.state.user, action="camera.delete", resource=camera_id,
                request_id=getattr(request.state, "request_id", "-"))
    db.commit()
    for key in seg_keys + snap_keys:
        try:
            rt.storage.delete(key)
        except Exception:
            pass
    return {"ok": True, "live_stream_stopped": live_stopped}


# ── NVR archive: per-camera recordings for scrub-back playback ──────────────
#
# The dashboard's live-view DVR player scrubs from "now" back into the
# archive. It needs the segment timeline for a camera (time-ordered, with
# durations) plus short-lived signed playback URLs per segment — the same
# scheme event media uses. Only rows whose file actually landed in storage
# are listed (size > 0): the recorder writes the row only after a successful
# put_stream, so an operator never scrubs into a hole that 404s.

def _parse_ts(value: str, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"bad {field}: use ISO 8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    """SQLite returns naive datetimes; normalize to UTC for arithmetic with
    aware parsed inputs (PostgreSQL returns aware — this is a no-op there)."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=dt.UTC)


@router.get("/cameras/{camera_id}/recordings",
            dependencies=[Depends(require_permission("video:view"))])
def camera_recordings(
    camera_id: str,
    request: Request,
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
    start: str = Query(..., description="ISO 8601 lower bound (UTC)"),
    end: str = Query(..., description="ISO 8601 upper bound (UTC)"),
    limit: int = Query(500, le=1000, ge=1),
):
    """Time-ordered recording segments overlapping [start, end], each with a
    signed playback URL (300 s). This is the scrubber's data source: the
    client maps any wall-clock time to the segment whose [start_ts, end_ts]
    contains it, then seeks to the offset within that segment's file."""
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    lo = _parse_ts(start, "start")
    hi = _parse_ts(end, "end")
    if hi <= lo:
        raise HTTPException(status_code=400, detail="end must be after start")
    rows = db.execute(
        select(VideoSegment)
        .where(VideoSegment.camera_id == camera_id)
        .where(VideoSegment.start_ts < hi)
        .where(VideoSegment.end_ts > lo)
        .where(VideoSegment.size_bytes > 0)
        .order_by(VideoSegment.start_ts.asc())
        .limit(limit)
    ).scalars().all()
    return {
        "camera_id": camera_id,
        "start": iso(lo),
        "end": iso(hi),
        "segments": [
            {
                "id": s.id,
                "start_ts": iso(s.start_ts),
                "end_ts": iso(s.end_ts),
                "duration_sec": s.duration_sec,
                "size_bytes": s.size_bytes,
                "url": rt.storage.sign_get_url(s.storage_key, expires_sec=300),
            }
            for s in rows
        ],
    }


@router.get("/cameras/{camera_id}/recordings/at",
            dependencies=[Depends(require_permission("video:view"))])
def recording_at(
    camera_id: str,
    request: Request,
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
    t: str = Query(..., description="ISO 8601 wall-clock time (UTC)"),
):
    """The single segment containing time `t`, with a signed URL and the
    offset-in-file to seek to. 404 when nothing covers that moment (no
    recording, retention, or gap before the first segment) — the client's
    honest 'no footage at this time' state."""
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    ts = _parse_ts(t, "t")
    seg = db.execute(
        select(VideoSegment)
        .where(VideoSegment.camera_id == camera_id)
        .where(VideoSegment.start_ts <= ts)
        .where(VideoSegment.end_ts >= ts)
        .where(VideoSegment.size_bytes > 0)
        .order_by(VideoSegment.start_ts.asc())
        .limit(1)
    ).scalars().first()
    if not seg:
        raise HTTPException(status_code=404, detail="no recording at this time")
    return {
        "camera_id": camera_id,
        "segment_id": seg.id,
        "start_ts": iso(seg.start_ts),
        "end_ts": iso(seg.end_ts),
        "duration_sec": seg.duration_sec,
        "seek_offset_sec": max(0.0, (ts - _aware(seg.start_ts)).total_seconds()),
        "url": rt.storage.sign_get_url(seg.storage_key, expires_sec=300),
    }
