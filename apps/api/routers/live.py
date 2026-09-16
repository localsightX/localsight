"""Live view API.

Issues short-lived, camera-scoped, signed tickets that authorize a media gateway
to stream a camera's substream (LL-HLS/WebRTC) without exposing the RTSP URL or
long-lived credentials to the client. Tickets are encrypted envelopes (carry their
own expiry) and are verified on the play endpoint. This keeps the secure-boundary
model: authn/authz is enforced server-side; the media gateway only honors valid tickets.

Stream lifecycle (see docs/reviews/CODE_ANALYSIS_REPORT.md F-07): every transcode
is tracked with its start time and the time the client last requested it. A reaper
thread terminates streams that are idle beyond LIVE_IDLE_TIMEOUT_SEC or older than
LIVE_MAX_DURATION_SEC, and reaps exited processes — ffmpeg never accumulates
without bound, and viewers-closed-tab streams die instead of transcoding forever.
"""
from __future__ import annotations

import datetime as dt
import os
import subprocess
import threading

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.bootstrap import Runtime
from apps.api.dependencies import get_current_user, get_db, get_runtime, require_permission
from apps.api.domain_live_cfg import LIVE_DIR, LIVE_IDLE_TIMEOUT_SEC, LIVE_MAX_DURATION_SEC
from packages.domain.models import Camera
from packages.domain.timeutil import iso
from packages.observability.logging import logging as log

router = APIRouter(prefix="/api", tags=["live"])

_live_lock = threading.Lock()


class _LiveStream:
    __slots__ = ("proc", "started_ts", "last_probe_ts")

    def __init__(self, proc: subprocess.Popen) -> None:
        self.proc = proc
        self.started_ts = dt.datetime.now(dt.timezone.utc)
        self.last_probe_ts = self.started_ts


_live_streams: dict[str, _LiveStream] = {}

_reaper_started = False
_reaper_lock = threading.Lock()


def _terminate_and_reap(proc: subprocess.Popen) -> None:
    """Terminate and wait so exited ffmpeg children never linger as zombies."""
    if proc.poll() is None:
        try:
            proc.terminate()
        except OSError:  # noqa: BLE001 - already dead
            return
    try:
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001 - best-effort reap
        try:
            proc.kill()
        except OSError:
            pass


def _ensure_reaper() -> None:
    """Start the idle-reaper daemon once (lazily, on first stream)."""
    global _reaper_started
    if _reaper_started:
        return
    with _reaper_lock:
        if _reaper_started:
            return
        _reaper_started = True

        def _reap_loop() -> None:
            while True:
                threading.Event().wait(LIVE_IDLE_TIMEOUT_SEC)
                now = dt.datetime.now(dt.timezone.utc)
                with _live_lock:
                    stale = []
                    for cid, ls in _live_streams.items():
                        idle_for = (now - ls.last_probe_ts).total_seconds()
                        age = (now - ls.started_ts).total_seconds()
                        if idle_for > LIVE_IDLE_TIMEOUT_SEC or age > LIVE_MAX_DURATION_SEC:
                            stale.append((cid, ls, idle_for > LIVE_IDLE_TIMEOUT_SEC))
                    for cid, ls, idle in stale:
                        _live_streams.pop(cid, None)
                for cid, ls, idle in stale:
                    _terminate_and_reap(ls.proc)
                    log.info(
                        "live stream for %s stopped (%s)",
                        cid, "idle" if idle else "max duration",
                    )

        threading.Thread(target=_reap_loop, name="live-reaper", daemon=True).start()


def _start_stream(rt, camera, url: str) -> str:
    """Launch (or reuse) an ffmpeg LL-HLS transcode of the camera substream.

    Returns the directory holding index.m3u8. Raises HTTPException(503) if the
    transcode cannot start — the manifest must never be handed out for a
    stream that isn't running.
    The operator-supplied URL is egress-validated first.
    """
    try:
        from packages.security.ssrf import validate_egress_url

        validate_egress_url(url, allowlist=rt.settings.ssrf_allowlist_cidrs)
    except Exception as exc:  # noqa: BLE001 - unsafe destination
        raise HTTPException(status_code=400, detail=f"unsafe stream URL: {exc}")
    os.makedirs(LIVE_DIR, exist_ok=True)
    out_dir = os.path.join(LIVE_DIR, camera.id)
    with _live_lock:
        existing = _live_streams.get(camera.id)
        if existing is not None:
            if existing.proc.poll() is None:
                existing.last_probe_ts = dt.datetime.now(dt.timezone.utc)
                return out_dir  # already streaming; viewer still watching
            _live_streams.pop(camera.id, None)
            _terminate_and_reap(existing.proc)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
        "-rtsp_transport", "tcp", "-i", url,
        "-an", "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
        "-f", "hls", "-hls_time", "2", "-hls_list_size", "10",
        "-hls_flags", "delete_segments",
        "-hls_segment_filename", os.path.join(out_dir, "%05d.ts"),
        os.path.join(out_dir, "index.m3u8"),
    ]
    try:
        # Own process group so terminate() hits ffmpeg cleanly even under a
        # supervising shell, and so its children don't outlive the API restart.
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        # No ffmpeg / bad argv: fail loudly. Returning a manifest that will
        # never exist makes the dashboard show a permanently dead player.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"live transcode failed to start: {exc}",
        ) from exc
    with _live_lock:
        _live_streams[camera.id] = _LiveStream(proc)
    _ensure_reaper()
    return out_dir


def _stop_stream(camera_id: str) -> bool:
    with _live_lock:
        ls = _live_streams.pop(camera_id, None)
    if ls is None:
        return False
    _terminate_and_reap(ls.proc)
    return True


def stop_camera_stream(camera_id: str) -> bool:
    """Public stop entry point: tear down a camera's live transcode, if any.

    Camera deletion (cameras router) uses this so removing a camera also stops
    its ffmpeg instead of leaving it writing under an id that no longer exists.
    Returns True when a transcode was actually stopped.
    """
    return _stop_stream(camera_id)


def shutdown_live_streams() -> None:
    """Stop every transcode (called on app shutdown so ffmpeg doesn't orphan)."""
    with _live_lock:
        streams = list(_live_streams.values())
        _live_streams.clear()
    for ls in streams:
        _terminate_and_reap(ls.proc)


@router.get("/live/streams", dependencies=[Depends(require_permission("live:view"))])
def live_streams():
    """Return the currently active live transcodes (presence/health).

    Each entry reports whether the ffmpeg process is still running, its PID,
    and how long ago the client last requested it — dead processes are dropped
    and idle streams report themselves ahead of the reaper.
    """
    now = dt.datetime.now(dt.timezone.utc)
    active = []
    with _live_lock:
        for camera_id, ls in _live_streams.items():
            if ls.proc.poll() is not None:
                continue
            active.append({
                "camera_id": camera_id,
                "running": True,
                "pid": ls.proc.pid,
                "idle_sec": int((now - ls.last_probe_ts).total_seconds()),
            })
    return {"active": active, "count": len(active)}


@router.post("/live/{camera_id}/stop", dependencies=[Depends(require_permission("live:view"))])
def stop_stream(camera_id: str):
    """Explicitly stop a camera's live transcode (dashboard 'stop' control).

    Returns 200 with `stopped: false` when no transcode was running — the
    end state (nothing streaming) is what the caller wants either way.
    """
    stopped = _stop_stream(camera_id)
    return {"camera_id": camera_id, "stopped": stopped}


class TicketRequest(BaseModel):
    camera_id: str
    ttl_sec: int = 300


@router.post("/live/ticket", dependencies=[Depends(require_permission("live:view"))])
def issue_ticket(body: TicketRequest, request: Request, db: Session = Depends(get_db),
                 rt: Runtime = Depends(get_runtime)):
    cam = db.get(Camera, body.camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=max(30, min(body.ttl_sec, 3600)))
    token = rt.crypto.encrypt_json({"camera_id": body.camera_id, "exp": iso(exp)})
    from apps.api.audit import write_audit
    write_audit(db, user=request.state.user, action="live.ticket.issue", resource=body.camera_id,
                request_id=getattr(request.state, "request_id", "-"))
    return {"camera_id": body.camera_id, "ticket": token, "expires_at": iso(exp)}


@router.get("/live/{camera_id}/play", dependencies=[Depends(require_permission("live:view"))])
def play(camera_id: str, ticket: str, db: Session = Depends(get_db),
         rt: Runtime = Depends(get_runtime)):
    """Validate a live ticket and start/return the authorized LL-HLS manifest.

    The media gateway (ffmpeg) exchanges the ticket for the camera substream and
    transcodes it to LL-HLS under /live-media; this endpoint never returns the RTSP
    URL or credentials.
    """
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    try:
        claims = rt.crypto.decrypt_json(ticket)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid ticket")
    if claims.get("camera_id") != camera_id:
        raise HTTPException(status_code=403, detail="ticket not for this camera")
    exp = dt.datetime.fromisoformat(claims["exp"])
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=dt.timezone.utc)
    if exp < dt.datetime.now(dt.timezone.utc):
        raise HTTPException(status_code=401, detail="ticket expired")
    manifest = f"/live-media/{camera_id}/index.m3u8"
    url_enc = cam.substream_url_enc
    if url_enc:
        _start_stream(rt, cam, rt.crypto.decrypt_str(url_enc))
    return {
        "camera_id": camera_id,
        "hls_manifest": manifest,
        "protocols": ["ll-hls"],
        "ticket": ticket,
    }
