"""Secure media delivery.

Video/snapshot bytes are served ONLY through short-lived, cryptographically
signed URLs (HMAC over key+expiry). There is no permanent public link. Access
also requires an authenticated session with video:view. Path traversal is
defeated by the storage layer's key validation.
"""
from __future__ import annotations

import mimetypes

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from apps.api.bootstrap import Runtime
from apps.api.dependencies import get_runtime

router = APIRouter(tags=["video"])


@router.get("/api/video/{key:path}")
def serve_video(
    key: str,
    request: Request,
    exp: str = Query(...),
    sig: str = Query(...),
    rt: Runtime = Depends(get_runtime),
) -> StreamingResponse:
    """Serve a media object via its signed, expiring URL.

    Authorization is the URL signature itself — an HMAC over `key:exp` with
    the master key, valid ≤ `signed_url_ttl` (default 300 s) and scoped to
    this one object. A Bearer session is NOT required here because these
    URLs are consumed by <img>/<video> tags, which cannot send Authorization
    headers. The signature is the designed credential for media delivery
    (see packages/storage/base.py); treating it as such is what lets the
    dashboard drawer render snapshots and clips.

    Signed URLs are issued only by permissioned endpoints (event detail,
    export, clip assembly), which audit every issuance.

    Large recordings stream from disk (never buffered into the heap) with
    HTTP Range support so <video> scrubbing works without re-downloading.
    """
    if not rt.storage.verify_signed_url(key, exp, sig):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid or expired link")
    ctype = mimetypes.guess_type(key)[0] or "application/octet-stream"
    headers = {"Cache-Control": "no-store", "Accept-Ranges": "bytes"}
    try:
        size = rt.storage.size(key)
    except (FileNotFoundError, ValueError, OSError):
        raise HTTPException(status_code=404, detail="not found") from None
    range_hdr = request.headers.get("range")
    if range_hdr:
        start, end = _parse_range(range_hdr, size)
        if start is None:
            return StreamingResponse(
                iter([b""]),
                status_code=416,
                headers={**headers, "Content-Range": f"bytes */{size}"},
            )
        return StreamingResponse(
            rt.storage.read_range(key, start, end),
            status_code=206,
            media_type=ctype,
            headers={
                **headers,
                "Content-Range": f"bytes {start}-{end}/{size}",
                "Content-Length": str(end - start + 1),
            },
        )
    return StreamingResponse(
        rt.storage.read_range(key, 0, size - 1),
        media_type=ctype,
        headers={**headers, "Content-Length": str(size)},
    )


def _parse_range(header: str, size: int) -> tuple[int | None, int]:
    """Parse a single `bytes=start-end` range. Returns (start, end) inclusive,
    or (None, 0) when unsatisfiable (caller answers 416)."""
    try:
        units, spec = header.strip().split("=", 1)
        if units.strip().lower() != "bytes":
            return None, 0
        start_s, _, end_s = spec.strip().partition("-")
        if start_s:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
        elif end_s:
            # Suffix range: last N bytes.
            start = max(0, size - int(end_s))
            end = size - 1
        else:
            return None, 0
    except ValueError:
        return None, 0
    if start < 0 or end < start or start >= size:
        return None, 0
    return start, min(end, size - 1)
