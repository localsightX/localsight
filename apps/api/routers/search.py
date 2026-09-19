"""Forensic search API (roadmap R2): attribute, plate, and saved searches.

Privacy posture (docs/security, roadmap 06): a search is an *investigative*
action, so every endpoint here is permission-gated (`search:view`; saving a
query additionally needs `search:save`) and the saved-search lifecycle is
audit-logged. Plate lookups go through the SAME keyed HMAC the worker wrote
(`CryptoBox.hmac_str` over the normalized plate) — no plaintext plate is ever
stored, returned, or matched, and the query echo is only what the operator
typed themselves.

Cross-database note (roadmap 06 risk): SQLite JSON1 and PostgreSQL jsonb
predicate syntaxes differ, so candidate rows are pre-filtered by indexed
columns only (camera/time) with a hard scan cap and matched in Python —
identical semantics on both engines. The ANN index (backlog B3) replaces the
bounded scan when track counts make it necessary.
"""
from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.audit import write_audit
from apps.api.bootstrap import Runtime
from apps.api.dependencies import get_current_user, get_db, get_runtime, require_permission
from packages.domain.models import Event, SavedSearch, Track, User
from packages.domain.timeutil import iso, parse_iso

router = APIRouter(prefix="/api", tags=["search"])

# ── shared caps (a search is user input over the whole DB — bound it) ──
_MAX_SCAN = 20_000          # candidate rows examined per search
_MAX_RESULTS = 100          # rows returned
_MAX_SAVED_PER_USER = 50    # saved searches per account
_PARAM_BYTES = 2048         # saved-search payload ceiling
_STR_MAX = 64               # attribute key/value string bound
_PLATE_RE = r"^[A-Za-z0-9][A-Za-z0-9 .-]{1,15}$"


def _normalize_plate(q: str) -> str:
    """Mirror packages.ai.anpr normalization exactly: uppercase, [A-Z0-9].

    The stored equality token is `CryptoBox.hmac_str(reading.plate)`; the
    pipeline normalizes BEFORE hashing, so the API must hash the identical
    string or the index silently misses. Garbage input normalizes to "" and
    can never match a stored token (empty hash is never written).
    """
    return re.sub(r"[^A-Z0-9]", "", (q or "").upper())


@router.get("/search/attributes", dependencies=[Depends(require_permission("search:view"))])
def search_attributes(
    key: str = Query(..., min_length=1, max_length=_STR_MAX),
    value: str = Query("", max_length=_STR_MAX),
    camera_id: str | None = None,
    start: str = "",
    end: str = "",
    limit: int = Query(25, ge=1, le=_MAX_RESULTS),
    db: Session = Depends(get_db),
):
    """B1 — attribute search over Track.detail (CLIP tags: jacket/color/…).

    Bounded scan of the most recent tracks in the (optionally camera- and
    time-filtered) window, matched in Python for cross-DB JSON parity. Each
    hit carries its most recent event id so the UI can open evidence.
    """
    stmt = select(Track).order_by(Track.last_seen.desc()).limit(_MAX_SCAN)
    if camera_id:
        stmt = stmt.where(Track.camera_id == camera_id)
    t0 = parse_iso(start) if start else None
    t1 = parse_iso(end) if end else None
    if t0:
        stmt = stmt.where(Track.last_seen >= t0)
    if t1:
        stmt = stmt.where(Track.last_seen <= t1)

    matched: list[dict] = []
    for tr in db.execute(stmt).scalars():
        detail = tr.detail if isinstance(tr.detail, dict) else {}
        if key not in detail:
            continue
        hit_value = detail.get(key)
        if value and hit_value != value and hit_value is not True:
            continue
        matched.append({
            "track_id": tr.id,
            "camera_id": tr.camera_id,
            "identity_status": tr.identity_status,
            "first_seen": iso(tr.first_seen),
            "last_seen": iso(tr.last_seen),
            "confidence": round(tr.confidence, 3),
            "matched": {key: hit_value},
            "attributes": detail,
        })
        if len(matched) >= limit:
            break
    return {"query": {"key": key, "value": value}, "results": matched}


@router.get("/search/plates", dependencies=[Depends(require_permission("search:view"))])
def search_plates(
    q: str = Query(..., pattern=_PLATE_RE, description="Plate text (letters/digits)"),
    camera_id: str | None = None,
    start: str = "",
    end: str = "",
    limit: int = Query(25, ge=1, le=_MAX_RESULTS),
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
):
    """B2 — plate search by exact equality over the keyed HMAC index.

    Only exact normalized plates are searchable: the keyed HMAC is not a
    prefix index by design — that property is exactly what makes it safe to
    store. Partial-plate investigations go through the event feed + time
    window. Results never include plate material, only the matching rows.
    """
    token = rt.crypto.hmac_str(_normalize_plate(q))
    stmt = select(Event).where(Event.event_type == "anpr").order_by(
        Event.timestamp_start.desc()).limit(_MAX_SCAN)
    if camera_id:
        stmt = stmt.where(Event.camera_id == camera_id)
    t0 = parse_iso(start) if start else None
    t1 = parse_iso(end) if end else None
    if t0:
        stmt = stmt.where(Event.timestamp_start >= t0)
    if t1:
        stmt = stmt.where(Event.timestamp_start <= t1)

    out: list[dict] = []
    for ev in db.execute(stmt).scalars():
        detail = ev.detail if isinstance(ev.detail, dict) else {}
        if detail.get("plate_hash") != token:
            continue
        out.append({
            "event_id": ev.id,
            "track_id": ev.track_id,
            "camera_id": ev.camera_id,
            "ts": iso(ev.timestamp_start),
            "confidence": round(ev.confidence, 3),
        })
        if len(out) >= limit:
            break
    return {"query": {"plate": _normalize_plate(q)}, "results": out}


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(pattern="^(attributes|plates|text)$")
    params: dict = Field(default_factory=dict)


@router.get("/searches", dependencies=[Depends(require_permission("search:view"))])
def list_saved(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """B8 — the caller's saved searches (never another user's)."""
    rows = db.execute(
        select(SavedSearch).where(SavedSearch.user_id == user.id)
        .order_by(SavedSearch.created_at.desc()).limit(_MAX_SAVED_PER_USER)
    ).scalars().all()
    return {"items": [
        {"id": s.id, "name": s.name, "kind": s.kind, "params": s.params,
         "created_at": iso(s.created_at)}
        for s in rows
    ]}


@router.post("/searches", status_code=201,
             dependencies=[Depends(require_permission("search:save"))])
def save_search(
    body: SavedSearchIn, request: Request,
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    """Save a named, re-runnable query. Audited; payload-bounded."""
    if len(json.dumps(body.params, default=str).encode()) > _PARAM_BYTES:
        raise HTTPException(status_code=422, detail="saved-search payload too large")
    dup = db.execute(
        select(SavedSearch).where(SavedSearch.user_id == user.id, SavedSearch.name == body.name)
    ).scalar_one_or_none()
    if dup is not None:
        raise HTTPException(status_code=409, detail="a saved search with that name exists")
    count = len(db.execute(
        select(SavedSearch).where(SavedSearch.user_id == user.id)).scalars().all())
    if count >= _MAX_SAVED_PER_USER:
        raise HTTPException(status_code=409, detail="saved-search quota reached")
    row = SavedSearch(user_id=user.id, name=body.name, kind=body.kind, params=body.params)
    db.add(row)
    db.flush()  # id available for the audit resource before the single commit
    write_audit(db, user=user, action="search.save",
                resource=f"saved_search:{row.name}",
                request_id=getattr(request.state, "request_id", "-"))
    db.commit()
    return {"id": row.id, "name": row.name, "kind": row.kind, "params": row.params}


@router.delete("/searches/{search_id}", dependencies=[Depends(require_permission("search:save"))])
def delete_saved(
    search_id: str, request: Request,
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    """Delete one of the caller's saved searches (404 for anyone else's)."""
    row = db.get(SavedSearch, search_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="saved search not found")
    name = row.name
    db.delete(row)
    write_audit(db, user=user, action="search.delete",
                resource=f"saved_search:{name}",
                request_id=getattr(request.state, "request_id", "-"))
    db.commit()
    return {"ok": True}
