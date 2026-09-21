"""Per-camera behavior-analytics rule management.

Rules are stored as JSON on Camera.rules and consumed by the worker's RuleEngine
(see packages.ai.rules.rule_engine_from_json). Writes pass the rule grammar v1
gate (packages.ai.rulegrammar) first: invalid payloads are rejected with 400 and
field-path errors, so a bad UI payload can never reach the worker. The engine
factory dry-run stays as defense in depth, and the worker still guards on load.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.audit import write_audit
from apps.api.dependencies import get_db, require_permission
from packages.ai.rulegrammar import SCHEMA_VERSION, normalize_rules, validate_rules
from packages.ai.rules import rule_from_dict
from packages.domain.models import Camera

router = APIRouter(prefix="/api", tags=["rules"])


class RulesBody(BaseModel):
    rules: list[dict]


@router.get(
    "/cameras/{camera_id}/rules",
    dependencies=[Depends(require_permission("rules:configure"))],
)
def get_rules(camera_id: str, db: Session = Depends(get_db)):
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    return {"camera_id": camera_id, "rules": cam.rules or []}


@router.put(
    "/cameras/{camera_id}/rules",
    dependencies=[Depends(require_permission("rules:configure"))],
)
def put_rules(camera_id: str, body: RulesBody, request: Request, db: Session = Depends(get_db)):
    cam = db.get(Camera, camera_id)
    if not cam:
        raise HTTPException(status_code=404, detail="camera not found")
    # Grammar v1 gate: reject with 400 + field-path errors before anything is
    # persisted (schema_version rides along so clients can feature-detect).
    errors = validate_rules(body.rules)
    if errors:
        raise HTTPException(status_code=400, detail={
            "message": "invalid rules payload",
            "schema_version": SCHEMA_VERSION,
            "errors": errors,
        })
    # Defense in depth: the engine-factory dry run (also catches drift between
    # the grammar and the dataclasses the worker actually consumes).
    for spec in body.rules:
        try:
            rule_from_dict(camera_id, spec)  # raises on bad spec
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid rule: {exc}") from exc
    # Persist the type-coerced payload so GET round-trips stably and the worker
    # never sees mixed int/float geometry.
    cam.rules = normalize_rules(body.rules)
    write_audit(db, user=request.state.user, action="camera.rules.update", resource=camera_id,
                request_id=getattr(request.state, "request_id", "-"),
                detail={"count": len(body.rules), "schema_version": SCHEMA_VERSION})
    db.commit()
    return {"camera_id": camera_id, "rules": cam.rules}
