"""LocalSight API application factory.

Builds the runtime (engine, crypto, storage, model registry) once at startup,
wires security middleware (request IDs, CORS, hardened headers), mounts all
routers, and registers error handlers. The AI/video worker is a separate process
(see apps/worker) that shares the same database and storage.
"""
from __future__ import annotations

import datetime as dt
import os
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from apps.api.bootstrap import build
from apps.api.config import Settings
from apps.api.dependencies import get_runtime
from apps.api import domain_live_cfg
from apps.api.routers import (
    audit,
    auth,
    cameras,
    events,
    persons,
    system,
    timeline,
    users,
    video,
    alerts,
    analytics,
    live,
    rules,
)
from packages.observability.logging import configure_logging
from packages.security.headers import SecurityHeadersMiddleware


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        request.state.permissions = set()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Local-first video intelligence platform (local AI, privacy by design).",
    )

    # Build runtime (raises if secrets are insecure).
    rt = build(settings)
    app.state.runtime = rt

    # Middleware order: outermost first. RequestId innermost-of-these so others
    # can read state; CORS outermost; security headers wrap responses.
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=settings.is_production)
    # CORS + credentials: allow_credentials=True with a wildcard origin echoes
    # ANY origin back with Access-Control-Allow-Credentials, so a phishing page
    # can drive the API with the victim's cookies/tokens. Forbid that combo at
    # startup — origins must be enumerated whenever credentials are allowed.
    _origins = settings.cors_origins
    if "*" in _origins:
        raise RuntimeError(
            "CORS_ALLOW_ORIGINS must enumerate explicit origins "
            f"(got {_origins}); the wildcard is not permitted with credentials."
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(RequestIdMiddleware)

    # Routers
    app.include_router(auth.router)
    app.include_router(cameras.router)
    app.include_router(persons.router)
    app.include_router(events.router)
    app.include_router(timeline.router)
    app.include_router(audit.router)
    app.include_router(users.router)
    app.include_router(video.router)
    app.include_router(system.router)
    app.include_router(alerts.router)
    app.include_router(analytics.router)
    app.include_router(live.router)
    app.include_router(rules.router)

    # Serve transcoded live HLS segments (written by the live gateway in live.py).
    # LIVE_DIR is the single shared source of truth for both the transcode root
    # and this mount — LOCALSIGHT_LIVE_DIR overrides both together.
    os.makedirs(domain_live_cfg.LIVE_DIR, exist_ok=True)
    app.mount("/live-media", StaticFiles(directory=domain_live_cfg.LIVE_DIR), name="live-media")

    # Serve the static dashboard (mounted last so /api and /health win).
    ui_dir = os.path.join(os.path.dirname(__file__), "..", "..", "ui")
    if os.path.isdir(ui_dir):
        app.mount("/", StaticFiles(directory=ui_dir, html=True), name="ui")

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        from packages.observability.logging import logging

        logging.getLogger("localsight").exception("unhandled error", extra={"request_id": getattr(request.state, "request_id", "-")})
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    @app.on_event("shutdown")
    async def _stop_live_transcodes() -> None:
        # Live ffmpeg transcodes are owned by this process; reap them on
        # shutdown so they never orphan across restarts.
        from apps.api.routers.live import shutdown_live_streams

        shutdown_live_streams()

    return app


app = create_app()
