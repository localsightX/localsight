"""FastAPI dependencies: DB session, runtime access, auth, RBAC, rate limiting."""
from __future__ import annotations

import datetime as dt

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from apps.api.bootstrap import Runtime
from apps.api.config import Settings
from packages.domain.models import RefreshToken, User
from packages.security.errors import AuthError
from packages.security.jwt import decode_token
from packages.security.ratelimit import RateLimiter

limiter = RateLimiter()


def get_runtime(request: Request) -> Runtime:
    return request.app.state.runtime


def get_settings(request: Request) -> Settings:
    return request.app.state.runtime.settings


def get_db(request: Request) -> Session:
    rt = request.app.state.runtime
    session = rt.SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _bearer(token: str | None) -> str:
    if not token or not token.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    return token.split(" ", 1)[1].strip()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("Authorization")
    token = _bearer(auth)
    rt = request.app.state.runtime
    try:
        claims = decode_token(token, rt.settings.jwt_secret, "access")
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    user = db.get(User, claims["sub"])
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user inactive or unknown")
    # cache permission set on the request for downstream checks
    request.state.permissions = set(claims.get("permissions", []))
    request.state.user = user
    return user


def require_permission(permission: str):
    def checker(request: Request, user: User = Depends(get_current_user)) -> User:
        perms = getattr(request.state, "permissions", set())
        if permission not in perms:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"missing permission: {permission}")
        return user

    return checker


def client_ip(request: Request, *, trust_proxy: bool = False) -> str:
    """Derive the client address for rate limiting and audit records.

    `X-Forwarded-For` is attacker-controlled input unless a trusted proxy
    overwrote/extended it — and even then the FIRST entry is the one the client
    itself sent. The default (trust_proxy=False) therefore keys on the socket
    address only: a spoofed header must never gate a rate limit or forge an
    audit trail. Behind the shipped nginx front (which APPENDS the socket
    address to any incoming header), set TRUST_PROXY_HEADERS=1 to use the LAST
    entry — the one our own proxy added.
    """
    if trust_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        hops = [hop.strip() for hop in fwd.split(",") if hop.strip()]
        if hops:
            return hops[-1]
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, rate: float, capacity: int):
    def checker(request: Request, rt: Runtime = Depends(get_runtime)) -> None:
        ip = client_ip(request, trust_proxy=rt.settings.trust_proxy_headers)
        if not limiter.allow(ip, bucket, rate, capacity):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")

    return checker


def get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


__all__ = [
    "Runtime", "RefreshToken", "dt", "get_current_user", "get_db",
    "get_request_id", "get_runtime", "get_settings", "limiter",
    "rate_limit", "require_permission",
]
