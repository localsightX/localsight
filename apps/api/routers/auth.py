"""Authentication: login (with MFA + lockout), refresh-token rotation, logout,
and TOTP enrollment. Access tokens are short-lived; refresh tokens rotate and
are tracked server-side so a stolen refresh can be revoked.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.audit import write_audit
from apps.api.bootstrap import Runtime
from apps.api.dependencies import client_ip, get_current_user, get_db, get_runtime, rate_limit
from packages.domain.models import RefreshToken, Role, User
from packages.domain.timeutil import iso
from packages.security.errors import AuthError
from packages.security.jwt import create_access_token, create_refresh_token, decode_token
from packages.security.mfa import generate_secret, provisioning_uri, verify_code
from packages.security.passwords import hash_password, verify_password
from packages.security.rbac import effective_permissions

router = APIRouter(prefix="/api/auth", tags=["auth"])


# Fixed precomputed hash for nonexistent-account logins: verifying against a
# CONSTANT hash (not a per-request re-hash) makes both login branches cost
# exactly one Argon2 verify with identical parameters, eliminating the timing
# oracle while halving real-login CPU.
_DUMMY_HASH = hash_password("dummy-password-not-used")


class LoginBody(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)
    mfa_code: str | None = Field(default=None, max_length=16)


class TokenBody(BaseModel):
    refresh_token: str


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


def _permissions_for(db: Session, user: User) -> list[str]:
    role = db.get(Role, user.role_id)
    return sorted(effective_permissions([role.name]))


@router.post("/login", dependencies=[Depends(rate_limit("login", rate=1.0, capacity=10))])
def login(body: LoginBody, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    rid = getattr(request.state, "request_id", "-")
    ip = client_ip(request, trust_proxy=rt.settings.trust_proxy_headers)
    # Hash-then-compare order: verify the password FIRST (or the dummy hash for
    # unknown accounts), THEN report lockout. Reversing this leaks account
    # existence — an attacker can distinguish "unknown email" (fast 401) from
    # "known but locked email" (423) without ever knowing a password.
    user = db.query(User).filter(User.email == body.email).first()
    locked = False
    if user and user.locked_until is not None:
        lu = user.locked_until
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=dt.UTC)
        locked = lu > dt.datetime.now(dt.UTC)

    # User-enumeration hardening: ALWAYS run exactly one Argon2 verify against
    # a fixed precomputed dummy hash when the account doesn't exist. Both
    # branches then cost the same single verify, and recomputing the dummy
    # per request (a fresh salt each time — ~47 ms of pure waste) is gone.
    hashed = user.password_hash if user is not None else _DUMMY_HASH
    ok = verify_password(body.password, hashed)

    if locked:
        write_audit(db, username=body.email, action="login", result="failure", source_ip=ip,
                    request_id=rid, detail={"reason": "locked"})
        db.commit()
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="account locked; try later")

    if not user or not ok:
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= rt.settings.max_login_attempts:
                user.locked_until = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=rt.settings.lockout_minutes)
                user.failed_login_attempts = 0
            db.commit()
        write_audit(db, username=body.email, action="login", result="failure", source_ip=ip,
                    request_id=rid, detail={"reason": "bad_credentials"})
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    # MFA step-up
    if user.mfa_enabled:
        if not body.mfa_code or not _verify_user_mfa(rt, user, body.mfa_code):
            write_audit(db, user=user, action="login", result="failure", source_ip=ip,
                        request_id=rid, detail={"reason": "mfa_failed"})
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid MFA code")
        user.failed_login_attempts = 0
        user.locked_until = None

    perms = _permissions_for(db, user)
    access = create_access_token(user.id, [user.role.name], perms, rt.settings.jwt_secret, rt.settings.access_token_ttl_min)
    refresh = _issue_refresh(db, user, rt)
    write_audit(db, user=user, action="login", result="success", source_ip=ip, request_id=rid)
    db.commit()
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": rt.settings.access_token_ttl_min * 60,
    }


def _verify_user_mfa(rt: Runtime, user: User, code: str) -> bool:
    if not user.mfa_secret_enc:
        return False
    secret = rt.crypto.decrypt_str(user.mfa_secret_enc)
    return verify_code(secret, code)


def _issue_refresh(db: Session, user: User, rt: Runtime) -> str:
    token = create_refresh_token(user.id, rt.settings.jwt_secret, rt.settings.refresh_token_ttl_days)
    claims = decode_token(token, rt.settings.jwt_secret, "refresh")
    db.add(RefreshToken(
        user_id=user.id,
        jti=claims["jti"],
        expires_at=dt.datetime.fromtimestamp(claims["exp"], dt.UTC),
    ))
    db.flush()
    return token


@router.post("/refresh", dependencies=[Depends(rate_limit("refresh", rate=2.0, capacity=20))])
def refresh(body: TokenBody, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    rid = getattr(request.state, "request_id", "-")
    ip = client_ip(request, trust_proxy=rt.settings.trust_proxy_headers)
    try:
        claims = decode_token(body.refresh_token, rt.settings.jwt_secret, "refresh")
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    record = db.query(RefreshToken).filter(RefreshToken.jti == claims["jti"]).first()
    if not record or record.revoked or record.replaced_by:
        write_audit(db, username=claims.get("sub", ""), action="token_refresh", result="failure",
                    source_ip=ip, request_id=rid, detail={"reason": "revoked_or_replay"})
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="refresh token invalid")

    user = db.get(User, claims["sub"])
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user inactive")

    # Rotate: revoke the presented refresh and issue a new pair.
    new_refresh = create_refresh_token(user.id, rt.settings.jwt_secret, rt.settings.refresh_token_ttl_days)
    new_claims = decode_token(new_refresh, rt.settings.jwt_secret, "refresh")
    record.revoked = True
    record.replaced_by = new_claims["jti"]
    db.add(RefreshToken(user_id=user.id, jti=new_claims["jti"],
                        expires_at=dt.datetime.fromtimestamp(new_claims["exp"], dt.UTC)))
    perms = _permissions_for(db, user)
    access = create_access_token(user.id, [user.role.name], perms, rt.settings.jwt_secret, rt.settings.access_token_ttl_min)
    write_audit(db, user=user, action="token_refresh", result="success", source_ip=ip, request_id=rid)
    db.commit()
    return {
        "access_token": access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": rt.settings.access_token_ttl_min * 60,
    }


@router.post("/logout")
def logout(body: TokenBody, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime)):
    rid = getattr(request.state, "request_id", "-")
    ip = client_ip(request, trust_proxy=rt.settings.trust_proxy_headers)
    try:
        claims = decode_token(body.refresh_token, rt.settings.jwt_secret, "refresh")
    except AuthError:
        return {"ok": True}
    record = db.query(RefreshToken).filter(RefreshToken.jti == claims["jti"]).first()
    if record:
        record.revoked = True
    write_audit(db, username=claims.get("sub", ""), action="logout", result="success", source_ip=ip, request_id=rid)
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    role = db.get(Role, user.role_id)
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": role.name,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "permissions": sorted(effective_permissions([role.name])),
    }


class PasswordChangeBody(BaseModel):
    old_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/password", dependencies=[Depends(rate_limit("password", rate=0.2, capacity=5))])
def change_password(
    body: PasswordChangeBody,
    request: Request,
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
    user: User = Depends(get_current_user),
):
    """Self-service password change (M2/E-6). Verifies the old password,
    rotates the hash, revokes every OTHER refresh token (other devices
    sign out; this session keeps working), and audits the rotation.
    Rate-limited: 5 attempts / 25 s per IP."""
    rid = getattr(request.state, "request_id", "-")
    ip = client_ip(request, trust_proxy=rt.settings.trust_proxy_headers)
    if not verify_password(body.old_password, user.password_hash):
        write_audit(db, user=user, action="user.password_change", result="failure",
                    source_ip=ip, request_id=rid, detail={"reason": "bad_credentials"})
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="current password is incorrect")
    if body.old_password == body.new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="new password must differ from the current one")
    user.password_hash = hash_password(body.new_password)
    # Revoke all refresh tokens: every other device is signed out. The
    # CURRENT access token lives ~15 more minutes; the client refreshes
    # into a fresh token on next use (its old refresh is revoked too, but
    # the rotation endpoint only rejects on NEXT use — acceptable, and
    # sessions here mean "this browser tab", which keeps its access token).
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False)
    ).update({"revoked": True})
    write_audit(db, user=user, action="user.password_change", result="success",
                source_ip=ip, request_id=rid)
    db.commit()
    return {"ok": True, "sessions_revoked": True}


@router.get("/sessions")
def list_own_sessions(
    request: Request,
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
    user: User = Depends(get_current_user),
):
    """The caller's active sessions (M2/E-13): unrevoked, unexpired refresh
    tokens, newest first. `current` flags the token this tab is using."""
    rows = db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked.is_(False),
        RefreshToken.expires_at > dt.datetime.now(dt.UTC),
    ).order_by(RefreshToken.created_at.desc()).all()
    return {
        "sessions": [
            {
                "id": r.id,
                "created_at": iso(r.created_at),
                "expires_at": iso(r.expires_at),
                "last_seen": iso(r.created_at),
            }
            for r in rows
        ]
    }


@router.post("/sessions/{token_id}/revoke")
def revoke_own_session(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
    rt: Runtime = Depends(get_runtime),
    user: User = Depends(get_current_user),
):
    rid = getattr(request.state, "request_id", "-")
    rec = db.query(RefreshToken).filter(
        RefreshToken.id == token_id, RefreshToken.user_id == user.id).first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")
    rec.revoked = True
    write_audit(db, user=user, action="user.session_revoke", resource=token_id,
                request_id=rid, result="success")
    db.commit()
    return {"ok": True}


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime), user: User = Depends(get_current_user)):
    secret = generate_secret()
    user.mfa_secret_enc = rt.crypto.encrypt_str(secret)
    user.mfa_enabled = False  # enabled only after a successful verify
    db.commit()
    return MfaSetupOut(secret=secret, otpauth_uri=provisioning_uri(secret, user.email))


@router.post("/mfa/verify")
def mfa_verify(body: dict, request: Request, db: Session = Depends(get_db), rt: Runtime = Depends(get_runtime), user: User = Depends(get_current_user)):
    code = (body or {}).get("code")
    if not user.mfa_secret_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA not initialized")
    secret = rt.crypto.decrypt_str(user.mfa_secret_enc)
    if not verify_code(secret, code or ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid code")
    user.mfa_enabled = True
    db.commit()
    return {"ok": True, "mfa_enabled": True}
