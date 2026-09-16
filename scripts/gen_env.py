#!/usr/bin/env python3
"""Generate a local `.env` from `.env.example` with cryptographically random
secrets. Run once before starting the stack:

    python scripts/gen_env.py

This NEVER writes secrets to git (`.env` is git-ignored). For production, supply
your own values (Vault / Docker secrets) and do not reuse generated keys.
"""
from __future__ import annotations

import base64
import os
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, ".env.example")
OUT = os.path.join(ROOT, ".env")


def _key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def main() -> int:
    if not os.path.exists(EXAMPLE):
        print("missing .env.example", file=sys.stderr)
        return 1
    if os.path.exists(OUT):
        print(f"{OUT} already exists; refusing to overwrite. Delete it first if intended.", file=sys.stderr)
        return 1

    jwt = _key()
    mek = _key()
    admin_pw = secrets.token_urlsafe(24)
    lines = []
    with open(EXAMPLE) as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("JWT_SECRET="):
                line = f"JWT_SECRET={jwt}"
            elif line.startswith("MASTER_ENCRYPTION_KEY="):
                line = f"MASTER_ENCRYPTION_KEY={mek}"
            elif line.startswith("BOOTSTRAP_ADMIN_PASSWORD="):
                line = f"BOOTSTRAP_ADMIN_PASSWORD={admin_pw}"
            lines.append(line)
    with open(OUT, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {OUT} with fresh random secrets.")
    print("Review retention/URLs before deploying. The bootstrap admin password")
    print("was minted randomly — record it now; it cannot be recovered:")
    print(f"  BOOTSTRAP_ADMIN_PASSWORD={admin_pw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
