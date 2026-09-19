"""Envelope encryption at rest.

Threat model: a database dump or a stolen disk must not reveal face embeddings,
snapshots, or sensitive configuration. We therefore encrypt those blobs before
they leave the application. Keys are kept separate from the data (the KEK is
supplied via environment / secrets manager, never the DB).

Envelope scheme (per record):
  * Generate a fresh random *data key* for each encrypt() call.
  * Encrypt the plaintext with Fernet(data_key)  -> ciphertext.
  * Wrap the data key with Fernet(KEK)            -> wrapped_key.
  * Store { wrapped_key, ciphertext } (base64).

Decrypting requires the KEK to unwrap the data key. Key rotation is supported
by re-wrapping with a new KEK without re-encrypting bulk data.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.fernet import Fernet, InvalidToken

from packages.security.errors import CryptoError


class CryptoBox:
    def __init__(self, master_key: str):
        if not master_key:
            raise CryptoError("MASTER_ENCRYPTION_KEY is required and was empty")
        self._key = master_key  # raw key retained for keyed hashes (HMAC below)
        try:
            self._kek = Fernet(master_key.encode() if isinstance(master_key, str) else master_key)
        except Exception as exc:  # surface as our error
            raise CryptoError(f"invalid master key: {exc}") from exc

    def hmac_str(self, text: str) -> str:
        """Keyed HMAC-SHA256 (hex, first 32 chars) over `text`.

        Deterministic equality-search token for low-entropy identifiers
        (license plates): a bare SHA-256 over a plate's tiny keyspace is
        brute-forceable offline, so the searchable form MUST be key-bound.
        Same master key ⇒ same token; rotating the key invalidates existing
        plate-hash indexes by design (treat as a re-index event).
        """
        import hashlib
        import hmac as _hmac

        return _hmac.new(
            self._key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256,
        ).hexdigest()[:32]

    # ── low-level envelope ────────────────────────────────────────────────
    def _seal(self, plaintext: bytes) -> dict:
        data_key = Fernet.generate_key()
        ct = Fernet(data_key).encrypt(plaintext)
        wrapped = self._kek.encrypt(data_key)
        return {"k": wrapped.decode(), "c": ct.decode()}

    def _open(self, envelope: dict) -> bytes:
        try:
            wrapped = envelope["k"].encode()
            ct = envelope["c"].encode()
            data_key = self._kek.decrypt(wrapped)
            return Fernet(data_key).decrypt(ct)
        except (KeyError, InvalidToken, TypeError) as exc:
            raise CryptoError("failed to decrypt envelope") from exc

    # ── public API ────────────────────────────────────────────────────────
    def encrypt_bytes(self, data: bytes) -> str:
        return base64.b64encode(json.dumps(self._seal(data)).encode()).decode()

    def decrypt_bytes(self, token: str) -> bytes:
        try:
            envelope = json.loads(base64.b64decode(token))
        except Exception as exc:
            raise CryptoError("malformed ciphertext token") from exc
        return self._open(envelope)

    def encrypt_str(self, text: str) -> str:
        return self.encrypt_bytes(text.encode("utf-8"))

    def decrypt_str(self, token: str) -> str:
        return self.decrypt_bytes(token).decode("utf-8")

    def encrypt_json(self, obj) -> str:
        return self.encrypt_str(json.dumps(obj, separators=(",", ":")))

    def decrypt_json(self, token: str):
        return json.loads(self.decrypt_str(token))


def generate_key() -> str:
    """Helper to mint a new base64 Fernet key (for KEK or data keys)."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()
