"""Local-filesystem storage with strict path-traversal protection and signed,
expiring download URLs (no permanently public links).

Keys are treated as opaque, slash-separated identifiers. Every key is validated
so it can never escape `root`, defending against `../../etc/passwd` style attacks
even if a key originates from user input.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import time
import urllib.parse
from collections.abc import Iterator

from packages.storage.base import StorageProvider


class LocalFilesystemStorage(StorageProvider):
    def __init__(self, root: str, signing_secret: str) -> None:
        self._root = os.path.abspath(root)
        os.makedirs(self._root, exist_ok=True)
        self._secret = signing_secret.encode()

    @property
    def local_volume_path(self) -> str | None:
        """The recordings volume the worker's disk-pressure monitor samples.

        Local storage *is* the media volume, so this is exactly the disk whose
        exhaustion loses evidence (reliability plan F3).
        """
        return self._root

    # ── safety ────────────────────────────────────────────────────────────
    def _resolve(self, key: str) -> str:
        if not key or key.startswith("/") or ".." in key.split("/"):
            raise ValueError("invalid storage key")
        # We avoid os.path.join's absolute-path override and normalize manually.
        rel = os.path.normpath(key)
        if rel != key or rel.startswith(".."):
            raise ValueError("invalid storage key (path traversal)")
        full = os.path.abspath(os.path.join(self._root, rel))
        if not full.startswith(self._root + os.sep) and full != self._root:
            raise ValueError("key escapes storage root")
        return full

    # ── object ops ───────────────────────────────────────────────────────
    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        path = self._resolve(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + f".tmp.{os.getpid()}"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)  # atomic

    def put_stream(self, key: str, source_path: str, content_type: str = "application/octet-stream") -> int:
        """Move `source_path` into storage without buffering it in memory.

        Large recordings land here: the recorder's ffmpeg output is moved with
        a same-filesystem rename when possible (zero-copy) or a chunked copy
        across filesystems. Either way the payload never enters the heap.
        """
        path = self._resolve(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        size = os.path.getsize(source_path)
        tmp = path + f".tmp.{os.getpid()}"
        try:
            os.replace(source_path, tmp)
        except OSError:
            # Cross-device (e.g. /tmp tmpfs -> storage volume): chunked copy.
            shutil.copyfile(source_path, tmp)
            os.remove(source_path)
        os.replace(tmp, path)  # atomic publish
        return size

    def get(self, key: str) -> bytes:
        with open(self._resolve(key), "rb") as fh:
            return fh.read()

    def size(self, key: str) -> int:
        return os.path.getsize(self._resolve(key))

    def read_range(self, key: str, start: int, end: int) -> Iterator[bytes]:
        """Yield bytes[start:end+1] via seek (64 KiB chunks, O(1) memory).

        The media endpoint serves multi-hundred-MB recordings through here, so
        the file is never buffered whole — a full-segment GET streams from disk
        in chunks, and a Range GET seeks straight to the requested window.
        """
        path = self._resolve(key)  # same traversal gate as get()
        size = os.path.getsize(path)
        start = max(0, start)
        end = min(end, size - 1)
        if start > end:
            return
        with open(path, "rb") as fh:
            fh.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                chunk = fh.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    def delete(self, key: str) -> None:
        try:
            os.remove(self._resolve(key))
        except FileNotFoundError:
            pass

    def exists(self, key: str) -> bool:
        try:
            return os.path.isfile(self._resolve(key))
        except ValueError:
            return False

    # ── signed URLs ───────────────────────────────────────────────────────
    def _sig(self, key: str, exp: int) -> str:
        mac = hmac.new(self._secret, f"{key}:{exp}".encode(), hashlib.sha256)
        return mac.hexdigest()

    def sign_get_url(self, key: str, expires_sec: int = 300) -> str:
        # Cap the TTL: a signed URL is a bearer credential for the object, so an
        # unbounded expiry is a permanent public link in disguise. The narrowest
        # window callers need is the DVR scrubber (~1 h), hence the ceiling.
        expires_sec = max(1, min(expires_sec, 3600))
        exp = int(time.time()) + expires_sec
        sig = self._sig(key, exp)
        return f"/api/video/{urllib.parse.quote(key, safe='')}?exp={exp}&sig={sig}"

    def verify_signed_url(self, key: str, exp: str, sig: str) -> bool:
        try:
            exp_i = int(exp)
        except ValueError:
            return False
        now = int(time.time())
        # Skew + cap: reject expired links, but also links whose expiry lies
        # beyond the signing ceiling — a leaked signer must not be able to mint
        # effectively-permanent bearer URLs by stuffing a far-future `exp`.
        if exp_i < now or exp_i > now + 3600 + 60:
            return False
        expected = self._sig(key, exp_i)
        return hmac.compare_digest(expected, sig or "")
