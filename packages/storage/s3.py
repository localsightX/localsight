"""S3-compatible storage (optional). Imported lazily so the package has no
hard boto3 dependency for local/SQLite deployments.

Media delivery follows the same contract as the local backend: `sign_get_url`
returns an *application-relative* `/api/video/...` path authorized by the
deployment-wide HMAC scheme, and the app streams bytes from S3 server-side.
No external S3 URL is ever exposed to the browser — critical for on-prem
deployments where the bucket is intentionally unreachable from client networks
and the product's "video never leaves the site" promise.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import urllib.parse
from collections.abc import Iterator

from packages.storage.base import StorageProvider


class S3CompatibleStorage(StorageProvider):
    def __init__(
        self,
        bucket: str,
        endpoint_url: str | None,
        region: str,
        prefix: str,
        signing_secret: str,
    ) -> None:
        try:
            import boto3  # noqa: F401 - lazy
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "boto3 is required for S3CompatibleStorage; install it or use STORAGE_BACKEND=local"
            ) from exc
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._client = boto3.client(
            "s3", endpoint_url=endpoint_url, region_name=region
        )
        self._secret = signing_secret.encode()

    def _full_key(self, key: str) -> str:
        return f"{self._prefix}/{key}" if self._prefix else key

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self._client.put_object(Bucket=self._bucket, Key=self._full_key(key), Body=data, ContentType=content_type)

    def put_stream(self, key: str, source_path: str, content_type: str = "application/octet-stream") -> int:
        """Upload a file via multipart — the payload never enters the heap.

        boto3's `upload_file` streams from disk in configurable chunks and
        handles multipart assembly, which `put_object` with an in-memory body
        cannot do for multi-hundred-MB recordings.
        """
        size = os.path.getsize(source_path)
        self._client.upload_file(
            source_path, self._bucket, self._full_key(key),
            ExtraArgs={"ContentType": content_type},
        )
        return size

    def get(self, key: str) -> bytes:
        from botocore.exceptions import ClientError

        try:
            obj = self._client.get_object(Bucket=self._bucket, Key=self._full_key(key))
            return obj["Body"].read()
        except ClientError as exc:  # pragma: no cover
            raise FileNotFoundError(key) from exc

    def size(self, key: str) -> int:
        from botocore.exceptions import ClientError

        try:
            head = self._client.head_object(Bucket=self._bucket, Key=self._full_key(key))
            return int(head["ContentLength"])
        except ClientError as exc:  # pragma: no cover
            raise FileNotFoundError(key) from exc

    def read_range(self, key: str, start: int, end: int) -> Iterator[bytes]:
        """Range GET against S3 (server-side slice, streamed in 64 KiB chunks)."""
        from botocore.exceptions import ClientError

        try:
            obj = self._client.get_object(
                Bucket=self._bucket, Key=self._full_key(key),
                Range=f"bytes={max(0, start)}-{max(0, end)}",
            )
            body = obj["Body"]
            while True:
                chunk = body.read(65536)
                if not chunk:
                    break
                yield chunk
        except ClientError as exc:  # pragma: no cover
            raise FileNotFoundError(key) from exc

    def delete(self, key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=self._full_key(key))

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self._bucket, Key=self._full_key(key))
            return True
        except ClientError:  # pragma: no cover
            return False

    # ── signed URLs (shared HMAC scheme; identical contract to local) ──────
    def _sig(self, key: str, exp: int) -> str:
        mac = hmac.new(self._secret, f"{key}:{exp}".encode(), hashlib.sha256)
        return mac.hexdigest()

    def sign_get_url(self, key: str, expires_sec: int = 300) -> str:
        # App-relative path — the app proxies S3 bytes on verify; the bucket
        # endpoint is never disclosed to the client. TTL capped like the local
        # backend: a signed URL is a bearer credential, not a public link.
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
        # Same skew + cap contract as the local backend (see comment there).
        if exp_i < now or exp_i > now + 3600 + 60:
            return False
        expected = self._sig(key, exp_i)
        return hmac.compare_digest(expected, sig or "")
