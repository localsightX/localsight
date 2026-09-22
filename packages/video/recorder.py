"""Main-stream recorder.

Per the architecture, the *main* stream is recorded while the *substream* drives
AI. This module records the main stream into short, seekable, time-aligned segments
(HLS-ready .mp4) under the StorageProvider and writes a VideoSegment row per
segment so the archive is queryable and retention-enforceable.

FFmpeg is launched as a confined subprocess (no shell, validated URL — reuses the
SSRF guard via `validate_egress_url`, which also honors the deploy-time allowlist so
private-VLAN camera URLs are accepted). Segment scheduling is pure and unit-tested;
only the subprocess spawn is environment-dependent and is injectable for tests.

Memory note: completed segments move to storage via `StorageProvider.put_stream`,
which never buffers the payload in the process heap — a 4 Mbps main stream fills a
300 s segment with ~150 MB, and a high-bitrate NVR can exceed 1 GB, so this path
must stay streaming.
"""
from __future__ import annotations

import datetime as dt
import os
import subprocess
import tempfile
import time as _time
from typing import Callable, Optional

from packages.domain.models import VideoSegment
from packages.security.errors import SecurityError
from packages.security.ssrf import validate_egress_url
from packages.video.ffmpeg import build_args  # reuse safe argv builder


def segment_boundary(ts: dt.datetime, seg_seconds: int) -> dt.datetime:
    """Start time of the segment bucket containing `ts` (UTC, floor to seg)."""
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    delta = (ts - epoch).total_seconds()
    aligned = int(delta // seg_seconds) * seg_seconds
    return epoch + dt.timedelta(seconds=aligned)


def segment_key(camera_id: str, start: dt.datetime, ext: str = "mp4", seg_seconds: int = 300) -> str:
    """Deterministic storage key: camera/<id>/<YYYY>/<MM>/<DD>/<HHMMSS>.{ext}.

    Aligned to the segment boundary so the key is stable for the whole window.
    """
    b = segment_boundary(start, seg_seconds)
    return (
        f"camera/{camera_id}/{b.year:04d}/{b.month:02d}/{b.day:02d}/"
        f"{b.hour:02d}{b.minute:02d}{b.second:02d}.{ext}"
    )


class Recorder:
    def __init__(
        self,
        camera_id: str,
        storage,
        crypto=None,
        seg_seconds: int = 300,
        spawn: Callable[..., subprocess.Popen] | None = None,
        on_segment: Callable[[VideoSegment], None] | None = None,
        allowlist: list[str] | None = None,
        tmp_root: str | None = None,
    ) -> None:
        self.camera_id = camera_id
        self.storage = storage
        self.crypto = crypto
        self.seg_seconds = seg_seconds
        self._spawn = spawn or subprocess.Popen
        self._on_segment = on_segment
        self._allowlist = allowlist
        # Private scratch dir (0700) instead of a predictable /tmp path: brief
        # plaintext media on a shared host must not be world-readable, and a
        # fixed name is a symlink hazard on multi-process hosts.
        self._tmp_root = tmp_root or os.path.join(
            tempfile.gettempdir(), f"localsight-rec-{camera_id}"
        )
        os.makedirs(self._tmp_root, mode=0o700, exist_ok=True)
        self._procs: dict[str, subprocess.Popen] = {}
        self._pending: dict[str, VideoSegment] = {}
        self._last_proc: Optional[subprocess.Popen] = None
        self._last_seg: Optional[VideoSegment] = None

    def _tmp_path(self, start: dt.datetime) -> str:
        return os.path.join(
            self._tmp_root, f"seg_{self.camera_id}_{start.timestamp()}.mp4"
        )

    def _build_args(self, url: str, start: dt.datetime) -> list[str]:
        tmp = self._tmp_path(start)
        return [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
            "-rtsp_transport", "tcp", "-i", url,
            "-y", "-t", str(self.seg_seconds),
            "-an", "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
            "-f", "mp4", tmp,
        ]

    def record_url(self, url: str, start: dt.datetime) -> VideoSegment:
        """Spawn a recorder for one segment and return the (unsaved) VideoSegment row.

        The caller is responsible for waiting on `last_proc` and then calling
        `finalize_last` to upload the completed clip and persist the row (this keeps
        the interface test-friendly and lets the worker run a continuous loop).
        """
        validate_egress_url(
            url, allowed_schemes={"rtsp", "rtsps", "http", "https"},
            allowlist=self._allowlist,
        )
        seg_start = segment_boundary(start, self.seg_seconds)
        # The key must align to the SAME boundary the segment is cut on. Passing
        # seg_seconds matters whenever it is not the 300 s default: the rig cuts
        # 30 s segments, and with the default bucket every segment inside a
        # 5-minute window shared one key, so each finalize overwrote the
        # previous clip on disk while its VideoSegment row kept pointing at the
        # (now foreign) file — playback served the wrong 30 s for 9 of 10
        # segments and size_bytes stopped matching the bytes on disk.
        key = segment_key(self.camera_id, seg_start, seg_seconds=self.seg_seconds)
        args = self._build_args(url, seg_start)
        try:
            proc = self._spawn(args)
        except (OSError, ValueError) as exc:
            raise SecurityError(f"failed to launch recorder: {exc}") from exc
        seg = VideoSegment(
            camera_id=self.camera_id,
            storage_key=key,
            storage_backend=getattr(self.storage, "backend_name", "local"),
            start_ts=seg_start,
            end_ts=seg_start + dt.timedelta(seconds=self.seg_seconds),
            duration_sec=float(self.seg_seconds),
            size_bytes=0,
        )
        self._procs[key] = proc
        self._pending[key] = seg
        self._last_proc = proc
        self._last_seg = seg
        return seg

    @property
    def last_proc(self) -> Optional[subprocess.Popen]:
        """The ffmpeg process spawned by the most recent `record_url` call.

        Part of the documented caller contract ("wait on last_proc, then
        finalize_last") — the worker's record loop uses it, so it must be a
        public attribute, not an internal one.
        """
        return self._last_proc

    @property
    def last_seg(self) -> Optional[VideoSegment]:
        return self._last_seg

    def _actual_duration(self, path: str) -> Optional[float]:
        """Probe the real duration of a finished segment via ffprobe.

        `record_url` pre-fills `duration_sec`/`end_ts` from the schedule; if the
        stream dropped at t=80 s the file is 80 s long, and trusting the schedule
        would mis-align every timeline render and clip window computed from it.
        """
        try:
            out = subprocess.run(
                ["ffprobe", "-hide_banner", "-v", "error",
                 "-show_entries", "format=duration", "-of", "csv=p=0", path],
                capture_output=True, timeout=30, check=True,
            )
            return float(out.stdout.strip())
        except Exception:  # noqa: BLE001 - metadata is best-effort
            return None

    def finalize_last(self) -> Optional[VideoSegment]:
        """Wait for the most recent segment's ffmpeg process to finish, move the
        clip to storage via the streaming path (no heap buffering), correct the
        row's duration from the actual file, and return it. Returns None if the
        segment failed or is missing.
        """
        seg = self._last_seg
        proc = self._last_proc
        if seg is None or proc is None:
            return None
        self._last_proc = None
        self._last_seg = None
        self._pending.pop(seg.storage_key, None)
        self._procs.pop(seg.storage_key, None)
        if proc.poll() is None:
            try:
                proc.wait()
            except Exception:  # noqa: BLE001 - best-effort wait
                pass
        if proc.returncode not in (0, None):
            return None
        tmp = self._tmp_path(seg.start_ts)
        try:
            if not os.path.isfile(tmp) or os.path.getsize(tmp) == 0:
                return None
            # Reconcile scheduled vs. actual duration (stream may have dropped
            # early) so timelines and clip windows stay truthful.
            actual = self._actual_duration(tmp)
            if actual is not None and actual > 0:
                seg.duration_sec = actual
                seg.end_ts = seg.start_ts + dt.timedelta(seconds=actual)
            if self.storage is not None:
                # Streaming move: ffmpeg already wrote the bytes; uploading via
                # put_stream avoids reading a potentially >1 GB file into RAM.
                seg.size_bytes = self.storage.put_stream(
                    seg.storage_key, tmp, "video/mp4"
                )
            else:
                seg.size_bytes = os.path.getsize(tmp)
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        except OSError:
            return None
        if self._on_segment:
            self._on_segment(seg)
        return seg

    def stop_all(self) -> None:
        """Terminate all in-flight segments and reap their processes.

        Snapshot the dicts first: the record thread's finalize_last pops from
        _procs concurrently, and iterating a dict while another thread mutates
        it raises "dictionary keys changed during iteration" — which crashes
        the camera thread during shutdown (observed live: worker teardown
        after a camera went unreachable).
        """
        procs = list(self._procs.values())
        for p in procs:
            if p.poll() is None:
                try:
                    p.terminate()
                except OSError:  # noqa: BLE001 - process may have exited
                    pass
        # Reap so terminated ffmpeg children don't linger as zombies.
        deadline = _time.monotonic() + 5.0
        for p in procs:
            try:
                p.wait(timeout=max(0.1, deadline - _time.monotonic()))
            except Exception:  # noqa: BLE001 - best-effort reap
                try:
                    p.kill()
                except OSError:
                    pass
        self._procs.clear()
        self._pending.clear()
