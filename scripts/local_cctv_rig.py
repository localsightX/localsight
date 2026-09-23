#!/usr/bin/env python3
"""Local CCTV rig for LocalSight — turn a MacBook into a one-camera NVR site.

DEV-ONLY convenience script. Brings up, on a single laptop:

    FaceTime HD (or synthetic test pattern)
        └─ ffmpeg (capture, split into two encodes)
             ├─ rtsp://127.0.0.1:8554/cctv_main (1280x720, recorded by the NVR)
             └─ rtsp://127.0.0.1:8554/cctv_sub  (640x360,  feeds the AI pipeline)
    mediamtx (local RTSP broker, loopback only)
        └─ LocalSight API (uvicorn) + AI/video worker
             ├─ main stream → segmented MP4 recordings (30 s segments)
             ├─ sub stream  → detection → events → (optional) alerts
             └─ live view    → LL-HLS at /live-media

Everything is standard-library only (no pip deps) and process-managed via
PID files under .rig/ — `stop` tears the whole tree down without orphans.

Commands:
    setup    one-time: brew install ffmpeg+mediamtx (skips if present)
    start    boot the full rig (idempotent pieces; --source camera|synthetic)
    status   show process + stream + API health
    verify   programmatic end-to-end checks (prints PASS/FAIL per stage)
    bench    detector latency budgets — R1 exit gate (PASS/FAIL + exit code)
    soak     72h false-alert gate — R3 exit (counts alert/cam/day, catches a
             deaf rig; writes .rig/soak/ report; PASS/FAIL + exit code)
    stop     terminate everything the rig started
    watch    tail combined rig logs live (Ctrl-C to detach)

Environment (all optional):
    RIG_PORT         API port        (default 8000)
    RIG_RTSP_PORT    RTSP port       (default 8554)
    RIG_SOURCE       camera|synthetic (default camera)
    RIG_ADMIN_PASS   bootstrap admin password (default rig-admin-2026)

Notes:
    * The rig env sets SSRF_ALLOWLIST=127.0.0.0/8 — REQUIRED for LocalSight to
      be allowed to connect to a loopback RTSP camera. That is safe here: the
      broker binds loopback only and nothing else runs on these ports.
    * Camera URLs registered with LocalSight use the 127.0.0.1 IP literal
      (not "localhost") because the SSRF allowlist matches hostnames against
      CIDRs and "localhost" is not an IP.
    * Recording uses 30 s segments (RECORD_SEGMENT_SECONDS=30) so evidence
      appears in the dashboard quickly during a demo instead of after 5 min.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RIG_DIR = os.path.join(REPO, ".rig")
LOGS_DIR = os.path.join(RIG_DIR, "logs")
PIDS_DIR = os.path.join(RIG_DIR, "pids")
ENV_FILE = os.path.join(RIG_DIR, "env")
SOAK_DIR = os.path.join(RIG_DIR, "soak")
# How the rig was booted: "local" (FaceTime/synthetic via the loopback broker)
# or "external" (the operator's real LAN camera — no local capture). The soak's
# preflight reads this so an external run is not asked for a local broker.
MODE_FILE = os.path.join(RIG_DIR, "mode")

API_PORT = int(os.environ.get("RIG_PORT", "8000"))
RTSP_PORT = int(os.environ.get("RIG_RTSP_PORT", "8554"))
ADMIN_EMAIL = "admin@localsight.local"
ADMIN_PASS = os.environ.get("RIG_ADMIN_PASS", "rig-admin-2026")
CAM_NAME = "MacBook CCTV (local rig)"
MAIN_PATH = "cctv_main"
SUB_PATH = "cctv_sub"
RTSP_HOST = "127.0.0.1"  # IP literal, see module docstring

VENV_PY = os.path.join(REPO, ".venv", "bin", "python")
MTX_BIN = shutil.which("mediamtx") or "/opt/homebrew/bin/mediamtx"
FFMPEG_BIN = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
DATA_STORAGE = os.path.join(REPO, "data", "storage")
LIVE_DIR = os.path.join(REPO, "data", "live")

# Wait/retry tuning for boot + verify.
WAIT_STEP = 0.5
API_WAIT_SEC = 30.0
RTSP_WAIT_SEC = 15.0


# ── small utilities ────────────────────────────────────────────────────────
def say(msg: str) -> None:
    print(f"[rig] {msg}", flush=True)


def die(msg: str) -> None:
    print(f"[rig] FATAL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def http_json(method: str, path: str, base: str, token: str | None = None,
              body: dict | None = None, timeout: float = 10.0):
    url = f"{base}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else {})


def wait_for(predicate, timeout: float, what: str) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(WAIT_STEP)
    say(f"timeout waiting for {what} ({timeout}s)")
    return False


# ── process management (PID-file tracked, tree-killed) ──────────────────────
def _pidfile(name: str) -> str:
    return os.path.join(PIDS_DIR, f"{name}.pid")


def spawn(name: str, argv: list[str], env: dict | None = None,
          log: str | None = None, cwd: str | None = None) -> int:
    """Start a tracked process with stdout/stderr to a log file, in its own
    process group (so `stop` kills the whole tree, incl. ffmpeg children)."""
    os.makedirs(PIDS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_path = os.path.abspath(log or os.path.join(LOGS_DIR, f"{name}.log"))
    with open(log_path, "ab") as fh:
        proc = subprocess.Popen(
            argv, cwd=cwd or REPO, env=env, stdout=fh, stderr=fh,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
    with open(_pidfile(name), "w") as pf:
        pf.write(str(proc.pid))
    return proc.pid


def _read_pid(name: str) -> int | None:
    pf = _pidfile(name)
    if not os.path.exists(pf):
        return None
    try:
        with open(pf) as fh:
            return int(fh.read().strip())
    except (ValueError, OSError):
        return None


def is_running(name: str) -> bool:
    pid = _read_pid(name)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(_pidfile(name))
        return False


def stop_named(name: str) -> bool:
    """Kill the process group recorded for `name`; reap so nothing orphans."""
    pid = _read_pid(name)
    if pid is None:
        return False
    with contextlib.suppress(OSError):
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    # Bounded reap; escalate to SIGKILL after 5 s.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.1)
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        os.remove(_pidfile(name))
    return True


# ── rig .env (generated once, separate from the app's .env) ─────────────────
def rig_env() -> dict:
    env = dict(os.environ)
    env.update(
        {
            "APP_ENV": "development",
            "DATABASE_URL": "sqlite:///./localsight.db",
            "JWT_SECRET": env.get("_RIG_JWT"),
            "MASTER_ENCRYPTION_KEY": env.get("_RIG_MEK"),
            "CORS_ALLOW_ORIGINS": f"http://localhost:{API_PORT}",
            "SSRF_ALLOWLIST": os.environ.get("RIG_SSRF_ALLOWLIST", "127.0.0.0/8"),
            "STORAGE_BACKEND": "local",
            "STORAGE_LOCAL_ROOT": DATA_STORAGE,
            "LOCALSIGHT_LIVE_DIR": LIVE_DIR,
            "RECORD_ENABLED": "true",
            "RECORD_SEGMENT_SECONDS": "30",
            "RETENTION_RECORDINGS_DAYS": "2",
            # Real detection: the staged YOLO11n ONNX (registry-verified).
            # Falls back to the reference motion detector by deleting this
            # line (or `uv pip remove onnxruntime` + `AI_DETECTOR=reference`).
            "AI_DETECTOR": "onnx",
            "AI_INFERENCE_FPS": "5",
            "AI_CONFIDENCE_THRESHOLD": "0.45",
            "AI_MOTION_GATE_ENABLED": "true",
            "AI_RULES_ENABLED": "true",
            # Identity recognition ON for the rig: SCRFD + ArcFace staged ONNX
            # (registry-verified, local onnxruntime). Enroll in People and
            # events link your identity.
            "AI_IDENTITY_RECOGNITION_ENABLED": "true",
            "AI_SIMILARITY_THRESHOLD": "0.45",
            "LOG_LEVEL": "INFO",
            "BOOTSTRAP_ADMIN_EMAIL": ADMIN_EMAIL,
            "BOOTSTRAP_ADMIN_PASSWORD": ADMIN_PASS,
        }
    )
    return env


def ensure_secrets() -> dict:
    """Generate fresh JWT/MEK secrets once per rig (stored in .rig/env, which
    is dev-only and gitignored via the .rig entry we add to .gitignore)."""
    os.makedirs(RIG_DIR, exist_ok=True)
    stored: dict = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as fh:
            for line in fh:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    stored[k] = v
    changed = False
    if not stored.get("_RIG_JWT"):
        stored["_RIG_JWT"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        changed = True
    if not stored.get("_RIG_MEK"):
        stored["_RIG_MEK"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        changed = True
    if changed:
        with open(ENV_FILE, "w") as fh:
            for k, v in stored.items():
                fh.write(f"{k}={v}\n")
        os.chmod(ENV_FILE, 0o600)
    # Expose to this process so rig_env() can inherit them.
    for key in ("_RIG_JWT", "_RIG_MEK"):
        os.environ.setdefault(key, stored[key])
    return stored


def _write_mode(mode: str) -> None:
    """Record how the rig was booted so later commands (the soak preflight) know
    which components to expect."""
    os.makedirs(os.path.dirname(MODE_FILE) or ".", exist_ok=True)
    with open(MODE_FILE, "w") as fh:
        fh.write(mode)


def rig_mode() -> str:
    """'local' (FaceTime/synthetic through the loopback broker) or 'external'
    (the operator's real LAN camera; no local capture). Rigs booted before the
    marker existed have no file — they are local, so back-compat is preserved."""
    try:
        with open(MODE_FILE) as fh:
            return fh.read().strip() or "local"
    except FileNotFoundError:
        return "local"


def _soak_required_components(mode: str) -> list[str]:
    """Components the soak's preflight demands before committing hours to a run.

    External mode has no local broker or capture — the operator's camera is the
    source — so requiring them there would block a correctly-running soak for no
    reason. Local mode keeps demanding all four: a dead capture in local mode is
    exactly the silent failure the preflight exists to catch.
    """
    if mode == "external":
        return ["api", "worker"]
    return ["mediamtx", "capture", "api", "worker"]


# ── mediamtx + capture ─────────────────────────────────────────────────────
def write_mtx_config() -> str:
    """Minimal broker for MediaMTX ≥1.19 (modern field names; validated against
    1.20.1): RTSP-in/out on loopback only; every other protocol disabled.
    No publish/read auth: the broker binds loopback, the machine is the only
    client, and the URLs LocalSight stores are loopback-literal anyway."""
    cfg = os.path.join(RIG_DIR, "mediamtx.yml")
    with open(cfg, "w") as fh:
        fh.write(f"""# Generated by scripts/local_cctv_rig.py — local dev rig ONLY.
# Loopback RTSP broker for the CCTV simulation; all other protocols off.
logLevel: warn
api: no
metrics: no
pprof: no
playback: no
rtsp: yes
rtspAddress: :{RTSP_PORT}
rtspTransports: [tcp]
rtpAddress: 127.0.0.1
rtcpAddress: 127.0.0.1
rtmp: no
hls: no
webrtc: no
srt: no
paths:
  cctv_main:
    source: publisher
  cctv_sub:
    source: publisher
""")
    return cfg


def start_broker() -> None:
    if is_running("mediamtx") or port_open(RTSP_PORT):
        say("mediamtx already running")
        return
    cfg = write_mtx_config()
    pid = spawn("mediamtx", [MTX_BIN, cfg])
    say(f"mediamtx pid {pid} (RTSP :{RTSP_PORT})")
    if not wait_for(lambda: port_open(RTSP_PORT), RTSP_WAIT_SEC, "RTSP port"):
        die("mediamtx failed to open the RTSP port — check .rig/logs/mediamtx.log")


def capture_args(source: str) -> list[str]:
    """One ffmpeg publishing main+sub. macOS only lets ONE process open the
    camera, so a single capture is split into both encodes.

    camera:     FaceTime HD 1280x720 → main + scaled 640x360 sub
    synthetic:  testsrc2 → main;  life pattern → sub (both always moving,
                which keeps the motion detector producing events)
    """
    auth = f"{RTSP_HOST}:{RTSP_PORT}"
    common = [
        FFMPEG_BIN, "-hide_banner", "-nostdin", "-loglevel", "warning",
    ]
    if source == "synthetic":
        # NB: lavfi size values must use the 'x' separator (640x360), never ':'
        # — a bare ':' starts a new filtergraph option, so 'size=640:360' fails
        # to parse ("No option name near '360...'") on every ffmpeg build.
        video_in = [
            "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30",
            "-f", "lavfi", "-i", "life=size=640x360:rate=30:mold=10",
        ]
        main_map = ["-map", "0:v", "-an"]
        sub_map = ["-map", "1:v", "-an"]
        sub_vf: list[str] = []
    else:
        # avfoundation: video device index 0 (FaceTime HD); ":none" = no audio.
        # FaceTime HD only advertises 30fps modes (720p/480p) — requesting 15
        # makes ffmpeg fail to open the device.
        video_in = [
            "-f", "avfoundation", "-framerate", "30",
            "-video_size", "1280x720", "-i", "0:none",
        ]
        main_map = ["-map", "0:v", "-an"]
        sub_map = ["-map", "0:v", "-an"]
        sub_vf = ["-vf", "scale=640:360"]

    sub_bitrate = ["-b:v", "500k"]
    return [
        *common, *video_in,
        # main stream (recorded by the NVR)
        *main_map,
        "-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency",
        "-pix_fmt", "yuv420p", "-g", "30", "-b:v", "1800k",
        "-f", "rtsp", "-rtsp_transport", "tcp", f"rtsp://{auth}/{MAIN_PATH}",
        # sub stream (AI pipeline)
        *sub_map, *sub_vf,
        "-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency",
        "-pix_fmt", "yuv420p", "-g", "30", *sub_bitrate,
        "-f", "rtsp", "-rtsp_transport", "tcp", f"rtsp://{auth}/{SUB_PATH}",
    ]


# ── capture publisher ─────────────────────────────────────────────────────


def rtsp_ready(timeout: float = 20.0) -> bool:
    """True when both rig paths answer an RTSP DESCRIBE (ffmpeg one-frame
    probe). This is the gate for starting the worker: the worker's camera
    thread only retries ~10 times with backoff, so it must not boot before
    the publisher is actually serving frames."""
    probe = [
        FFMPEG_BIN, "-hide_banner", "-loglevel", "error", "-nostdin",
        "-rtsp_transport", "tcp", "-i", f"rtsp://{RTSP_HOST}:{RTSP_PORT}/{SUB_PATH}",
        "-frames:v", "1", "-f", "null", "-",
    ]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(probe, capture_output=True, timeout=8)
            if r.returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            pass
        except OSError:
            return False
        time.sleep(1.0)
    return False


def start_capture(source: str) -> None:
    if is_running("capture"):
        say("capture already running")
        return
    argv = capture_args(source)
    pid = spawn("capture", argv)
    say(f"capture ffmpeg pid {pid} (source={source})")
    if not rtsp_ready():
        die("capture did not publish within 20 s — check .rig/logs/capture.log "
            "(camera permission granted? try --source synthetic)")


# ── API + worker + registration ────────────────────────────────────────────
def start_api(env: dict) -> None:
    if is_running("api"):
        say("API already running (tracked)")
        return
    if port_open(API_PORT):
        die(f"port {API_PORT} is in use by a process the rig does not track; "
            f"stop it or set RIG_PORT")
    argv = [VENV_PY, "-m", "uvicorn", "apps.api.main:app",
            "--host", "127.0.0.1", "--port", str(API_PORT), "--log-level", "info"]
    pid = spawn("api", argv, env=env)
    say(f"API pid {pid} → http://localhost:{API_PORT}")
    base = f"http://127.0.0.1:{API_PORT}"
    if not wait_for(lambda: _api_alive(base), API_WAIT_SEC, "API /health/live"):
        die("API did not come up — check .rig/logs/api.log")


def _api_alive(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/health/live", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def login(base: str) -> str:
    """Login with bounded retries. Rate-limited (429) logins are fatal — the
    rig's own 1/s burst limiter needs ~30 s to recover, so failing fast with
    guidance beats spinning."""
    last: Exception | None = None
    for _ in range(20):
        try:
            st, body = http_json("POST", "/api/auth/login", base,
                                 body={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
            if st == 200:
                return body["access_token"]
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise RuntimeError(
                    "login rate-limited — wait ~30 s or restart the API process"
                ) from exc
            last = exc
        except Exception as exc:  # API still booting
            last = exc
        time.sleep(0.5)
    raise RuntimeError(f"login failed after retries: {last}")


def _create_or_reuse_camera(base: str, token: str, name: str, main_url: str,
                            sub_url: str, resolution: str = "1280x720",
                            fps: int = 15) -> str:
    """Create-or-reuse a camera by name via the real API (SSRF-validated,
    encrypted at rest — the exact path a real operator's camera takes)."""
    st, cams = http_json("GET", "/api/cameras", base, token)
    if st != 200:
        die(f"camera list failed: {st}")
    for c in cams:
        if c["name"] == name:
            say(f"camera already registered: {c['id']} (status {c['status']})")
            return c["id"]
    st, body = http_json("POST", "/api/cameras", base, token, body={
        "name": name,
        "stream_url": main_url,
        "substream_url": sub_url,
        "resolution": resolution,
        "fps": fps,
        "timezone": "UTC",
    })
    if st != 200:
        die(f"camera registration failed: {st} {body}")
    say(f"camera registered: {body['id']}")
    _install_rules(base, token, body["id"])
    return body["id"]


def register_camera(base: str, token: str, source: str) -> str:
    """The local rig camera: the loopback broker publishing FaceTime/synthetic."""
    auth = f"{RTSP_HOST}:{RTSP_PORT}"
    return _create_or_reuse_camera(
        base, token, CAM_NAME,
        f"rtsp://{auth}/{MAIN_PATH}", f"rtsp://{auth}/{SUB_PATH}",
        resolution="1280x720" if source == "camera" else "1280x720 (synthetic)",
    )


def provision_external_camera(base: str, token: str) -> str | None:
    """Optionally register the operator's real LAN camera from RIG_CAM_* env.

    External mode provisions nothing by default — the operator may have already
    configured the camera they want to soak. When RIG_CAM_NAME and
    RIG_CAM_MAIN_URL are set, do the create-or-reuse + rule install so the soak
    has exactly one armed camera; rules matter because the soak needs analytic
    fires (line_cross/loitering), not just presence. The substream defaults to
    the main URL so a single-stream camera still drives the AI pipeline.
    """
    name = os.environ.get("RIG_CAM_NAME")
    main_url = os.environ.get("RIG_CAM_MAIN_URL")
    if not name or not main_url:
        say("external mode: RIG_CAM_NAME/RIG_CAM_MAIN_URL not set — register your")
        say("camera via POST /api/cameras (or export those vars and restart),")
        say("arm its rules, then run `verify` before soaking")
        return None
    return _create_or_reuse_camera(
        base, token, name, main_url,
        os.environ.get("RIG_CAM_SUB_URL") or main_url,
        resolution=os.environ.get("RIG_CAM_RESOLUTION", "1280x720"),
    )


def retire_rig_camera(base: str, token: str) -> None:
    """Remove the dev FaceTime camera when booting in external mode.

    Its loopback broker is not running, so the worker would only burn its
    reconnect budget against rtsp://127.0.0.1:8554 and end up OFFLINE — and a
    soak lists every camera, so that one stale row would fail the "cameras
    stayed ONLINE" guard for a camera that is not even the subject. This script
    created that camera, so deleting it here is symmetric; the DB cascade drops
    its dev detections/tracks/segments (rule 8).
    """
    st, cams = http_json("GET", "/api/cameras", base, token)
    if st != 200:
        return
    for c in cams or []:
        if c["name"] == CAM_NAME:
            st2, _ = http_json("DELETE", f"/api/cameras/{c['id']}", base, token)
            if st2 == 200:
                say(f"retired dev rig camera {c['id']} (external mode)")
            else:
                say(f"warning: could not retire dev rig camera (status {st2})")


def _install_rules(base: str, token: str, cam_id: str) -> None:
    """Demo behavior rules sized for the synthetic/person-sized scene: a
    vertical line crossing mid-frame + a loitering zone over the whole view."""
    rules = [
        {"type": "line_cross", "rule_id": "rig-line",
         "a": [0.5, 0.0], "b": [0.5, 1.0], "direction": 1},
        {"type": "loitering", "rule_id": "rig-loiter",
         "zone": [[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 1.0]], "dwell_sec": 10},
    ]
    st, _ = http_json("PUT", f"/api/cameras/{cam_id}/rules", base, token,
                      body={"rules": rules})
    if st != 200:
        say(f"warning: rule install failed ({st}) — events will be presence-only")


def start_worker(env: dict) -> None:
    if is_running("worker"):
        say("worker already running")
        return
    pid = spawn("worker", [VENV_PY, "-m", "apps.worker"], env=env)
    say(f"worker pid {pid}")


# ── commands ───────────────────────────────────────────────────────────────
def cmd_setup() -> None:
    missing = [b for b in (FFMPEG_BIN, MTX_BIN) if not os.path.exists(b)]
    if missing:
        say(f"installing via brew: {missing}")
        subprocess.run(["brew", "install", "ffmpeg", "mediamtx"], check=True)
    if not os.path.exists(VENV_PY):
        say("creating .venv (python 3.13)")
        subprocess.run(["uv", "venv", "--python", "3.13", ".venv"], check=True)
        subprocess.run(["uv", "pip", "install", "--python", VENV_PY,
                        "-r", "requirements.txt", "numpy", "psutil"], check=True)
    say("setup complete")


def cmd_start(source: str) -> None:
    os.makedirs(RIG_DIR, exist_ok=True)
    os.makedirs(DATA_STORAGE, exist_ok=True)
    ensure_secrets()
    env = rig_env()
    base = f"http://127.0.0.1:{API_PORT}"
    _write_mode("external" if source == "external" else "local")

    if source == "external":
        # The operator's real LAN camera is the source: no broker, no FaceTime
        # capture. The camera is registered BEFORE the worker boots because the
        # worker snapshots the camera list once at startup (review note D-6) — a
        # camera added after would sit idle until a restart. RIG_SSRF_ALLOWLIST
        # must cover the camera's VLAN (the guard blocks private ranges by
        # default); the dev rig camera is retired so the soak lists only the
        # camera the operator intends to watch.
        start_api(env)
        token = login(base)
        retire_rig_camera(base, token)
        cam_id = provision_external_camera(base, token)
        start_worker(env)
        say("rig is up (external camera):")
        say(f"  dashboard    → http://localhost:{API_PORT}")
        say(f"  login        → {ADMIN_EMAIL} / {ADMIN_PASS}")
        if cam_id:
            say(f"  camera       → {os.environ['RIG_CAM_NAME']} ({cam_id})")
        else:
            say("  camera       → register yours via POST /api/cameras")
        say("run `verify` for end-to-end checks, `stop` to tear down")
        return

    start_broker()

    # A capture process may be alive but dead (broker restarted under it).
    # Reprobe; if the publisher is gone, kill and respawn before booting the
    # worker — the worker's reconnect budget is finite (~10 attempts).
    if is_running("capture") and not rtsp_ready(timeout=5.0):
        say("capture process alive but not publishing — restarting it")
        stop_named("capture")
    start_capture(source)

    start_api(env)
    token = login(base)
    cam_id = register_camera(base, token, source)

    start_worker(env)

    say("rig is up:")
    say(f"  dashboard    → http://localhost:{API_PORT}")
    say(f"  login        → {ADMIN_EMAIL} / {ADMIN_PASS}")
    say(f"  camera       → {CAM_NAME} ({cam_id})")
    say("  rtsp         → " + f"rtsp://127.0.0.1:{RTSP_PORT}/{MAIN_PATH}")
    say("run `verify` for end-to-end checks, `stop` to tear down")


def cmd_status() -> None:
    base = f"http://127.0.0.1:{API_PORT}"
    names = ["mediamtx", "capture", "api", "worker"]
    print("processes:")
    for n in names:
        mark = "running" if is_running(n) else "stopped"
        pid = ""
        pid_num = _read_pid(n)
        if pid_num is not None:
            pid = f" (pid {pid_num})"
        print(f"  {n:<10} {mark}{pid}")
    print(f"ports: rtsp:{RTSP_PORT} open={port_open(RTSP_PORT)}  "
          f"api:{API_PORT} open={port_open(API_PORT)}")
    if port_open(API_PORT):
        try:
            token = login(base)
            _st, cams = http_json("GET", "/api/cameras", base, token)
            for c in cams:
                print(f"  camera {c['name']}: {c['status']} (last_seen {c['last_seen']})")
        except Exception as exc:
            print(f"  (camera status unavailable: {exc})")


def cmd_verify() -> int:
    base = f"http://127.0.0.1:{API_PORT}"
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, note: str = "") -> None:
        checks.append((name, ok, note))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  ' + note if note else ''}")

    print("rig verification:")
    # 1. processes
    for n in ("mediamtx", "capture", "api", "worker"):
        check(f"process {n}", is_running(n))
    check(f"rtsp port {RTSP_PORT}", port_open(RTSP_PORT))
    # 2. API + auth
    check("api health", _api_alive(base))
    token = login(base)

    # 4. camera status via API (the F2 fix path)
    st, cams = http_json("GET", "/api/cameras", base, token)
    check("camera list", st == 200)
    # External mode registers the operator's camera (RIG_CAM_NAME) and retires
    # the dev one; fall back to the first registered camera so verify still
    # probes the real device instead of hard-failing on a missing rig name.
    want = os.environ.get("RIG_CAM_NAME") or CAM_NAME
    rig_cam = next((c for c in cams if c["name"] == want),
                   cams[0] if cams else None)
    if rig_cam:
        check("camera ONLINE", rig_cam["status"] == "ONLINE",
              f"status={rig_cam['status']} last_seen={rig_cam['last_seen']}")
        cam_id = rig_cam["id"]
    else:
        check("camera registered", False, "rig camera not found")
        return 1

    # 5. live view ticket → play → HLS manifest on disk
    st, body = http_json("POST", "/api/live/ticket", base, token,
                         body={"camera_id": cam_id, "ttl_sec": 300})
    check("live ticket", st == 200)
    if st == 200:
        st2, _play = http_json(
            "GET", f"/api/live/{cam_id}/play?ticket={body['ticket']}", base, token)
        check("live play (transcode start)", st2 == 200)
        manifest = os.path.join(LIVE_DIR, cam_id, "index.m3u8")
        ok = wait_for(lambda: os.path.exists(manifest), 10.0, "HLS manifest")
        check("HLS manifest on disk", ok, manifest if ok else "not created")

    # 6. recordings: wait up to ~40s for the first 30 s segment to land
    seg_found = False
    deadline = time.monotonic() + 45.0
    seg_count = 0
    while time.monotonic() < deadline:
        st, tl = http_json("GET",
                           f"/api/timeline?date={time.strftime('%Y-%m-%d')}&camera_id={cam_id}",
                           base, token)
        seg_count = len(tl.get("recording", []))
        if seg_count > 0:
            seg_found = True
            break
        time.sleep(3)
    check("recording segment persisted", seg_found, f"{seg_count} segment(s)")

    # 7. events flowing (presence/line_cross/loitering)
    st, evs = http_json("GET", f"/api/events?camera_id={cam_id}&limit=5", base, token)
    check("events endpoint", st == 200)
    n_events = evs.get("total", 0)
    check("events recorded", n_events > 0, f"total={n_events}")
    if n_events:
        types = {}
        for it in evs["items"]:
            types[it["event_type"]] = types.get(it["event_type"], 0) + 1
        check("event types", bool(types), str(types))

    failed = [c for c in checks if not c[1]]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    if failed:
        print("failing:", ", ".join(f[0] for f in failed))
        return 1
    print("RIG VERIFIED — end-to-end streaming, recording, AI, live view all working.")
    return 0


def cmd_stop() -> None:
    any_stopped = False
    for n in ("worker", "api", "capture", "mediamtx"):
        if stop_named(n):
            say(f"stopped {n}")
            any_stopped = True
    if not any_stopped:
        say("nothing to stop (rig not running)")
    else:
        say("rig torn down; data kept in ./localsight.db + ./data/ (rerun `start` to resume)")


def cmd_watch() -> None:
    logs = [os.path.join(LOGS_DIR, f"{n}.log") for n in
            ("mediamtx", "capture", "api", "worker")]
    existing = [path for path in logs if os.path.exists(path)]
    if not existing:
        die("no rig logs yet — run `start` first")
    # Replace this process with tail(1): intentional, so Ctrl-C flows to tail
    # directly and there is no orphaned watcher.
    os.execvp("tail", ["tail", "-n", "20", "-F", *existing])  # noqa: S606


def cmd_bench(backend: str, iterations: int) -> int:
    """Run the detector latency bench with the rig's own env (R1 exit gate).

    Runs as a subprocess so the rig's staged-model env (AI_DETECTOR,
    AI_MODEL_NAME, regression allowlist) applies exactly as the worker sees it
    — benchmarking a differently configured interpreter would measure a
    deployment nobody runs. Exit code is the bench's own pass/fail, so the
    command is usable directly in CI or a pre-demo check.
    """
    if not os.path.exists(os.path.join(RIG_DIR, "env")):
        die("rig env not found — run `setup`/`start` first")
    print(f"bench: backend={backend} iterations={iterations}")
    cmd = [sys.executable, os.path.join(REPO, "scripts", "bench_detector.py"),
           "--backend", backend, "--iterations", str(iterations)]
    proc = subprocess.run(cmd, cwd=REPO)
    print("bench report rendered above; exit code carries the budget verdict.")
    return proc.returncode


# ── soak (R3-Close.1) ───────────────────────────────────────────────────────


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _soak_login(base: str, tries: int = 5) -> str:
    """Login with soak-grade patience.

    ``login()`` raises on a 429 (auth is rate-limited at 1/s burst 10). Over a
    multi-hour soak a transient lockout is expected, not exceptional — dying
    there would throw away hours of a 72 h window. Back off and retry instead
    (the bucket fully refills in ~10 s).
    """
    last: Exception | None = None
    for attempt in range(tries):
        try:
            return login(base)
        except Exception as exc:
            last = exc
            if attempt < tries - 1:
                say(f"login attempt {attempt + 1}/{tries} failed ({exc}); "
                    "backing off 30 s before retry")
                time.sleep(30.0)
    raise RuntimeError(f"soak login failed after {tries} tries: {last}")


class _SoakSession:
    """API session that survives access-token expiry.

    Access tokens live 15 min; a soak runs for hours. Re-login transparently on
    a 401 so a token rolling over mid-window never aborts the run.
    """

    def __init__(self, base: str) -> None:
        self.base = base
        self.token = _soak_login(base)

    def get(self, path: str, timeout: float = 15.0):
        try:
            return http_json("GET", path, self.base, self.token, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                say("access token expired mid-soak; re-authenticating")
                self.token = _soak_login(self.base)
                return http_json("GET", path, self.base, self.token, timeout=timeout)
            raise


class SoakWindow:
    """Per-camera, per-UTC-day alert accounting over a soak window.

    ``used_today`` from ``GET /api/alerts/budget`` counts analytic events since
    UTC midnight and *resets at UTC midnight*. A naive running total therefore
    double-counts every day boundary, and a long window's true rate is hidden
    inside one average. This class finalizes each UTC day separately so a bursty
    day cannot hide and days cannot be double-counted.

    The first observed day is *partial* unless the soak began at UTC midnight:
    it may carry events from before the window opened. Its count is a delta from
    the baseline captured at soak start, so pre-window events are never charged
    to the soak.
    """

    def __init__(self, baseline: dict[str, int] | None = None) -> None:
        self.baseline = dict(baseline or {})
        self.day_counts: dict[str, dict[str, int]] = {}
        self.day_partial: dict[str, bool] = {}
        self.last_day: str | None = None
        self.fires_total = 0
        self._finalized: set[str] = set()

    def sample(self, utc_date: str, cam_id: str, used_today: int) -> None:
        """Record one budget reading for one camera."""
        if self.last_day is not None and utc_date != self.last_day:
            self.finalize_day(self.last_day)
        if utc_date not in self.day_counts:
            self.day_counts[utc_date] = {}
            self.day_partial[utc_date] = self.last_day is None
            if self.last_day is None:
                # A camera absent from the soak-start snapshot did not exist
                # when the window opened, so it has no pre-window events to
                # exclude — its baseline is 0, not its first observed count.
                self.baseline.setdefault(cam_id, 0)
        self.last_day = utc_date
        if self.day_partial[utc_date]:
            # Only charge what happened inside the window.
            self.day_counts[utc_date][cam_id] = max(0, used_today - self.baseline.get(cam_id, 0))
        else:
            self.day_counts[utc_date][cam_id] = used_today

    def finalize_day(self, utc_date: str) -> None:
        """Lock in a day's counts (idempotent — rollover then close)."""
        if utc_date not in self.day_counts or utc_date in self._finalized:
            return
        self._finalized.add(utc_date)
        total = sum(self.day_counts[utc_date].values())
        self.fires_total += total
        kind = "partial" if self.day_partial.get(utc_date) else "full"
        say(f"UTC day {utc_date} finalized ({kind}): {total} analytic fire(s)")

    def close(self) -> None:
        """Finalize the in-flight day at soak end."""
        if self.last_day is not None:
            self.finalize_day(self.last_day)

    def per_camera_total(self, cam_id: str) -> int:
        return sum(self.day_counts[d].get(cam_id, 0) for d in self.day_counts)

    def days(self) -> list[str]:
        return sorted(self.day_counts)


def cmd_soak(hours: float, budget_per_cam_day: int, min_fires: int,
             poll_sec: float, deaf_window_sec: float, tag: str,
             out_dir: str) -> int:
    """R3-Close.1: the 72 h false-alert soak, as a reproducible gate.

    The soak is the R3 exit gate because it answers the one question unit tests
    cannot: with real rules armed on a real scene for days, does the pipeline
    stay quiet when nothing happens *and* loud when something does?

    Two failure modes both fail the run:

    * **Spam** — more analytic fires than the budget allows, per camera per UTC
      day (from ``GET /api/alerts/budget`` — the same durable rows the worker
      seeds its fan-out gate from, so the verdict and runtime budget can never
      disagree).
    * **Deafness** — a rig that detects nothing trivially "passes" a quiet
      budget. Guarded three ways: cameras stay ONLINE, ``last_seen`` keeps
      advancing (the heartbeat only ticks while frames flow), and at least
      ``min_fires`` analytic events register (the scripted intrusions).

    The verdict is written to a JSON + markdown artifact, not a spreadsheet, so
    the gate is reproducible and archivable into `03`.
    """
    base = f"http://127.0.0.1:{API_PORT}"
    if hours <= 0:
        die("--hours must be positive")

    # Preflight: the soak observes a running rig, it does not boot one. Failing
    # fast here beats recording hours of "no camera" as a pass.
    for n in _soak_required_components(rig_mode()):
        if not is_running(n):
            die(f"rig component '{n}' is not running — start the rig first "
                "(`python scripts/local_cctv_rig.py start`) then launch the soak")
    if not _api_alive(base):
        die("API not responding — check .rig/logs/api.log before soaking")

    session = _SoakSession(base)
    st, cams = http_json("GET", "/api/cameras", base, session.token)
    if st != 200 or not cams:
        die(f"no cameras visible to soak (status {st}); register a camera first")
    cam_ids = [c["id"] for c in cams]
    cam_names = {c["id"]: c["name"] for c in cams}
    say(f"soak target: {len(cam_ids)} camera(s): "
        + ", ".join(f"{cam_names[c]} ({c})" for c in cam_ids))

    os.makedirs(out_dir, exist_ok=True)
    started_at = _utc_now()
    deadline = time.monotonic() + hours * 3600.0

    st, base_budget = session.get("/api/alerts/budget")
    if st != 200:
        die(f"alert budget endpoint unavailable (status {st}) — the soak reads "
            "its counts from here")
    baseline = {row["camera_id"]: row["used_today"]
                for row in base_budget.get("cameras", [])}
    window = SoakWindow(baseline)

    prev_last_seen: dict[str, str | None] = {c: None for c in cam_ids}
    last_seen_advanced: dict[str, float] = {c: time.monotonic() for c in cam_ids}
    offline_events: dict[str, int] = {c: 0 for c in cam_ids}
    deaf_intervals: dict[str, list[float]] = {c: [] for c in cam_ids}
    samples = 0

    say(f"soak START {started_at.isoformat()} — {hours:g} h, budget "
        f"{budget_per_cam_day} alert/cam/day, min {min_fires} fire(s), "
        f"poll {poll_sec:g} s")
    say("operator: perform the scripted intrusions during the window; the soak "
        "asserts they register (a deaf rig fails the gate, never passes it)")

    try:
        while time.monotonic() < deadline:
            now = _utc_now()
            try:
                st, bud = session.get("/api/alerts/budget")
                stc, cam_rows = session.get("/api/cameras")
            except Exception as exc:
                say(f"poll failed ({exc}); continuing — a missed sample is not a "
                    "failed soak, but repeated failures surface as deafness")
                time.sleep(poll_sec)
                continue

            if st == 200:
                utc_date = now.strftime("%Y-%m-%d")
                for row in bud.get("cameras", []):
                    cid = row["camera_id"]
                    if cid in cam_ids:
                        window.sample(utc_date, cid, int(row.get("used_today") or 0))

            if stc == 200:
                for cam in cam_rows:
                    cid = cam["id"]
                    if cid not in cam_ids:
                        continue
                    if cam["status"] != "ONLINE":
                        offline_events[cid] = offline_events.get(cid, 0) + 1
                    seen = cam.get("last_seen")
                    if seen and seen != prev_last_seen[cid]:
                        prev_last_seen[cid] = seen
                        last_seen_advanced[cid] = time.monotonic()
                    stale_for = time.monotonic() - last_seen_advanced[cid]
                    if stale_for > deaf_window_sec:
                        deaf_intervals[cid].append(stale_for)

            samples += 1
            time.sleep(poll_sec)
    except KeyboardInterrupt:
        say("interrupted by operator — finalizing a partial report")
    finally:
        window.close()

    ended_at = _utc_now()
    elapsed_h = (ended_at - started_at).total_seconds() / 3600.0

    checks, window_rate, _worst, complete = _soak_checks(
        window=window, cam_ids=cam_ids, cam_names=cam_names,
        offline_events=offline_events, deaf_intervals=deaf_intervals,
        budget_per_cam_day=budget_per_cam_day, min_fires=min_fires,
        elapsed_h=elapsed_h, requested_h=hours,
        deaf_window_sec=deaf_window_sec,
    )
    return _soak_report(
        window=window, cam_ids=cam_ids, cam_names=cam_names,
        offline_events=offline_events, deaf_intervals=deaf_intervals,
        checks=checks, window_rate=window_rate, elapsed_h=elapsed_h,
        requested_h=hours, samples=samples, started_at=started_at,
        ended_at=ended_at, tag=tag, out_dir=out_dir, poll_sec=poll_sec,
        complete=complete, budget_per_cam_day=budget_per_cam_day,
        min_fires=min_fires,
    )


def _soak_checks(*, window: SoakWindow, cam_ids: list[str],
                 cam_names: dict[str, str], offline_events: dict[str, int],
                 deaf_intervals: dict[str, list[float]],
                 budget_per_cam_day: int, min_fires: int, elapsed_h: float,
                 requested_h: float, deaf_window_sec: float
                 ) -> tuple[list[tuple[str, bool, str]], float, float, bool]:
    """Evaluate every soak assertion. Returns (checks, window_rate, worst, complete).

    Pure: no I/O, so the gate logic is unit-testable against a synthetic window.
    """
    elapsed_days = max(elapsed_h / 24.0, 1e-9)
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, note: str = "") -> None:
        checks.append((name, ok, note))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  ' + note if note else ''}")

    print("soak verdict:")
    # A partial run cannot certify a 72 h gate — but it still reports, so an
    # interrupted soak is diagnosable rather than discarded.
    complete = elapsed_h >= requested_h * 0.95
    check(f"soak duration ≥ requested ({requested_h:g} h)", complete,
          f"elapsed {elapsed_h:.2f} h")

    # 1. Spam guard: per UTC day, no camera exceeds the budget. The partial
    # first day is scaled to a 24 h rate so a short-but-bursty opening is still
    # caught, and a burst can never hide behind a favourable average.
    violations: list[str] = []
    worst_rate = 0.0
    days = window.days()
    for utc_date in days:
        partial = window.day_partial.get(utc_date)
        for cid in cam_ids:
            n = window.day_counts[utc_date].get(cid, 0)
            if partial and utc_date == days[-1]:
                span_h = max(min(elapsed_h, 24.0), 1e-9)
                rate = n / span_h * 24.0
            else:
                rate = float(n)
            worst_rate = max(worst_rate, rate)
            if rate > budget_per_cam_day:
                violations.append(f"{cam_names[cid]} day {utc_date}: {n} "
                                  f"({rate:.2f}/day)")
    check(f"false-alert budget ≤ {budget_per_cam_day}/cam/day",
          not violations,
          "; ".join(violations) if violations else f"worst {worst_rate:.2f}/cam/day")

    # 2. Window-average guard: a bursty day cannot hide inside a quiet week.
    window_rate = window.fires_total / elapsed_days / max(len(cam_ids), 1)
    check("window-average within budget", window_rate <= budget_per_cam_day,
          f"{window_rate:.2f}/cam/day over {elapsed_days:.2f} day(s)")

    # 3. Deafness guards — silence must not pass.
    offline = {c: n for c, n in offline_events.items() if n}
    check("cameras stayed ONLINE", not offline,
          "; ".join(f"{cam_names[c]} offline {n} sample(s)" for c, n in offline.items())
          or "no offline samples")
    deaf = {c: iv for c, iv in deaf_intervals.items() if iv}
    check(f"last_seen advanced (deaf guard, window {deaf_window_sec:g} s)",
          not deaf,
          "; ".join(f"{cam_names[c]} stale {max(iv):.0f} s" for c, iv in deaf.items())
          or "heartbeats current")
    check(f"scripted intrusions registered (≥{min_fires} fire(s))",
          window.fires_total >= min_fires,
          f"{window.fires_total} analytic fire(s) total")
    return checks, window_rate, worst_rate, complete


def _soak_report(*, window: SoakWindow, cam_ids: list[str],
                 cam_names: dict[str, str], offline_events: dict[str, int],
                 deaf_intervals: dict[str, list[float]], checks: list,
                 window_rate: float, elapsed_h: float, requested_h: float,
                 samples: int, started_at: dt.datetime,
                 ended_at: dt.datetime, tag: str, out_dir: str,
                 poll_sec: float, complete: bool, budget_per_cam_day: int,
                 min_fires: int) -> int:
    """Assemble the report, archive JSON + markdown, and return the exit code."""
    per_cam = {
        cid: {
            "name": cam_names[cid],
            "fires_total": window.per_camera_total(cid),
            "per_utc_day": {d: window.day_counts[d].get(cid, 0)
                            for d in window.days()},
            "offline_samples": offline_events.get(cid, 0),
            "max_stale_sec": (max(deaf_intervals[cid])
                              if deaf_intervals.get(cid) else 0.0),
        }
        for cid in cam_ids
    }
    report = {
        "tag": tag,
        "started_at": started_at.isoformat(), "ended_at": ended_at.isoformat(),
        "requested_hours": requested_h, "elapsed_hours": round(elapsed_h, 3),
        "budget_per_cam_day": budget_per_cam_day,
        "min_fires_expected": min_fires,
        "cameras": per_cam,
        "fires_total": window.fires_total,
        "window_rate_per_cam_day": round(window_rate, 3),
        "checks": [{"name": n, "pass": ok, "note": note} for n, ok, note in checks],
        "verdict": "PASS" if all(ok for _, ok, _ in checks) else "FAIL",
        "samples": samples,
        "poll_sec": poll_sec,
        "note": "complete window" if complete else "partial run",
    }
    os.makedirs(out_dir, exist_ok=True)
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    json_path = os.path.join(out_dir, f"soak_{tag}_{stamp}.json")
    with open(json_path, "w") as fh:
        json.dump(report, fh, indent=2)
    md_path = os.path.join(out_dir, f"soak_{tag}_{stamp}.md")
    with open(md_path, "w") as fh:
        fh.write(_soak_markdown(report))
    say(f"report → {json_path}")
    say(f"summary → {md_path}")

    failed = [c for c in checks if not c[1]]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} soak checks passed "
          f"({report['verdict']})")
    if failed:
        print("failing:", ", ".join(f[0] for f in failed))
        return 1
    print("SOAK PASSED — quiet when nothing happened, loud when it did.")
    return 0


def _soak_markdown(report: dict) -> str:
    """A paste-ready summary, including the `03` KPI row value."""
    lines = [
        f"# Soak report — {report['tag']}",
        "",
        f"- **Verdict:** {report['verdict']} ({report['note']})",
        f"- **Window:** {report['started_at']} → {report['ended_at']} "
        f"({report['elapsed_hours']:g} h of {report['requested_hours']:g} requested)",
        f"- **Budget:** ≤{report['budget_per_cam_day']} alert/cam/day · "
        f"expected ≥{report['min_fires_expected']} scripted fire(s)",
        f"- **Result:** {report['fires_total']} analytic fire(s), "
        f"{report['window_rate_per_cam_day']}/cam/day window average",
        "",
        "## Per camera",
        "",
        "| Camera | Fires | Worst day | Offline samples | Max stale (s) |",
        "|---|---|---|---|---|",
    ]
    for cam in report["cameras"].values():
        worst = max(cam["per_utc_day"].values()) if cam["per_utc_day"] else 0
        lines.append(f"| {cam['name']} | {cam['fires_total']} | {worst} | "
                     f"{cam['offline_samples']} | {cam['max_stale_sec']:.0f} |")
    lines += ["", "## Checks", "", "| Check | Result | Note |", "|---|---|---|"]
    for chk in report["checks"]:
        lines.append(f"| {chk['name']} | {'PASS' if chk['pass'] else 'FAIL'} | "
                     f"{chk['note']} |")
    lines += [
        "",
        f"**`03` KPI paste (false-alert rate):** "
        f"`{report['window_rate_per_cam_day']} alert/cam/day over "
        f"{report['elapsed_hours']:g} h ({report['tag']})`",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup", help="install brew deps + venv")
    p_start = sub.add_parser("start", help="boot the full rig")
    p_start.add_argument("--source", choices=["camera", "synthetic", "external"],
                         default=os.environ.get("RIG_SOURCE", "camera"),
                         help="FaceTime camera, synthetic moving pattern, or "
                              "'external' = the operator's real LAN camera "
                              "(pairs with RIG_SSRF_ALLOWLIST + RIG_CAM_* env)")
    sub.add_parser("status", help="process/stream/API health")
    sub.add_parser("verify", help="end-to-end checks")
    p_bench = sub.add_parser("bench", help="detector latency budgets (R1 exit gate)")
    p_bench.add_argument("--backend", default="onnx",
                         choices=["none", "onnx", "openvino", "tensorrt"],
                         help="none = pure hot paths only, no staged model needed")
    p_bench.add_argument("--iterations", type=int, default=100)
    p_soak = sub.add_parser("soak", help="72h false-alert soak (R3 exit gate)")
    p_soak.add_argument("--hours", type=float, default=72.0,
                        help="soak window length (fractional ok for smoke tests)")
    p_soak.add_argument("--budget", type=int, default=1,
                        dest="budget_per_cam_day",
                        help="max analytic alerts per camera per UTC day")
    p_soak.add_argument("--min-fires", type=int, default=2, dest="min_fires",
                        help="scripted intrusions that MUST fire (deaf-rig guard)")
    p_soak.add_argument("--poll-sec", type=float, default=60.0, dest="poll_sec",
                        help="sampling interval for the budget + liveness probes")
    p_soak.add_argument("--deaf-window-sec", type=float, default=300.0,
                        dest="deaf_window_sec",
                        help="last_seen may be stale this long before the run "
                             "is flagged deaf")
    p_soak.add_argument("--tag", default="r3",
                        help="label for the report files (e.g. r3, smoke)")
    p_soak.add_argument("--out-dir", default=SOAK_DIR, dest="out_dir",
                        help="where to write soak_*.json / .md reports")
    sub.add_parser("stop", help="tear the rig down")
    sub.add_parser("watch", help="tail all rig logs")
    args = ap.parse_args()

    if args.cmd == "setup":
        cmd_setup()
    elif args.cmd == "start":
        cmd_start(args.source)
    elif args.cmd == "status":
        cmd_status()
    elif args.cmd == "verify":
        return cmd_verify()
    elif args.cmd == "bench":
        return cmd_bench(args.backend, args.iterations)
    elif args.cmd == "soak":
        return cmd_soak(args.hours, args.budget_per_cam_day, args.min_fires,
                        args.poll_sec, args.deaf_window_sec, args.tag,
                        args.out_dir)
    elif args.cmd == "stop":
        cmd_stop()
    elif args.cmd == "watch":
        cmd_watch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
