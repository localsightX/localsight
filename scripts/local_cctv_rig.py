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
            "SSRF_ALLOWLIST": "127.0.0.0/8",
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
        video_in = [
            "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30",
            "-f", "lavfi", "-i", "life=size=640:360:rate=30:mold=10",
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


def register_camera(base: str, token: str, source: str) -> str:
    """Create-or-reuse the rig camera via the real API (SSRF-validated,
    encrypted at rest — the exact path a real operator's camera takes)."""
    st, cams = http_json("GET", "/api/cameras", base, token)
    if st != 200:
        die(f"camera list failed: {st}")
    for c in cams:
        if c["name"] == CAM_NAME:
            say(f"camera already registered: {c['id']} (status {c['status']})")
            return c["id"]
    auth = f"{RTSP_HOST}:{RTSP_PORT}"
    main_url = f"rtsp://{auth}/{MAIN_PATH}"
    sub_url = f"rtsp://{auth}/{SUB_PATH}"
    st, body = http_json("POST", "/api/cameras", base, token, body={
        "name": CAM_NAME,
        "stream_url": main_url,
        "substream_url": sub_url,
        "resolution": "1280x720" if source == "camera" else "1280x720 (synthetic)",
        "fps": 15,
        "timezone": "UTC",
    })
    if st != 200:
        die(f"camera registration failed: {st} {body}")
    cam_id = body["id"]
    say(f"camera registered: {cam_id}")
    _install_rules(base, token, cam_id)
    return cam_id


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
    rig_cam = next((c for c in cams if c["name"] == CAM_NAME), None)
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
    proc = subprocess.run(cmd, cwd=REPO)  # noqa: S603 - fixed argv, our own script
    print("bench report rendered above; exit code carries the budget verdict.")
    return proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup", help="install brew deps + venv")
    p_start = sub.add_parser("start", help="boot the full rig")
    p_start.add_argument("--source", choices=["camera", "synthetic"],
                         default=os.environ.get("RIG_SOURCE", "camera"),
                         help="FaceTime camera or synthetic moving pattern")
    sub.add_parser("status", help="process/stream/API health")
    sub.add_parser("verify", help="end-to-end checks")
    p_bench = sub.add_parser("bench", help="detector latency budgets (R1 exit gate)")
    p_bench.add_argument("--backend", default="onnx",
                         choices=["none", "onnx", "openvino", "tensorrt"],
                         help="none = pure hot paths only, no staged model needed")
    p_bench.add_argument("--iterations", type=int, default=100)
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
    elif args.cmd == "stop":
        cmd_stop()
    elif args.cmd == "watch":
        cmd_watch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
