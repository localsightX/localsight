"""Disk-pressure monitoring (reliability plan F3 — "disk full").

The worker wired a `DiskPressureMonitor` into the retention loop, but the
monitor's path came from `getattr(rt.storage, "root", None)` while the local
backend keeps it in `_root`. The attribute therefore never existed, the path
was always None, and every deployment logged "monitoring inactive: storage
backend has no local volume" — on the very backend that *owns* one. Disk full
is the failure mode that quietly destroys an NVR, so an alarm that can never
fire is worse than no alarm: it reads as "watched". These tests pin the
contract end to end (provider path → monitor → alert-once-per-crossing).
"""
from __future__ import annotations

import os

import pytest

from packages.observability import disk
from packages.storage.base import StorageProvider


class _RemoteStorage(StorageProvider):
    """Minimal remote provider: no local volume should be reported."""

    def put(self, key, data, content_type="application/octet-stream"): ...
    def put_stream(self, key, source_path, content_type="application/octet-stream"): return 0
    def get(self, key): raise FileNotFoundError(key)
    def size(self, key): raise FileNotFoundError(key)
    def read_range(self, key, start, end): raise FileNotFoundError(key)
    def delete(self, key): ...
    def exists(self, key): return False
    def sign_get_url(self, key, expires_sec=300): return ""
    def verify_signed_url(self, key, exp, sig): return False


@pytest.fixture()
def rt(app):
    return app.state.runtime


# ── pure threshold + hysteresis logic ────────────────────────────────────

def test_pressure_level_boundaries():
    assert disk.pressure_level(0.0) == disk.OK
    assert disk.pressure_level(0.7999) == disk.OK
    assert disk.pressure_level(0.80) == disk.WARNING      # >= warn
    assert disk.pressure_level(0.8999) == disk.WARNING
    assert disk.pressure_level(0.90) == disk.CRITICAL     # >= critical
    assert disk.pressure_level(1.0) == disk.CRITICAL


def test_escalation_is_immediate():
    m = disk.DiskPressureMonitor("/")
    assert m.observe(0.50) == disk.OK
    assert m.observe(0.85) == disk.WARNING
    assert m.observe(0.95) == disk.CRITICAL


def test_critical_holds_until_usage_drops_a_full_band():
    m = disk.DiskPressureMonitor("/")
    assert m.observe(0.95) == disk.CRITICAL
    # 0.88 is below the critical line (0.90) but inside the re-arm band, so the
    # verdict must not clear yet — this is what stops hourly flap.
    assert m.observe(0.88) == disk.CRITICAL
    assert m.observe(0.84) == disk.WARNING
    assert m.observe(0.70) == disk.OK


def test_warning_does_not_clear_inside_band():
    m = disk.DiskPressureMonitor("/")
    assert m.observe(0.81) == disk.WARNING
    assert m.observe(0.79) == disk.WARNING   # still within warn - band (0.75)
    assert m.observe(0.74) == disk.OK


def test_unknown_ratio_holds_last_verdict_and_counts_polls():
    m = disk.DiskPressureMonitor(None)
    assert m.observe(0.95) == disk.CRITICAL
    assert m.observe(None) == disk.CRITICAL   # never silently "heals"
    assert m.unknown_polls == 1
    assert m.last_ratio is None


def test_take_alert_fires_once_per_change():
    m = disk.DiskPressureMonitor("/")
    assert m.take_alert() is None                 # starting at OK is not an alert
    m.observe(0.85)
    assert m.take_alert() == disk.WARNING
    assert m.take_alert() is None                 # no repeat while steady
    m.observe(0.86)
    assert m.take_alert() is None
    m.observe(0.95)
    assert m.take_alert() == disk.CRITICAL
    m.observe(0.50)
    assert m.take_alert() == disk.OK              # recovery reported once


def test_usage_ratio_reads_a_real_volume(tmp_path):
    ratio = disk.usage_ratio(str(tmp_path))
    assert ratio is not None and 0.0 <= ratio <= 1.0


def test_usage_ratio_is_none_when_unknown():
    assert disk.usage_ratio(None) is None
    assert disk.usage_ratio("") is None
    assert disk.usage_ratio("/definitely/not/a/path/at/all") is None



# ── provider contract (the regression) ───────────────────────────────────

def test_local_backend_reports_its_recordings_volume(rt):
    """The bug: local storage exposed no readable path, so F3 never ran."""
    path = rt.storage.local_volume_path
    assert path is not None
    assert os.path.isabs(path)
    assert os.path.isdir(path)


def test_base_provider_defaults_to_no_local_volume():
    assert _RemoteStorage().local_volume_path is None


def test_make_disk_monitor_samples_the_recordings_volume(rt):
    from apps.worker.main import make_disk_monitor

    monitor = make_disk_monitor(rt)
    assert monitor.path is not None, "disk pressure monitoring must not be a no-op"
    assert monitor.path == os.path.abspath(rt.settings.storage_local_root)
    # Thresholds come from settings, not hard-coded defaults.
    assert monitor.warn == rt.settings.disk_warn_pct
    assert monitor.critical == rt.settings.disk_critical_pct


def test_make_disk_monitor_stays_silent_without_a_local_volume(rt):
    from apps.worker.main import make_disk_monitor

    class _FakeRuntime:
        settings = rt.settings
        storage = _RemoteStorage()

    monitor = make_disk_monitor(_FakeRuntime())
    assert monitor.path is None
    # Unknown disk state must never be reported as healthy *nor* as an incident.
    assert monitor.poll() == (disk.OK, None)
    assert monitor.take_alert() is None


# ── end-to-end: sample → alert dispatch seam ─────────────────────────────

def _scripted_ratios(monkeypatch, values):
    """Patch the sampled usage ratio; the monitor's own logic stays real."""
    seq = iter(values)
    monkeypatch.setattr(disk, "usage_ratio", lambda path: next(seq, None))


def test_disk_pressure_alerts_once_per_crossing(rt, monkeypatch):
    from apps.worker import main as worker

    _scripted_ratios(monkeypatch, [0.50, 0.85, 0.86, 0.95, 0.50])
    monitor = worker.make_disk_monitor(rt)
    sent: list = []

    assert worker._check_disk_pressure(rt, monitor, emit=sent.append) is None
    assert sent == []

    warn = worker._check_disk_pressure(rt, monitor, emit=sent.append)
    assert warn is not None and warn.severity == "warning"
    assert warn.rule_type == "disk_pressure"
    assert warn.camera_id == ""            # site-level, not camera-scoped
    assert warn.detail["level"] == disk.WARNING
    assert warn.detail["used_pct"] == 85.0

    # A steadier (or slightly worse) sample inside the band must not re-alert.
    assert worker._check_disk_pressure(rt, monitor, emit=sent.append) is None

    crit = worker._check_disk_pressure(rt, monitor, emit=sent.append)
    assert crit is not None and crit.severity == "critical"
    assert crit.detail["level"] == disk.CRITICAL
    assert len(sent) == 2

    # Recovery is logged, never alerted: a green disk is not an incident.
    assert worker._check_disk_pressure(rt, monitor, emit=sent.append) is None
    assert len(sent) == 2
    assert monitor.level == disk.OK


def test_disk_pressure_uses_the_alert_queue_by_default(rt, monkeypatch):
    """The dispatch path (not just the injectable seam) must carry the alert."""
    from apps.worker import main as worker

    _scripted_ratios(monkeypatch, [0.95])
    queued: list = []

    class _Queue:
        def put(self, item):
            queued.append(item)

    monkeypatch.setattr(worker, "_alert_queue", _Queue())
    monitor = worker.make_disk_monitor(rt)
    alert = worker._check_disk_pressure(rt, monitor)

    assert alert is not None
    assert queued == [alert]
    assert queued[0].title == "storage critical"


def test_disk_pressure_publishes_prometheus_gauges(rt, monkeypatch):
    from apps.worker import main as worker
    from packages.observability.metrics import metrics

    _scripted_ratios(monkeypatch, [0.95])
    monitor = worker.make_disk_monitor(rt)
    worker._check_disk_pressure(rt, monitor, emit=lambda _a: None)

    exposition = metrics.render()
    assert "disk_used_ratio" in exposition
    assert "disk_pressure_level" in exposition
