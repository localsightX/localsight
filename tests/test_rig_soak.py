"""Soak harness logic (R3-Close.1) — `scripts/local_cctv_rig.py`.

The soak counts analytic fires per camera per UTC day. The subtle part is that
`used_today` (from GET /api/alerts/budget) *resets at UTC midnight*, so a
multi-day window must finalize each day separately or it silently double-counts
the rollover, and the first day is *partial* — it may carry events from before
the window opened, which must not be charged to the soak. These tests pin both
behaviours plus every verdict path, including the deaf-rig guard (a silent rig
must FAIL a quiet budget, never pass it).
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SPEC = importlib.util.spec_from_file_location(
    "local_cctv_rig", os.path.join(_REPO, "scripts", "local_cctv_rig.py"))
_RIG = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_RIG)

SoakWindow = _RIG.SoakWindow
_soak_checks = _RIG._soak_checks
_soak_report = _RIG._soak_report
_soak_markdown = _RIG._soak_markdown


def _verdict(checks: list) -> str:
    return "PASS" if all(ok for _, ok, _ in checks) else "FAIL"


def test_single_partial_day_charges_only_in_window_events():
    """Pre-window events are excluded: the day is a delta from the baseline."""
    w = SoakWindow(baseline={"cam1": 5})
    w.sample("2026-09-22", "cam1", 5)   # nothing happened yet
    w.sample("2026-09-22", "cam1", 9)   # 4 fires inside the window
    w.close()
    assert w.day_counts["2026-09-22"]["cam1"] == 4
    assert w.fires_total == 4
    assert w.day_partial["2026-09-22"] is True


def test_utc_midnight_rollover_finalizes_each_day_without_double_counting():
    """used_today resets at UTC midnight; a naive running total would cap at the
    first day's value and hide the second day entirely."""
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 3)   # day 1: 3 fires
    w.sample("2026-09-23", "cam1", 2)   # day 2: counter reset, 2 fires
    w.close()
    assert w.day_counts["2026-09-22"]["cam1"] == 3
    assert w.day_counts["2026-09-23"]["cam1"] == 2
    assert w.day_partial["2026-09-22"] is True
    assert w.day_partial["2026-09-23"] is False
    assert w.fires_total == 5
    assert w.per_camera_total("cam1") == 5


def test_finalize_day_is_idempotent():
    """A day finalized twice (rollover + close) must not double-count its fires."""
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 4)
    w.finalize_day("2026-09-22")
    w.finalize_day("2026-09-22")
    w.close()
    assert w.fires_total == 4


def test_camera_appearing_mid_soak_gets_a_baseline():
    """A camera registered after the soak starts must not be charged for events
    that preceded its registration."""
    w = SoakWindow(baseline={})
    w.sample("2026-09-22", "cam1", 2)
    w.close()
    assert w.day_counts["2026-09-22"]["cam1"] == 2


def _checks(window, **over):
    """Run the verdict logic with everything healthy unless overridden."""
    kw = dict(window=window, cam_ids=["cam1"], cam_names={"cam1": "Cam"},
              offline_events={}, deaf_intervals={}, budget_per_cam_day=1,
              min_fires=1, elapsed_h=24.0, requested_h=24.0,
              deaf_window_sec=300.0)
    kw.update(over)
    return _soak_checks(**kw)


def test_partial_last_day_is_scaled_to_a_24h_rate():
    """A short-but-bursty window must still trip the budget when scaled up."""
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 1)
    w.close()
    # 1 fire in 6 h scales to 4/day > budget of 1.
    checks, _r, _w, _c = _checks(w, elapsed_h=6.0, requested_h=6.0)
    assert _verdict(checks) == "FAIL"
    assert any("false-alert budget" in n and not ok for n, ok, _ in checks)


def test_healthy_window_passes_all_checks():
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 0)   # partial day, nothing
    w.sample("2026-09-23", "cam1", 1)   # one full day, exactly at budget
    w.close()
    checks, _r, _w, complete = _checks(w)
    assert complete is True
    assert _verdict(checks) == "PASS"


def test_spam_over_budget_fails():
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 0)
    w.sample("2026-09-23", "cam1", 3)   # 3 > budget 1
    w.close()
    checks, _r, _w, _c = _checks(w)
    assert _verdict(checks) == "FAIL"
    assert any("false-alert budget" in n and not ok for n, ok, _ in checks)


def test_deaf_rig_with_zero_fires_fails_not_passes():
    """The acceptance criterion: a soak that detects nothing fails as hard as
    one that spams — a zero-fire window must not pass a quiet budget."""
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 0)
    w.close()
    checks, _r, _w, _c = _checks(w, min_fires=2)
    assert _verdict(checks) == "FAIL"
    assert any("scripted intrusions" in n and not ok for n, ok, _ in checks)


def test_offline_camera_fails():
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 1)
    w.close()
    checks, _r, _w, _c = _checks(w, offline_events={"cam1": 3})
    assert _verdict(checks) == "FAIL"
    assert any("stayed ONLINE" in n and not ok for n, ok, _ in checks)


def test_stale_last_seen_fails_deaf_guard():
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 1)
    w.close()
    checks, _r, _w, _c = _checks(w, deaf_intervals={"cam1": [600.0]})
    assert _verdict(checks) == "FAIL"
    assert any("last_seen advanced" in n and not ok for n, ok, _ in checks)


def test_partial_run_does_not_certify_the_full_window():
    """A 6 h slice of a 72 h gate reports but cannot PASS the duration check."""
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 0)
    w.close()
    checks, _r, _w, complete = _checks(w, elapsed_h=6.0, requested_h=72.0,
                                       min_fires=0)
    assert complete is False
    assert _verdict(checks) == "FAIL"
    assert any("duration" in n and not ok for n, ok, _ in checks)


def test_report_artifacts_are_written(tmp_path):
    import datetime as dt

    # A genuinely healthy window: 1 fire on one full day, exactly at budget.
    w = SoakWindow(baseline={"cam1": 0})
    w.sample("2026-09-22", "cam1", 0)   # partial opening day, nothing fired
    w.sample("2026-09-23", "cam1", 1)   # one full day at budget
    w.close()
    checks, rate, _w, complete = _checks(w)
    assert _verdict(checks) == "PASS"
    started = dt.datetime(2026, 9, 22, 12, 0, tzinfo=dt.UTC)
    ended = started + dt.timedelta(hours=24)
    rc = _soak_report(
        window=w, cam_ids=["cam1"], cam_names={"cam1": "Cam"},
        offline_events={}, deaf_intervals={}, checks=checks, window_rate=rate,
        elapsed_h=24.0, requested_h=24.0, samples=1440, started_at=started,
        ended_at=ended, tag="unit", out_dir=str(tmp_path), poll_sec=60.0,
        complete=complete, budget_per_cam_day=1, min_fires=1,
    )
    assert rc == 0
    files = os.listdir(str(tmp_path))
    assert any(f.startswith("soak_unit_") and f.endswith(".json") for f in files)
    assert any(f.startswith("soak_unit_") and f.endswith(".md") for f in files)
    with open(os.path.join(str(tmp_path), next(
            f for f in files if f.endswith(".json")))) as fh:
        report = json.load(fh)
    assert report["verdict"] == "PASS"
    assert report["budget_per_cam_day"] == 1
    assert report["min_fires_expected"] == 1
    assert report["cameras"]["cam1"]["fires_total"] == 1
    assert report["note"] == "complete window"


def test_markdown_contains_kpi_paste_line():
    report = {
        "tag": "r3", "verdict": "PASS", "note": "complete window",
        "started_at": "2026-09-22T00:00:00+00:00",
        "ended_at": "2026-09-25T00:00:00+00:00",
        "elapsed_hours": 72.0, "requested_hours": 72.0,
        "budget_per_cam_day": 1, "min_fires_expected": 2,
        "fires_total": 2, "window_rate_per_cam_day": 0.667,
        "cameras": {"cam1": {"name": "Cam", "fires_total": 2,
                             "per_utc_day": {"2026-09-22": 1, "2026-09-23": 1},
                             "offline_samples": 0, "max_stale_sec": 0.0}},
        "checks": [{"name": "c", "pass": True, "note": "n"}],
    }
    md = _soak_markdown(report)
    assert "# Soak report — r3" in md
    assert "**Verdict:** PASS" in md
    assert "`03` KPI paste" in md
    assert "0.667 alert/cam/day over 72 h (r3)" in md


# ── external-camera mode (soaking a real LAN camera) ────────────────────────
def test_ssrf_allowlist_defaults_to_loopback_only(monkeypatch):
    """The rig must keep blocking private ranges unless the operator opts in —
    loopback-only is what makes the dev rig safe against a misconfigured add."""
    monkeypatch.delenv("RIG_SSRF_ALLOWLIST", raising=False)
    assert _RIG.rig_env()["SSRF_ALLOWLIST"] == "127.0.0.0/8"


def test_ssrf_allowlist_opens_the_camera_vlan(monkeypatch):
    """RIG_SSRF_ALLOWLIST is how a real LAN camera (e.g. 192.168.x) gets past
    the SSRF guard at registration — without it the add is rejected by design.
    """
    monkeypatch.setenv("RIG_SSRF_ALLOWLIST", "192.168.0.0/16")
    assert _RIG.rig_env()["SSRF_ALLOWLIST"] == "192.168.0.0/16"


def test_soak_preflight_components_depend_on_mode():
    """Local mode demands the broker + capture (a dead capture there is exactly
    the silent failure the preflight exists to catch); external mode has
    neither, so demanding them would block a correctly-running soak."""
    assert _RIG._soak_required_components("local") == ["mediamtx", "capture", "api", "worker"]
    assert _RIG._soak_required_components("external") == ["api", "worker"]


def test_rig_mode_marker_round_trips_and_defaults_to_local(tmp_path, monkeypatch):
    monkeypatch.setattr(_RIG, "MODE_FILE", str(tmp_path / "mode"))
    assert _RIG.rig_mode() == "local"   # no marker yet → pre-existing rigs
    _RIG._write_mode("external")
    assert _RIG.rig_mode() == "external"


def test_verify_date_uses_the_utc_day_not_local():
    """Regression: cmd_verify built the timeline query date with time.strftime
    (local time), but /api/timeline filters by UTC day. On a UTC+4 box at 22:48
    UTC the local calendar day had already rolled to 09-23 while every segment
    still landed on UTC 09-22, so the probe queried an empty day and reported
    "recording segment persisted" as a spurious FAIL.
    """
    utc_plus_4 = dt.timezone(dt.timedelta(hours=4))
    assert _RIG._verify_date(dt.datetime(2026, 9, 23, 2, 48, tzinfo=utc_plus_4)) == "2026-09-22"
    assert _RIG._verify_date(dt.datetime(2026, 9, 22, 22, 48, tzinfo=dt.UTC)) == "2026-09-22"
    # The reported day only ever rolls at the UTC midnight boundary.
    assert _RIG._verify_date(dt.datetime(2026, 9, 23, 0, 0, tzinfo=dt.UTC)) == "2026-09-23"


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))

