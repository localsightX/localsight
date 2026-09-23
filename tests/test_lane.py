"""R4.1 gate-access LPR schema: lanes, the keyed-HMAC plate whitelist, allow
windows, and the per-camera pipeline switches (off by default).

Covers the invariants the roadmap acceptance criteria depend on: deny-by-
default matching against the same plate-hash token space the ANPR pipeline
emits, deletion cascading away a retired camera's lane config, and the
additive `pipeline_flags` column surviving an in-place upgrade.
"""
from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from apps.api.bootstrap import _ensure_columns
from packages.domain.lane import is_within_window, pipeline_flag_enabled
from packages.domain.models import (
    PIPELINE_FLAG_LANE_ACCESS,
    Camera,
    Lane,
    LaneWhitelistEntry,
)

_TUE_MORNING = dt.datetime(2026, 9, 22, 9, 30, tzinfo=dt.timezone.utc)  # Tue 09:30 UTC
_TUE_EVENING = dt.datetime(2026, 9, 22, 18, 0, tzinfo=dt.timezone.utc)  # Tue 18:00 UTC
_SUN_MORNING = dt.datetime(2026, 9, 27, 10, 0, tzinfo=dt.timezone.utc)  # Sun 10:00 UTC


# ── per-camera analytic switches: off unless explicitly enabled ─────────────


def test_pipeline_flag_enabled_requires_explicit_true():
    assert pipeline_flag_enabled(None, PIPELINE_FLAG_LANE_ACCESS) is False
    assert pipeline_flag_enabled({}, PIPELINE_FLAG_LANE_ACCESS) is False
    assert pipeline_flag_enabled({"anpr": True}, PIPELINE_FLAG_LANE_ACCESS) is False
    assert pipeline_flag_enabled({PIPELINE_FLAG_LANE_ACCESS: False}, PIPELINE_FLAG_LANE_ACCESS) is False
    # Strict: a truthy non-bool must not silently arm an analytic.
    assert pipeline_flag_enabled({PIPELINE_FLAG_LANE_ACCESS: "true"}, PIPELINE_FLAG_LANE_ACCESS) is False
    assert pipeline_flag_enabled({PIPELINE_FLAG_LANE_ACCESS: True}, PIPELINE_FLAG_LANE_ACCESS) is True


# ── allow windows ───────────────────────────────────────────────────────────


def test_is_within_window_none_is_unrestricted():
    assert is_within_window(_TUE_MORNING, None) is True


def test_is_within_window_daytime_bounds():
    window = {"start": "09:00", "end": "17:00"}
    assert is_within_window(_TUE_MORNING, window) is True
    # end is exclusive
    assert is_within_window(dt.datetime(2026, 9, 22, 17, 0, tzinfo=dt.timezone.utc), window) is False
    assert is_within_window(_TUE_EVENING, window) is False


def test_is_within_window_overnight_wraps_midnight():
    window = {"start": "17:00", "end": "07:00"}
    assert is_within_window(_TUE_EVENING, window) is True
    assert is_within_window(dt.datetime(2026, 9, 22, 2, 0, tzinfo=dt.timezone.utc), window) is True
    assert is_within_window(_TUE_MORNING, window) is False  # 09:30 is outside


def test_is_within_window_day_filter():
    window = {"start": "09:00", "end": "17:00", "days": [1, 2, 3, 4, 5]}
    assert is_within_window(_TUE_MORNING, window) is True    # Tuesday
    assert is_within_window(_SUN_MORNING, window) is False   # Sunday


def test_is_within_window_honours_timezone():
    # 09:00-17:00 Berlin = 07:00-15:00 UTC, so 09:30 UTC sits inside.
    window = {"start": "09:00", "end": "17:00", "tz": "Europe/Berlin"}
    assert is_within_window(_TUE_MORNING, window) is True
    # ...but 16:00 UTC (18:00 local) is outside.
    assert is_within_window(dt.datetime(2026, 9, 22, 16, 0, tzinfo=dt.timezone.utc), window) is False


def test_is_within_window_malformed_denies():
    assert is_within_window(_TUE_MORNING, {}) is False                    # missing bounds
    assert is_within_window(_TUE_MORNING, {"start": "09:00"}) is False    # missing end
    assert is_within_window(_TUE_MORNING, {"start": "9", "end": "17:00"}) is False  # bad time
    assert is_within_window(_TUE_MORNING, {"start": "09:00", "end": "17:00", "tz": "Mars/Olympus_Mons"}) is False
    assert is_within_window(_TUE_MORNING, {"start": "09:00", "end": "17:00", "days": "weekday"}) is False
    assert is_within_window(_TUE_MORNING, ["09:00", "17:00"]) is False    # not a mapping


# ── schema: whitelist match, cascades, uniqueness ───────────────────────────


def _make_lane(client, plate: str = "AB12CDE") -> tuple[str, str, str]:
    rt = client.app.state.runtime
    with rt.SessionLocal() as session:
        cam = Camera(name="gate-cam")
        session.add(cam)
        session.commit()
        session.refresh(cam)
        lane = Lane(
            camera_id=cam.id,
            name="main gate",
            barrier_channel="webhook",
            armed_by="operator-1",
        )
        session.add(lane)
        session.commit()
        session.refresh(lane)
        token = rt.crypto.hmac_str(plate)
        session.add(LaneWhitelistEntry(lane_id=lane.id, plate_hash=token, label="delivery van"))
        session.commit()
        return cam.id, lane.id, token


def test_whitelist_exact_keyed_hmac_match(client):
    rt = client.app.state.runtime
    _cam_id, lane_id, token = _make_lane(client)
    with rt.SessionLocal() as session:
        # The ANPR event's detail.plate_hash joins directly against the
        # whitelist: same crypto.hmac_str token space as the R2 plate index.
        hit = (
            session.query(LaneWhitelistEntry)
            .filter(LaneWhitelistEntry.lane_id == lane_id, LaneWhitelistEntry.plate_hash == token)
            .first()
        )
        assert hit is not None
        assert hit.label == "delivery van"
        assert hit.enabled is True

        # Deny-by-default: an unknown plate has no row, so no barrier command.
        miss = (
            session.query(LaneWhitelistEntry)
            .filter(
                LaneWhitelistEntry.lane_id == lane_id,
                LaneWhitelistEntry.plate_hash == rt.crypto.hmac_str("ZZ999ZZ"),
            )
            .first()
        )
        assert miss is None


def test_deleting_camera_cascades_to_lane_and_whitelist(client):
    rt = client.app.state.runtime
    cam_id, lane_id, _token = _make_lane(client)
    with rt.SessionLocal() as session:
        session.query(Camera).filter_by(id=cam_id).delete()
        session.commit()
    with rt.SessionLocal() as session:
        assert session.query(Lane).filter_by(id=lane_id).first() is None
        assert session.query(LaneWhitelistEntry).filter_by(lane_id=lane_id).first() is None


def test_whitelist_plate_is_unique_per_lane(client):
    rt = client.app.state.runtime
    _cam_id, lane_id, token = _make_lane(client)
    with rt.SessionLocal() as session:
        session.add(LaneWhitelistEntry(lane_id=lane_id, plate_hash=token, label="duplicate"))
        with pytest.raises(IntegrityError):
            session.commit()


def test_lane_is_one_per_camera(client):
    rt = client.app.state.runtime
    with rt.SessionLocal() as session:
        cam = Camera(name="gate-cam")
        session.add(cam)
        session.commit()
        session.refresh(cam)
        camera_id = cam.id
        session.add(Lane(camera_id=camera_id, barrier_channel="webhook"))
        session.commit()

    with rt.SessionLocal() as session:
        session.add(Lane(camera_id=camera_id, barrier_channel="mqtt"))
        with pytest.raises(IntegrityError):
            session.commit()


def test_pipeline_flags_added_on_upgrade_from_legacy_db(client):
    rt = client.app.state.runtime

    def camera_columns() -> set[str]:
        return {col["name"] for col in inspect(rt.engine).get_columns("cameras")}

    # A fresh database already has the column (create_all + _ensure_columns).
    assert "pipeline_flags" in camera_columns()

    # Simulate a pre-R4.1 database: tables intact, the new column absent.
    if rt.engine.dialect.name == "sqlite" and rt.engine.dialect.dbapi.sqlite_version_info < (3, 35):
        pytest.skip("SQLite < 3.35 cannot DROP COLUMN")
    with rt.engine.begin() as conn:
        conn.execute(text("ALTER TABLE cameras DROP COLUMN pipeline_flags"))
    assert "pipeline_flags" not in camera_columns()

    # An upgrade boot must re-add it, and the swallow-list must let the other
    # (already-present) ALTERs pass without error.
    _ensure_columns(rt)
    assert "pipeline_flags" in camera_columns()
