import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import config
from config import Settings, ensure_settings_compat, get_auto_feed_refresh_hours, is_auto_feed_refresh_enabled
from src.feeds.models import FeedResult, FeedSourceResult
from src.monitoring.refresh import quick_refresh_all
from src.monitoring.scheduler import maybe_run_scheduled_feed_refresh
from src.monitoring.state import STATE_PATH, read_monitoring_state, update_monitoring_state
from src.monitoring.status import (
    compute_feed_health,
    format_relative_time,
    format_time_until,
    get_dashboard_status,
)


def _patch_state(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    state_path = cache_dir / "monitoring_state.json"
    monkeypatch.setattr("src.monitoring.state.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.monitoring.state.STATE_PATH", state_path)
    return state_path


def test_ensure_settings_compat_patches_missing_fields(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("ENABLE_AUTO_FEED_REFRESH", "false")
    monkeypatch.setenv("AUTO_FEED_REFRESH_HOURS", "24")
    stale = SimpleNamespace(local_only=True)
    ensure_settings_compat(stale)
    assert hasattr(stale, "enable_auto_feed_refresh")
    assert stale.enable_auto_feed_refresh is False
    assert stale.auto_feed_refresh_hours == 24


def test_stale_settings_singleton_accessors(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("ENABLE_AUTO_FEED_REFRESH", "false")
    monkeypatch.setenv("AUTO_FEED_REFRESH_HOURS", "24")
    stale = SimpleNamespace(
        local_only=True,
        enable_live_feeds=False,
        enable_auto_feed_refresh=False,
        auto_feed_refresh_hours=24,
    )
    monkeypatch.setattr(config, "settings", stale)
    assert is_auto_feed_refresh_enabled() is False
    assert get_auto_feed_refresh_hours() == 24


def test_format_relative_time_never():
    assert format_relative_time(None) == "never"


def test_format_relative_time_hours_ago():
    past = datetime.now(timezone.utc) - timedelta(hours=2, minutes=5)
    assert format_relative_time(past) == "2 hours ago"


def test_format_time_until_future():
    future = datetime.now(timezone.utc) + timedelta(hours=3)
    assert format_time_until(future) == "in 3 hours"


def test_format_time_until_due_now():
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    assert format_time_until(past) == "due now"


def test_update_and_read_monitoring_state(monkeypatch, tmp_path):
    state_path = _patch_state(monkeypatch, tmp_path)
    update_monitoring_state(last_feed_refresh="2026-01-01T00:00:00+00:00")
    assert state_path.exists()
    state = read_monitoring_state()
    assert state["last_feed_refresh"] == "2026-01-01T00:00:00+00:00"
    assert "updated_at" in state


def test_compute_feed_health_disabled(monkeypatch):
    settings = Settings(local_only=True, enable_live_feeds=False)
    monkeypatch.setattr("src.monitoring.status.settings", settings)
    monkeypatch.setattr("src.monitoring.status.can_refresh_live", lambda: False)
    label, detail = compute_feed_health()
    assert label == "Disabled"


def test_compute_feed_health_healthy(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    now = datetime.now(timezone.utc).isoformat()
    for name in ("urlhaus", "nist_nvd", "cisa_kev"):
        (cache_dir / f"{name}.json").write_text(
            json.dumps({"cached_at": now, "source": name, "items": [{"value": "x"}], "meta": {}}),
            encoding="utf-8",
        )

    settings = Settings(
        local_only=False,
        enable_live_feeds=True,
        enable_urlhaus=True,
        enable_otx=False,
        enable_threatfox=False,
        enable_nvd_feed=True,
        enable_cisa_kev=True,
        feed_cache_ttl_minutes=60,
    )
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.cache.settings", settings)
    monkeypatch.setattr("src.monitoring.status.settings", settings)
    monkeypatch.setattr("src.monitoring.status.can_refresh_live", lambda: True)

    label, detail = compute_feed_health()
    assert label == "Healthy"
    assert "3/3" in detail


def test_get_dashboard_status_includes_scan_time(monkeypatch, tmp_path):
    _patch_state(monkeypatch, tmp_path)
    update_monitoring_state(last_feed_refresh=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
    monkeypatch.setattr("src.monitoring.status.is_auto_feed_refresh_enabled", lambda: True)
    monkeypatch.setattr("src.monitoring.status.get_auto_feed_refresh_hours", lambda: 24)
    monkeypatch.setattr("src.monitoring.status.can_refresh_live", lambda: True)
    monkeypatch.setattr("src.monitoring.status.compute_feed_health", lambda: ("Healthy", "ok"))
    monkeypatch.setattr("src.monitoring.status.list_network_scans", lambda limit=1: [])

    status = get_dashboard_status()
    assert status.feed_health == "Healthy"
    assert status.last_feed_refresh == "1 hour ago"
    assert status.auto_refresh_enabled is True


def test_quick_refresh_all_mocks_feeds_and_scan(monkeypatch, tmp_path):
    _patch_state(monkeypatch, tmp_path)
    feed_result = FeedResult(
        iocs=[],
        sources=[FeedSourceResult(name="urlhaus", count=2)],
    )
    monkeypatch.setattr("src.monitoring.refresh.can_refresh_live", lambda: True)
    monkeypatch.setattr("src.monitoring.refresh.refresh_feeds", lambda force_refresh=False: feed_result)
    monkeypatch.setattr("src.monitoring.refresh.save_iocs", lambda iocs: None)
    monkeypatch.setattr(
        "src.monitoring.refresh.run_network_scan",
        lambda target, port_range, scan_type: {
            "target": target,
            "summary": "1 host(s) up, 0 open port(s)",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    monkeypatch.setattr("src.monitoring.refresh.allowed_targets", lambda: ["127.0.0.1"])

    result = quick_refresh_all()
    assert result["feeds"]["count"] == 0
    assert result["scan"]["target"] == "127.0.0.1"
    assert not result["errors"]
    state = read_monitoring_state()
    assert "last_quick_refresh" in state
    assert "last_network_scan" in state
    assert "last_feed_refresh" in state


def test_quick_refresh_skips_feeds_when_disabled(monkeypatch, tmp_path):
    _patch_state(monkeypatch, tmp_path)
    monkeypatch.setattr("src.monitoring.refresh.can_refresh_live", lambda: False)
    monkeypatch.setattr(
        "src.monitoring.refresh.run_network_scan",
        lambda target, port_range, scan_type: {
            "target": target,
            "summary": "scan ok",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    monkeypatch.setattr("src.monitoring.refresh.allowed_targets", lambda: ["127.0.0.1"])

    result = quick_refresh_all()
    assert result["feeds"]["skipped"] is True
    assert result["scan"]["summary"] == "scan ok"


def test_scheduler_starts_thread_when_due(monkeypatch, tmp_path):
    _patch_state(monkeypatch, tmp_path)
    monkeypatch.setattr("src.monitoring.scheduler.is_auto_feed_refresh_enabled", lambda: True)
    monkeypatch.setattr("src.monitoring.scheduler.get_auto_feed_refresh_hours", lambda: 24)
    monkeypatch.setattr("src.monitoring.scheduler.can_refresh_live", lambda: True)

    with patch("src.monitoring.scheduler.threading.Thread") as thread_cls:
        thread = MagicMock()
        thread.is_alive.return_value = False
        thread_cls.return_value = thread
        started = maybe_run_scheduled_feed_refresh()
        assert started is True
        thread_cls.assert_called_once()
        thread.start.assert_called_once()


def test_scheduler_skips_when_not_due(monkeypatch, tmp_path):
    _patch_state(monkeypatch, tmp_path)
    update_monitoring_state(last_feed_refresh=datetime.now(timezone.utc).isoformat())
    monkeypatch.setattr("src.monitoring.scheduler.is_auto_feed_refresh_enabled", lambda: True)
    monkeypatch.setattr("src.monitoring.scheduler.get_auto_feed_refresh_hours", lambda: 24)
    monkeypatch.setattr("src.monitoring.scheduler.can_refresh_live", lambda: True)

    assert maybe_run_scheduled_feed_refresh() is False