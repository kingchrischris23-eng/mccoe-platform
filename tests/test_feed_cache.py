import json
from datetime import datetime, timedelta, timezone

from config import Settings
from src.feeds.cache import read_cache, write_cache


def _patch_cache(monkeypatch, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.cache.settings", settings)


def test_write_and_read_fresh_cache(monkeypatch, tmp_path):
    _patch_cache(monkeypatch, tmp_path)
    write_cache("urlhaus", [{"ioc_type": "url", "value": "http://evil.test"}])
    items, meta = read_cache("urlhaus")
    assert items is not None
    assert len(items) == 1
    assert meta.stale is False


def test_stale_fallback_serves_expired_cache(monkeypatch, tmp_path):
    _patch_cache(monkeypatch, tmp_path)
    stale_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    cache_file = tmp_path / "cache" / "nist_nvd.json"
    cache_file.write_text(
        json.dumps({"cached_at": stale_time, "source": "nist_nvd", "items": [{"value": "CVE-1"}], "meta": {}}),
        encoding="utf-8",
    )
    items, meta = read_cache("nist_nvd", ttl_minutes=15, allow_stale=True)
    assert items is not None
    assert meta.stale is True


def test_stale_not_served_when_fallback_disabled(monkeypatch, tmp_path):
    _patch_cache(monkeypatch, tmp_path)
    monkeypatch.setenv("FEED_STALE_FALLBACK", "false")
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.cache.settings", settings)

    stale_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    cache_file = tmp_path / "cache" / "cisa_kev.json"
    cache_file.write_text(
        json.dumps({"cached_at": stale_time, "source": "cisa_kev", "items": [{"value": "CVE-2"}], "meta": {}}),
        encoding="utf-8",
    )
    items, meta = read_cache("cisa_kev", ttl_minutes=15)
    assert items is None
    assert meta.stale is True