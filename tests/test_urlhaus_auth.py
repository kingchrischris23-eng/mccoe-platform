from config import Settings
from src.feeds.sources import fetch_urlhaus


def test_urlhaus_requires_auth_key(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_ONLY", "false")
    monkeypatch.setenv("ENABLE_LIVE_FEEDS", "true")
    monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.sources.settings", settings)

    result = fetch_urlhaus(force_refresh=True)

    assert result.error == "missing_api_key"
    assert result.count == 0