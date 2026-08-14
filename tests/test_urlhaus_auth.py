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
    settings = Settings(abuse_ch_auth_key="", abusech_auth_key="")
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.sources.settings", settings)
    monkeypatch.setattr("config.get_abusech_auth_key", lambda: "")
    monkeypatch.setattr("config.has_abusech_auth_key", lambda: False)
    monkeypatch.setattr("src.feeds.sources.get_abusech_auth_key", lambda: "")
    monkeypatch.setattr("src.feeds.sources.has_abusech_auth_key", lambda: False)

    result = fetch_urlhaus(force_refresh=True)

    assert result.error == "missing_auth_key"
    assert result.count == 0