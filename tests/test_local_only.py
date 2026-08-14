import pytest

from config import Settings
from src.feeds.aggregator import aggregate_feeds
from src.feeds.sources import fetch_otx, fetch_threatfox, fetch_urlhaus
from src.vuln.checker import run_vuln_check
from src.vuln.nvd_client import lookup_cves


@pytest.fixture
def local_only_env(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_ONLY", "true")
    monkeypatch.setenv("OTX_API_KEY", "")
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("config.get_abusech_auth_key", lambda: "")
    monkeypatch.setattr("config.has_abusech_auth_key", lambda: False)
    for module in (
        "src.feeds.sources",
        "src.feeds.nvd_feed",
        "src.feeds.cisa_kev",
        "src.feeds.cache",
        "src.vuln.nvd_client",
        "src.vuln.checker",
    ):
        monkeypatch.setattr(f"{module}.settings", settings)


def test_local_only_skips_external_feeds(local_only_env):
    urlhaus = fetch_urlhaus(force_refresh=True)
    otx = fetch_otx(force_refresh=True)
    threatfox = fetch_threatfox(force_refresh=True)
    assert urlhaus.iocs == []
    assert otx.iocs == []
    assert threatfox.iocs == []
    assert aggregate_feeds() == []


def test_local_only_returns_empty_cves(local_only_env):
    assert lookup_cves("nginx") == []


def test_local_only_real_scan_no_fake_data(local_only_env, monkeypatch):
    settings = Settings()
    monkeypatch.setattr("src.vuln.checker.settings", settings)

    result = run_vuln_check("127.0.0.1", ports=[65534])
    assert "mode" not in result
    assert result["target"] == "127.0.0.1"