import pytest

from src.feeds.aggregator import aggregate_feeds
from src.feeds.sources import fetch_otx, fetch_urlhaus
from src.vuln.checker import run_vuln_check
from src.vuln.nvd_client import lookup_cves


@pytest.fixture
def local_only_env(monkeypatch):
    monkeypatch.setenv("LOCAL_ONLY", "true")
    monkeypatch.setenv("OTX_API_KEY", "fake-key-should-not-be-used")
    from config import Settings

    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.sources.settings", settings)
    monkeypatch.setattr("src.vuln.nvd_client.settings", settings)
    monkeypatch.setattr("src.vuln.checker.settings", settings)


def test_local_only_skips_external_feeds(local_only_env):
    assert fetch_urlhaus() == []
    assert fetch_otx() == []
    assert aggregate_feeds() == []


def test_local_only_returns_empty_cves(local_only_env):
    assert lookup_cves("nginx") == []


def test_local_only_real_scan_no_fake_data(local_only_env, monkeypatch):
    from config import Settings

    settings = Settings()
    monkeypatch.setattr("src.vuln.checker.settings", settings)

    result = run_vuln_check("127.0.0.1", ports=[65534])
    assert "mode" not in result
    assert result["target"] == "127.0.0.1"