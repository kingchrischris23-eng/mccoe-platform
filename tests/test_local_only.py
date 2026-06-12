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

    monkeypatch.setattr("config.settings", Settings())
    monkeypatch.setattr("src.feeds.sources.settings", Settings())
    monkeypatch.setattr("src.vuln.nvd_client.settings", Settings())
    monkeypatch.setattr("src.vuln.checker.settings", Settings())


def test_local_only_skips_external_feeds(local_only_env):
    assert fetch_urlhaus() == []
    assert fetch_otx() == []
    iocs = aggregate_feeds()
    assert len(iocs) >= 4
    assert all(ioc.source != "URLhaus" for ioc in iocs)


def test_local_only_uses_sample_cves(local_only_env):
    findings = lookup_cves("nginx")
    assert findings
    assert findings[0]["cve_id"].startswith("CVE-")


def test_local_only_uses_sample_vuln_scan(local_only_env, monkeypatch):
    from config import Settings

    settings = Settings()
    monkeypatch.setattr("src.vuln.checker.settings", settings)
    monkeypatch.setattr("src.vuln.checker.is_local_only", lambda: True)

    result = run_vuln_check("127.0.0.1")
    assert result["mode"] == "local_only_sample"
    assert result["open_ports"]
    assert result["cve_findings"]