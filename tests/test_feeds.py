from src.data_import.ioc_importer import import_iocs_from_file
from src.feeds.aggregator import aggregate_feeds


def test_import_fixture_iocs(fixtures_dir):
    iocs = import_iocs_from_file(fixtures_dir / "demo_iocs.csv")
    assert len(iocs) >= 4
    assert any(ioc.ioc_type == "ip" for ioc in iocs)


def test_aggregate_empty_without_feeds(monkeypatch, tmp_path):
    from config import Settings

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    settings = Settings(
        local_only=True,
        enable_urlhaus=False,
        enable_otx=False,
        enable_threatfox=False,
        enable_nvd_feed=False,
        enable_cisa_kev=False,
    )
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)
    monkeypatch.setattr("config.settings", settings)
    for module in ("src.feeds.sources", "src.feeds.nvd_feed", "src.feeds.cisa_kev", "src.feeds.cache"):
        monkeypatch.setattr(f"{module}.settings", settings)
    iocs = aggregate_feeds()
    assert iocs == []


def test_aggregator_dedupes_cve(monkeypatch, tmp_path):
    from datetime import datetime, timezone

    from src.feeds.aggregator import refresh_feeds
    from src.feeds.cache import write_cache
    from src.feeds.common import ioc_to_dict
    from src.feeds.models import IOC

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)

    now = datetime.now(timezone.utc)
    nvd_ioc = IOC("cve", "CVE-2024-1111", "high", "NIST NVD", now, ["nvd"], "NVD desc")
    kev_ioc = IOC("cve", "CVE-2024-1111", "critical", "CISA KEV", now, ["kev"], "KEV desc")
    write_cache("nist_nvd", [ioc_to_dict(nvd_ioc)], source="NIST NVD")
    write_cache("cisa_kev", [ioc_to_dict(kev_ioc)], source="CISA KEV")

    result = refresh_feeds(force_refresh=False)
    assert result.total == 1
    assert result.iocs[0].severity == "critical"
    assert "kev" in result.iocs[0].tags