from src.data_import.ioc_importer import import_iocs_from_file
from src.feeds.aggregator import aggregate_feeds


def test_import_fixture_iocs(fixtures_dir):
    iocs = import_iocs_from_file(fixtures_dir / "demo_iocs.csv")
    assert len(iocs) >= 4
    assert any(ioc.ioc_type == "ip" for ioc in iocs)


def test_aggregate_empty_without_feeds():
    iocs = aggregate_feeds()
    assert iocs == []