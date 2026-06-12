from src.feeds.aggregator import aggregate_feeds
from src.feeds.sources import load_sample_iocs


def test_sample_iocs_load():
    iocs = load_sample_iocs()
    assert len(iocs) >= 4
    assert any(ioc.ioc_type == "ip" for ioc in iocs)


def test_aggregate_dedupes():
    iocs = aggregate_feeds()
    keys = [ioc.key for ioc in iocs]
    assert len(keys) == len(set(keys))