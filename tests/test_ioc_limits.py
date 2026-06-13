from datetime import datetime, timedelta, timezone

from config import Settings, get_max_iocs_report
from src.feeds.ioc_display import is_recent_ioc, recency_label, recency_tier
from src.feeds.models import IOC
from src.storage.repository import (
    count_iocs_filtered,
    init_db,
    list_ioc_distinct,
    list_ioc_values,
    list_iocs,
    list_iocs_filtered,
    save_iocs,
)


def _make_ioc(index: int, source: str = "test", *, days_ago: int = 0) -> IOC:
    seen = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return IOC(
        ioc_type="cve",
        value=f"CVE-2024-{index:04d}",
        severity="high" if index % 2 else "critical",
        source=source,
        first_seen=seen,
        tags=["test"],
        description=f"IOC {index}",
    )


def test_list_iocs_unlimited_by_default(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(i) for i in range(350)])

    assert len(list_iocs()) == 350


def test_pagination_and_sort_newest(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(i, days_ago=i) for i in range(5)])

    page1 = list_iocs_filtered(limit=2, offset=0, sort="newest")
    page2 = list_iocs_filtered(limit=2, offset=2, sort="newest")
    assert len(page1) == 2
    assert len(page2) == 2
    assert page1[0]["value"] == "CVE-2024-0000"


def test_sort_risk_orders_critical_first(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(1), _make_ioc(2), _make_ioc(3)])

    rows = list_iocs_filtered(sort="risk", limit=10)
    assert rows[0]["severity"] == "critical"


def test_search_filter(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(1), _make_ioc(99)])

    rows = list_iocs_filtered(search="0099")
    assert len(rows) == 1
    assert rows[0]["value"] == "CVE-2024-0099"


def test_count_recent_iocs(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(1, days_ago=1), _make_ioc(2, days_ago=40)])

    assert count_iocs_filtered(recent_days=30) == 1


def test_recency_tiers(monkeypatch, tmp_path):
    fresh = _make_ioc(1, days_ago=3)
    active = _make_ioc(2, days_ago=15)
    old = _make_ioc(3, days_ago=60)
    assert recency_tier({"first_seen": fresh.first_seen.isoformat()}) == "fresh"
    assert recency_tier({"first_seen": active.first_seen.isoformat()}) == "active"
    assert recency_tier({"first_seen": old.first_seen.isoformat()}) == "older"
    assert is_recent_ioc({"first_seen": fresh.first_seen.isoformat()})
    assert recency_label({"first_seen": fresh.first_seen.isoformat()}) == "Last 7 days"
    assert recency_label({"first_seen": active.first_seen.isoformat()}) == "8-30 days"
    assert recency_label({"first_seen": old.first_seen.isoformat()}) == "Older (31+ days)"


def test_list_ioc_values_unlimited(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(i) for i in range(6)])
    save_iocs([_make_ioc(i + 100) for i in range(150)])
    assert len(list_ioc_values()) == 156


def test_get_max_iocs_report_bounds():
    assert get_max_iocs_report() >= 5000


def test_recency_tier_sql_filter(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(1, days_ago=2), _make_ioc(2, days_ago=20), _make_ioc(3, days_ago=90)])

    assert count_iocs_filtered(recency_tier="fresh") == 1
    assert count_iocs_filtered(recency_tier="active") == 1
    assert count_iocs_filtered(recency_tier="older") == 1


def test_list_ioc_distinct(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(1, "NIST NVD"), _make_ioc(2, "CISA KEV")])

    assert "high" in list_ioc_distinct("severity")
    assert "cve" in list_ioc_distinct("ioc_type")


def test_explicit_limit_overrides_unlimited(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(i) for i in range(8)])
    assert len(list_iocs(limit=3)) == 3