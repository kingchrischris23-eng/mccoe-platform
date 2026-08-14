from datetime import datetime, timedelta, timezone

from src.feeds.models import IOC
from src.reports.data_collector import collect_report_data
from src.reports.filters import ReportFilters
from src.storage.repository import count_iocs_filtered, init_db, save_iocs


def _make_ioc(index: int, *, source: str = "NIST NVD", severity: str = "high", days_ago: int = 0) -> IOC:
    seen = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return IOC(
        ioc_type="cve",
        value=f"CVE-2024-{index:04d}",
        severity=severity,
        source=source,
        first_seen=seen,
        tags=["test"],
        description=f"CVE {index}",
    )


def test_report_filters_default_max_items():
    filters = ReportFilters.defaults()
    assert filters.effective_limit() == 150
    assert filters.date_range == "30d"


def test_collect_report_data_applies_filters(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs(
        [
            _make_ioc(1, source="CISA KEV", severity="critical", days_ago=2),
            _make_ioc(2, source="NIST NVD", severity="high", days_ago=5),
            _make_ioc(3, source="NIST NVD", severity="low", days_ago=5),
            _make_ioc(4, source="MCCoE Lab Feed", severity="high", days_ago=60),
        ]
    )

    filters = ReportFilters(
        severities=["critical", "high"],
        date_range="30d",
        source="cisa_kev",
        max_items=100,
    )
    data = collect_report_data(filters=filters)

    assert data.ioc_total_count == 4
    assert data.ioc_filtered_count == 1
    assert len(data.iocs) == 1
    assert data.iocs[0]["source"] == "CISA KEV"
    assert "CISA KEV only" in data.filter_summary[2]


def test_count_and_list_support_recent_days(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs([_make_ioc(1, days_ago=3), _make_ioc(2, days_ago=40)])

    assert count_iocs_filtered(recent_days=30) == 1
    assert len(collect_report_data(filters=ReportFilters(date_range="30d")).iocs) == 1