from datetime import datetime, timezone

from config import Settings
from src.feeds.models import IOC
from src.reports.data_collector import collect_report_data
from src.reports.markdown import render_markdown_content
from src.storage.repository import init_db, save_iocs


def _make_ioc(index: int) -> IOC:
    return IOC(
        ioc_type="cve",
        value=f"CVE-2024-{index:04d}",
        severity="high",
        source="NIST NVD",
        first_seen=datetime.now(timezone.utc),
        tags=["nvd"],
        description=f"CVE {index}",
    )


def test_report_caps_iocs_and_notes_total(monkeypatch, tmp_path):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("config.settings", Settings(max_iocs_report=5000))
    init_db()
    save_iocs([_make_ioc(i) for i in range(250)])

    data = collect_report_data()
    assert data.ioc_total_count == 250
    assert data.ioc_filtered_count == 250
    assert len(data.iocs) == 150
    assert data.ioc_report_limit == 150

    md = render_markdown_content(data)
    assert "250" in md
    assert "Recently Added" in md or "Last 7 days" in md