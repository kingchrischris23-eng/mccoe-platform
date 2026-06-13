import json
from datetime import datetime, timezone

from src.feeds.models import IOC
from src.storage.data_clear import execute_clear, preview_clear
from src.storage.repository import (
    create_log_session,
    init_db,
    save_alerts,
    save_iocs,
    save_report,
    save_vuln_scan,
)


def _seed_data(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    cache_dir = tmp_path / "cache"
    reports_dir = tmp_path / "reports"
    scans_dir = tmp_path / "scans"
    for path in (cache_dir, reports_dir, scans_dir):
        path.mkdir(parents=True)
    (cache_dir / "nist_nvd.json").write_text('{"items": []}', encoding="utf-8")
    (cache_dir / "cisa_kev.json").write_text('{"items": []}', encoding="utf-8")
    (reports_dir / "report.pdf").write_bytes(b"%PDF-1.4")
    (scans_dir / "scan.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr("config.DB_PATH", db_path)
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("config.REPORTS_DIR", reports_dir)
    monkeypatch.setattr("config.SCANS_DIR", scans_dir)
    monkeypatch.setattr("src.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("src.storage.data_clear.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.storage.data_clear.REPORTS_DIR", reports_dir)
    monkeypatch.setattr("src.storage.data_clear.SCANS_DIR", scans_dir)

    init_db()
    now = datetime.now(timezone.utc)
    save_iocs(
        [
            IOC("cve", "CVE-2024-0001", "high", "NIST NVD", now, ["nvd"], "feed"),
            IOC("ip", "1.2.3.4", "medium", "MCCoE Lab Feed", now, ["lab"], "manual"),
        ]
    )
    session_id = create_log_session("sample.log")
    save_alerts(
        session_id,
        [
            {
                "rule_id": "r1",
                "rule_name": "Brute Force",
                "severity": "high",
                "source_ip": "1.2.3.4",
                "message": "test",
                "matched_line": "line",
                "remediation": "",
                "created_at": now.isoformat(),
            }
        ],
    )
    save_vuln_scan(
        {
            "target": "127.0.0.1",
            "scanned_at": now.isoformat(),
            "open_ports": [],
            "header_issues": [],
            "cve_findings": [],
            "risk_score": 1.0,
        }
    )
    save_report(
        {
            "filename": "report.pdf",
            "generated_at": now.isoformat(),
            "summary": "test",
            "ioc_count": 1,
            "alert_count": 1,
            "vuln_count": 1,
        }
    )


def test_preview_clear_counts(tmp_path, monkeypatch):
    _seed_data(tmp_path, monkeypatch)
    preview = preview_clear(["all_user_data"])
    assert preview.feed_iocs == 1
    assert preview.manual_iocs == 1
    assert preview.alerts == 1
    assert preview.reports == 1
    assert preview.report_files == 1


def test_execute_clear_manual_iocs_only(tmp_path, monkeypatch):
    _seed_data(tmp_path, monkeypatch)
    result = execute_clear(["manual_iocs"])
    assert result.manual_iocs == 1
    preview = preview_clear(["manual_iocs"])
    assert preview.manual_iocs == 0
    feed_preview = preview_clear(["feed_cache"])
    assert feed_preview.feed_iocs == 1


def test_execute_clear_feed_cache(tmp_path, monkeypatch):
    _seed_data(tmp_path, monkeypatch)
    result = execute_clear(["feed_cache"])
    assert result.feed_iocs == 1
    assert result.feed_cache_files >= 2
    assert not (tmp_path / "cache" / "nist_nvd.json").exists()


def test_execute_clear_all_user_data(tmp_path, monkeypatch):
    _seed_data(tmp_path, monkeypatch)
    result = execute_clear(["all_user_data"])
    assert "feed_cache" in result.categories
    assert "reports" in result.categories
    preview = preview_clear(["all_user_data"])
    assert preview.total_items == 0