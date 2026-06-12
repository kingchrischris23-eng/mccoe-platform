from src.data_import.ioc_importer import import_iocs_from_file
from src.logs.detectors import detect_alerts
from src.logs.parser import parse_log_file
from src.reports.charts import alert_breakdown_pie, vulnerability_risk_bar
from src.reports.generator import (
    generate_threat_report,
    generate_threat_report_markdown,
    generate_threat_reports,
)
from src.storage.repository import create_log_session, init_db, save_alerts, save_iocs, save_log_entries, save_vuln_scan


def _seed_report_data(fixtures_dir, tmp_path, monkeypatch):
    monkeypatch.setattr("src.reports.generator.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.reports.markdown.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs(import_iocs_from_file(fixtures_dir / "demo_iocs.csv"))
    content = (fixtures_dir / "demo_attack.log").read_text(encoding="utf-8")
    entries = parse_log_file(content)
    alerts = detect_alerts(entries)
    session_id = create_log_session("demo_attack.log")
    save_log_entries(session_id, entries)
    save_alerts(session_id, alerts)
    save_vuln_scan(
        {
            "target": "127.0.0.1",
            "open_ports": [{"port": 80, "service": "http"}],
            "header_issues": [],
            "cve_findings": [{"cve_id": "CVE-2024-0001", "score": 7.5, "description": "test"}],
            "risk_score": 42.0,
        }
    )


def test_generate_pdf_report(fixtures_dir, tmp_path, monkeypatch):
    _seed_report_data(fixtures_dir, tmp_path, monkeypatch)
    report_path = generate_threat_report(auto=True)
    assert report_path.exists()
    assert report_path.suffix == ".pdf"
    assert report_path.stat().st_size > 1500


def test_generate_markdown_report(fixtures_dir, tmp_path, monkeypatch):
    _seed_report_data(fixtures_dir, tmp_path, monkeypatch)
    report_path = generate_threat_report_markdown(auto=True)
    content = report_path.read_text(encoding="utf-8")
    assert report_path.suffix == ".md"
    assert "Missouri Cybersecurity Center of Excellence" in content


def test_generate_empty_report(tmp_path, monkeypatch):
    monkeypatch.setattr("src.reports.generator.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.reports.markdown.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("config.DB_PATH", tmp_path / "empty.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "empty.db")
    init_db()
    report_path = generate_threat_report(auto=False)
    assert report_path.exists()


def test_generate_both_formats(fixtures_dir, tmp_path, monkeypatch):
    _seed_report_data(fixtures_dir, tmp_path, monkeypatch)
    paths = generate_threat_reports(auto=True)
    assert paths["pdf"].exists()
    assert paths["markdown"].exists()


def test_chart_generation(tmp_path):
    pie = alert_breakdown_pie({"Brute Force": 3, "SQLi": 2}, tmp_path / "pie.png")
    bar = vulnerability_risk_bar(
        [{"target": "127.0.0.1", "risk_score": 55}, {"target": "localhost", "risk_score": 30}],
        tmp_path / "bar.png",
    )
    assert pie and pie.exists()
    assert bar and bar.exists()