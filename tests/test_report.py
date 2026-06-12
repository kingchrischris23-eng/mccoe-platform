from src.feeds.sources import load_sample_iocs
from src.logs.detectors import detect_alerts
from src.logs.parser import load_sample_log, parse_log_file
from src.reports.charts import alert_breakdown_pie, vulnerability_risk_bar
from src.reports.generator import (
    generate_threat_report,
    generate_threat_report_markdown,
    generate_threat_reports,
)
from src.reports.markdown import render_markdown_content
from src.reports.data_collector import collect_report_data
from src.storage.repository import create_log_session, init_db, save_alerts, save_iocs, save_log_entries, save_vuln_scan


def _seed_report_data():
    init_db()
    save_iocs(load_sample_iocs())
    entries = parse_log_file(load_sample_log())
    alerts = detect_alerts(entries)
    session_id = create_log_session("apache_attack.log")
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
    save_vuln_scan(
        {
            "target": "localhost",
            "open_ports": [{"port": 443, "service": "https"}],
            "header_issues": [],
            "cve_findings": [{"cve_id": "CVE-2024-0002", "score": 5.0, "description": "test"}],
            "risk_score": 28.0,
        }
    )


def test_generate_pdf_report(tmp_path, monkeypatch):
    monkeypatch.setattr("src.reports.generator.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.reports.markdown.REPORTS_DIR", tmp_path)
    _seed_report_data()

    report_path = generate_threat_report(auto=True)
    assert report_path.exists()
    assert report_path.suffix == ".pdf"
    assert report_path.stat().st_size > 1500


def test_generate_markdown_report(tmp_path, monkeypatch):
    monkeypatch.setattr("src.reports.generator.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.reports.markdown.REPORTS_DIR", tmp_path)
    _seed_report_data()

    report_path = generate_threat_report_markdown(auto=True)
    content = report_path.read_text(encoding="utf-8")
    assert report_path.suffix == ".md"
    assert "Missouri Cybersecurity Center of Excellence" in content
    assert "Training Notes" in content
    assert "Risk Scoring Legend" in content


def test_generate_both_formats(tmp_path, monkeypatch):
    monkeypatch.setattr("src.reports.generator.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.reports.markdown.REPORTS_DIR", tmp_path)
    _seed_report_data()

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


def test_markdown_includes_ioc_explanations():
    data = collect_report_data()
    content = render_markdown_content(data)
    if data.iocs:
        assert "ip" in content.lower() or "domain" in content.lower()
    assert "FOR TRAINING PURPOSES ONLY" in content