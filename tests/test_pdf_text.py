from src.reports.generator import MCCoEReportPDF, _build_pdf
from src.reports.pdf_text import sanitize_pdf_text


def test_sanitize_replaces_em_dash():
    assert sanitize_pdf_text("CVE — high risk") == "CVE - high risk"


def test_sanitize_replaces_en_dash_and_quotes():
    assert sanitize_pdf_text("“Test” – value") == '"Test" - value'


def test_sanitize_replaces_unknown_unicode():
    assert "?" in sanitize_pdf_text("Hello \u4e16\u754c world")


def test_pdf_with_unicode_content(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    from src.reports.data_collector import ReportData

    monkeypatch.setattr("src.reports.generator.REPORTS_DIR", tmp_path)
    data = ReportData(
        timestamp=datetime.now(timezone.utc),
        auto=False,
        iocs=[
            {
                "ioc_type": "ip",
                "value": "10.0.0.1",
                "severity": "high",
                "source": "test",
                "description": "Active exploit — em-dash and “smart quotes”",
            }
        ],
        alerts=[],
        vuln_scans=[],
        analysis=None,
        alert_breakdown={},
        correlations=[],
        feed_summary=[{"name": "nist_nvd", "count": 1, "cached_at": None, "stale": True, "live": False}],
        kev_highlights=[],
        nvd_highlights=[],
        network_scans=[],
    )
    output = tmp_path / "unicode_test.pdf"
    _build_pdf(data, output)
    assert output.exists()
    assert output.stat().st_size > 500
    assert sanitize_pdf_text("Test — dash") == "Test - dash"