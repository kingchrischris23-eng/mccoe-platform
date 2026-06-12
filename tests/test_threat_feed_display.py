import pandas as pd

from src.ui.threat_feed_display import mitigation_for_row, severity_badge


def test_severity_badge_renders_html():
    badge = severity_badge("critical")
    assert "CRITICAL" in badge
    assert "#922b21" in badge


def test_mitigation_for_cisa_kev_uses_required_action():
    row = pd.Series(
        {
            "ioc_type": "cve",
            "value": "CVE-2024-0001",
            "source": "CISA KEV",
            "description": "Test vuln | Action: Apply updates. | Due: 2026-07-01",
        }
    )
    mitigation = mitigation_for_row(row)
    assert "Apply updates." in mitigation
    assert "2026-07-01" in mitigation


def test_mitigation_for_url():
    row = pd.Series(
        {
            "ioc_type": "url",
            "value": "http://evil.example/payload.exe",
            "source": "URLhaus",
            "description": "URLhaus entry: online",
        }
    )
    mitigation = mitigation_for_row(row)
    assert "proxy" in mitigation.lower()