from datetime import datetime, timezone

import pandas as pd

from src.feeds.ioc_display import (
    SEVERITY_UI_COLORS,
    enrich_ioc_row,
    normalize_severity,
    severity_palette,
    style_dataframe_rows,
    threat_table_css,
)


def _sample_row(severity: str = "critical", *, days_ago: int = 1) -> dict:
    seen = datetime.now(timezone.utc)
    if days_ago:
        from datetime import timedelta

        seen = seen - timedelta(days=days_ago)
    return enrich_ioc_row(
        {
            "ioc_type": "cve",
            "value": "CVE-2024-0001",
            "severity": severity,
            "source": "CISA KEV",
            "first_seen": seen.isoformat(),
            "tags": "kev",
            "description": "Test CVE",
        }
    )


def test_normalize_severity_defaults_unknown_to_low():
    assert normalize_severity("unknown") == "low"
    assert normalize_severity("CRITICAL") == "critical"


def test_severity_palette_uses_saturated_accents():
    assert severity_palette("critical")["accent"] == "#C62828"
    assert severity_palette("high")["accent"] == "#F57C00"
    assert severity_palette("medium")["accent"] == "#F9A825"
    assert severity_palette("low")["accent"] == "#1976D2"


def test_style_dataframe_applies_severity_colors():
    rows = [_sample_row("critical"), _sample_row("low", days_ago=40)]
    styled = style_dataframe_rows(pd.DataFrame(rows), display_columns=list(rows[0].keys()))
    html = styled.to_html()
    assert "#C62828" in html
    assert "#1976D2" in html
    assert "font-weight: 700" in html


def test_style_dataframe_includes_table_header_and_borders():
    rows = [_sample_row("high")]
    styled = style_dataframe_rows(pd.DataFrame(rows))
    html = styled.to_html()
    assert "#263238" in html
    assert "border-left" in html


def test_threat_table_css_includes_hover_and_dark_mode():
    css = threat_table_css()
    assert "tbody tr:hover" in css
    assert 'data-theme="dark"' in css


def test_all_severities_have_row_backgrounds_per_recency():
    for sev, palette in SEVERITY_UI_COLORS.items():
        assert set(palette["row_bg"].keys()) == {"fresh", "active", "older"}