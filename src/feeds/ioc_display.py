from datetime import datetime, timedelta, timezone

import pandas as pd

RECENCY_DAYS = 30
FRESH_DAYS = 7
ACTIVE_DAYS = 30
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Saturated severity palette for UI tables
SEVERITY_UI_COLORS = {
    "critical": {
        "accent": "#C62828",
        "badge_text": "#FFFFFF",
        "text": "#1A1A1A",
        "row_bg": {
            "fresh": "#FFCDD2",
            "active": "#EF9A9A",
            "older": "#E57373",
        },
    },
    "high": {
        "accent": "#F57C00",
        "badge_text": "#FFFFFF",
        "text": "#1A1A1A",
        "row_bg": {
            "fresh": "#FFE0B2",
            "active": "#FFCC80",
            "older": "#FFB74D",
        },
    },
    "medium": {
        "accent": "#F9A825",
        "badge_text": "#212121",
        "text": "#1A1A1A",
        "row_bg": {
            "fresh": "#FFF59D",
            "active": "#FFF176",
            "older": "#FFEE58",
        },
    },
    "low": {
        "accent": "#1976D2",
        "badge_text": "#FFFFFF",
        "text": "#1A1A1A",
        "row_bg": {
            "fresh": "#BBDEFB",
            "active": "#90CAF9",
            "older": "#64B5F6",
        },
    },
}

RECENCY_CHIP_COLORS = {
    "fresh": {"bg": "#2E7D32", "text": "#FFFFFF", "label": "Last 7 days"},
    "active": {"bg": "#EF6C00", "text": "#FFFFFF", "label": "8-30 days"},
    "older": {"bg": "#455A64", "text": "#FFFFFF", "label": "Older"},
}

# Legacy alias kept for any external references
RECENCY_UI_COLORS = {
    tier: f"background-color: {RECENCY_CHIP_COLORS[tier]['bg']}; color: {RECENCY_CHIP_COLORS[tier]['text']};"
    for tier in RECENCY_CHIP_COLORS
}

# PDF fill RGB highlights
RECENCY_PDF_COLORS = {
    "fresh": (212, 237, 218),
    "active": (255, 243, 205),
    "older": (233, 236, 239),
}
HIGH_RISK_PDF_COLOR = (255, 220, 220)
HIGH_RISK_SEVERITIES = {"critical", "high"}


def parse_first_seen(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def days_since_seen(row: dict) -> int | None:
    seen = parse_first_seen(row.get("first_seen"))
    if seen is None:
        return None
    return int((datetime.now(timezone.utc) - seen).total_seconds() // 86400)


def recency_tier(row: dict) -> str:
    """fresh = last 7d, active = 8-30d, older = 31+d."""
    days = days_since_seen(row)
    if days is None:
        return "older"
    if days <= FRESH_DAYS:
        return "fresh"
    if days <= ACTIVE_DAYS:
        return "active"
    return "older"


def is_recent_ioc(row: dict, *, days: int = RECENCY_DAYS) -> bool:
    seen = parse_first_seen(row.get("first_seen"))
    if seen is None:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return seen >= cutoff


def is_high_risk(row: dict) -> bool:
    return str(row.get("severity", "")).lower() in HIGH_RISK_SEVERITIES


def recency_label(row: dict) -> str:
    tier = recency_tier(row)
    if tier == "fresh":
        return "Last 7 days"
    if tier == "active":
        return "8-30 days"
    return "Older (31+ days)"


def format_last_seen(row: dict) -> str:
    seen = parse_first_seen(row.get("first_seen"))
    if seen is None:
        return "—"
    return seen.strftime("%Y-%m-%d %H:%M UTC")


def pdf_highlight_for_row(row: dict) -> tuple[tuple[int, int, int] | None, bool]:
    """Return (fill_rgb, bold) for PDF rendering."""
    tier = recency_tier(row)
    bold = is_high_risk(row)
    if tier == "fresh" and bold:
        return HIGH_RISK_PDF_COLOR, True
    if tier == "fresh":
        return RECENCY_PDF_COLORS["fresh"], bold
    if tier == "active" and bold:
        return (255, 235, 200), True
    if tier == "active":
        return RECENCY_PDF_COLORS["active"], bold
    if bold:
        return HIGH_RISK_PDF_COLOR, True
    return RECENCY_PDF_COLORS["older"], False


def enrich_ioc_row(row: dict) -> dict:
    enriched = dict(row)
    enriched["last_seen"] = format_last_seen(row)
    enriched["recency_tier"] = recency_tier(row)
    enriched["recency"] = recency_label(row)
    enriched["high_risk"] = is_high_risk(row)
    return enriched


def normalize_severity(value: str | None) -> str:
    key = str(value or "low").strip().lower()
    if key in SEVERITY_UI_COLORS:
        return key
    return "low"


def severity_palette(severity: str | None) -> dict:
    return SEVERITY_UI_COLORS[normalize_severity(severity)]


def _cell_style(
    *,
    background: str,
    text_color: str,
    accent: str,
    font_weight: str = "500",
    border_left: str | None = None,
) -> str:
    left = border_left or f"4px solid {accent}"
    return (
        f"background-color: {background}; "
        f"color: {text_color}; "
        f"font-weight: {font_weight}; "
        f"border-bottom: 1px solid {accent}; "
        f"border-left: {left}; "
        f"padding: 8px 10px;"
    )


def _severity_badge_style(palette: dict) -> str:
    accent = palette["accent"]
    return (
        f"background-color: {accent}; "
        f"color: {palette['badge_text']}; "
        f"font-weight: 700; "
        f"text-transform: uppercase; "
        f"letter-spacing: 0.05em; "
        f"border: 2px solid {accent}; "
        f"border-radius: 6px; "
        f"text-align: center; "
        f"padding: 6px 12px;"
    )


def _recency_chip_style(tier: str) -> str:
    chip = RECENCY_CHIP_COLORS.get(tier, RECENCY_CHIP_COLORS["older"])
    return (
        f"background-color: {chip['bg']}; "
        f"color: {chip['text']}; "
        f"font-weight: 600; "
        f"border-radius: 6px; "
        f"text-align: center; "
        f"padding: 5px 10px; "
        f"border: 1px solid {chip['bg']};"
    )


def _table_styles() -> list[dict]:
    return [
        {
            "selector": "thead th",
            "props": [
                ("background-color", "#263238"),
                ("color", "#FFFFFF"),
                ("font-weight", "700"),
                ("font-size", "13px"),
                ("text-transform", "uppercase"),
                ("letter-spacing", "0.06em"),
                ("border", "2px solid #37474F"),
                ("padding", "10px 12px"),
                ("text-align", "left"),
            ],
        },
        {
            "selector": "tbody td",
            "props": [
                ("border-right", "1px solid rgba(0, 0, 0, 0.12)"),
                ("font-size", "13px"),
                ("line-height", "1.35"),
            ],
        },
        {
            "selector": "table",
            "props": [
                ("border-collapse", "collapse"),
                ("border", "2px solid #37474F"),
                ("width", "100%"),
            ],
        },
    ]


def threat_table_css() -> str:
    """Extra CSS for Streamlit dataframe hover + dark-mode readability."""
    return """
    <style>
    div[data-testid="stDataFrame"] table {
        border-collapse: collapse !important;
    }
    div[data-testid="stDataFrame"] tbody tr {
        transition: filter 0.15s ease, box-shadow 0.15s ease;
    }
    div[data-testid="stDataFrame"] tbody tr:hover td {
        filter: brightness(0.94) saturate(1.08);
        box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.18);
    }
    div[data-testid="stDataFrame"] tbody tr:hover td[style*="background-color"] {
        cursor: pointer;
    }
    .stApp[data-theme="dark"] div[data-testid="stDataFrame"] tbody tr:hover td {
        filter: brightness(1.12) saturate(1.1);
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.22);
    }
    .stApp[data-theme="dark"] div[data-testid="stDataFrame"] thead th {
        background-color: #1A237E !important;
        border-color: #283593 !important;
    }
    </style>
    """


def style_dataframe_rows(df, display_columns: list[str] | None = None) -> object:
    """Apply severity + recency styling with strong contrast for Streamlit tables."""
    if df.empty:
        return df

    cols = display_columns or [c for c in df.columns if c != "recency_tier"]
    display = df[cols].copy()
    tiers = df["recency_tier"] if "recency_tier" in df.columns else None
    severities = df["severity"] if "severity" in df.columns else None

    def _style_row(row: pd.Series) -> pd.Series:
        idx = row.name
        tier = tiers.iloc[idx] if tiers is not None else recency_tier(row.to_dict())
        if tier not in {"fresh", "active", "older"}:
            tier = "older"

        sev = normalize_severity(severities.iloc[idx] if severities is not None else row.get("severity"))
        palette = SEVERITY_UI_COLORS[sev]
        row_bg = palette["row_bg"].get(tier, palette["row_bg"]["older"])
        accent = palette["accent"]
        text_color = palette["text"]
        value_weight = "700" if sev in {"critical", "high"} else "600"

        styles: dict[str, str] = {}
        for col in display.columns:
            if col == "severity":
                styles[col] = _severity_badge_style(palette)
            elif col == "recency":
                styles[col] = _recency_chip_style(tier)
            elif col == "value":
                styles[col] = _cell_style(
                    background=row_bg,
                    text_color=text_color,
                    accent=accent,
                    font_weight=value_weight,
                )
            else:
                styles[col] = _cell_style(
                    background=row_bg,
                    text_color=text_color,
                    accent=accent,
                )
        return pd.Series(styles)

    return display.style.apply(_style_row, axis=1).set_table_styles(_table_styles(), overwrite=False)