import math

import pandas as pd
import streamlit as st

SEVERITY_COLORS = {
    "critical": "#922b21",
    "high": "#d9534f",
    "medium": "#f0ad4e",
    "low": "#5cb85c",
}

SEVERITY_ORDER = ("critical", "high", "medium", "low")
PAGE_SIZE_OPTIONS = (25, 50, 100, 200)


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(str(severity).lower(), "#6c757d")
    label = str(severity).upper()
    return (
        f"<span style='background:{color};color:white;padding:2px 8px;"
        f"border-radius:4px;font-size:0.8rem;font-weight:600;'>{label}</span>"
    )


def render_severity_summary(df: pd.DataFrame) -> None:
    counts = {level: int((df["severity"] == level).sum()) for level in SEVERITY_ORDER}
    cols = st.columns(len(SEVERITY_ORDER))
    for col, level in zip(cols, SEVERITY_ORDER):
        col.markdown(
            f"{severity_badge(level)}<br><span style='font-size:1.4rem;font-weight:700;"
            f"color:{SEVERITY_COLORS[level]}'>{counts[level]}</span>",
            unsafe_allow_html=True,
        )


def mitigation_for_row(row: pd.Series) -> str:
    ioc_type = str(row.get("ioc_type", "")).lower()
    source = str(row.get("source", ""))
    description = str(row.get("description", ""))
    value = str(row.get("value", ""))

    if source == "CISA KEV":
        action = _extract_field(description, "Action:")
        due = _extract_field(description, "Due:")
        parts = [action or "Apply vendor patch per CISA KEV guidance."]
        if due:
            parts.append(f"Remediation due by {due}.")
        parts.append("Track progress in change management and verify with Vuln Checker.")
        return " ".join(parts)

    if ioc_type == "cve" or value.upper().startswith("CVE-"):
        return (
            "Review vendor advisory, apply security patches, and validate remediation with "
            "Vuln Checker or authenticated scanning."
        )

    if ioc_type in {"url", "domain"}:
        return (
            "Block at DNS/web proxy, hunt for outbound connections in firewall and proxy logs, "
            "and isolate hosts that attempted access."
        )

    if ioc_type == "ip":
        return (
            "Block at perimeter firewall, correlate the IP in Log Analyzer, and investigate "
            "any internal hosts that communicated with it."
        )

    if ioc_type in {"hash", "md5", "sha1", "sha256"}:
        return (
            "Block hash on EDR/email gateway, scan endpoints for matching files, and "
            "quarantine affected systems pending analysis."
        )

    if ioc_type == "email":
        return "Block sender/domain, purge matching messages from mailboxes, and notify affected users."

    if ioc_type == "filename":
        return "Block execution via application control, search endpoints for matching files, and remove artifacts."

    if "phishing" in description.lower():
        return "Block indicators, reset affected credentials, and run user awareness follow-up."

    return "Validate in environment, add to blocklists, correlate with logs, and document response actions."


def _extract_field(description: str, prefix: str) -> str:
    if prefix not in description:
        return ""
    segment = description.split(prefix, 1)[1]
    return segment.split("|", 1)[0].strip()


def filter_ioc_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    st.markdown("**Filters**")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        severity = st.multiselect(
            "Severity",
            [level for level in SEVERITY_ORDER if level in df["severity"].unique()],
            default=[level for level in SEVERITY_ORDER if level in df["severity"].unique()],
        )
    with col2:
        ioc_types = sorted(df["ioc_type"].unique())
        ioc_type = st.multiselect("IOC Type", ioc_types, default=ioc_types)
    with col3:
        sources = sorted(df["source"].unique())
        source = st.multiselect("Source", sources, default=sources)
    with col4:
        search = st.text_input("Search", placeholder="Value, tags, description...")

    filtered = df[
        df["severity"].isin(severity) & df["ioc_type"].isin(ioc_type) & df["source"].isin(source)
    ]
    if search:
        needle = search.lower()
        filtered = filtered[
            filtered["value"].str.lower().str.contains(needle, na=False)
            | filtered["tags"].astype(str).str.lower().str.contains(needle, na=False)
            | filtered["description"].astype(str).str.lower().str.contains(needle, na=False)
        ]
    return filtered


def style_ioc_dataframe(df: pd.DataFrame):
    def _severity_style(value: str) -> str:
        color = SEVERITY_COLORS.get(str(value).lower(), "#6c757d")
        return f"background-color: {color}; color: white; font-weight: 600;"

    return df.style.map(_severity_style, subset=["severity"])


def paginate_dataframe(df: pd.DataFrame, *, key_prefix: str = "threat_feed") -> pd.DataFrame:
    total = len(df)
    if total == 0:
        st.info("No IOCs match the current filters.")
        return df

    page_size = st.selectbox("Rows per page", PAGE_SIZE_OPTIONS, index=1, key=f"{key_prefix}_page_size")
    total_pages = max(1, math.ceil(total / page_size))

    if f"{key_prefix}_page" not in st.session_state:
        st.session_state[f"{key_prefix}_page"] = 1

    nav1, nav2, nav3 = st.columns([1, 2, 1])
    with nav1:
        if st.button("Previous", disabled=st.session_state[f"{key_prefix}_page"] <= 1, key=f"{key_prefix}_prev"):
            st.session_state[f"{key_prefix}_page"] -= 1
            st.rerun()
    with nav2:
        st.markdown(
            f"<div style='text-align:center;padding-top:0.4rem;'>"
            f"Page <b>{st.session_state[f'{key_prefix}_page']}</b> of <b>{total_pages}</b> "
            f"({total} IOCs)</div>",
            unsafe_allow_html=True,
        )
    with nav3:
        if st.button(
            "Next",
            disabled=st.session_state[f"{key_prefix}_page"] >= total_pages,
            key=f"{key_prefix}_next",
        ):
            st.session_state[f"{key_prefix}_page"] += 1
            st.rerun()

    st.session_state[f"{key_prefix}_page"] = min(st.session_state[f"{key_prefix}_page"], total_pages)
    start = (st.session_state[f"{key_prefix}_page"] - 1) * page_size
    return df.iloc[start : start + page_size]


def render_ioc_table(df: pd.DataFrame) -> None:
    if df.empty:
        return

    filtered = filter_ioc_dataframe(df)
    st.metric("Visible IOCs", len(filtered))

    if filtered.empty:
        st.info("No IOCs match the current filters.")
        return

    render_severity_summary(filtered)
    page = paginate_dataframe(filtered)
    display = page.copy()
    display["mitigation"] = display.apply(mitigation_for_row, axis=1)
    display = display[
        ["ioc_type", "value", "severity", "source", "tags", "description", "mitigation"]
    ]

    st.dataframe(
        style_ioc_dataframe(display),
        use_container_width=True,
        hide_index=True,
        column_config={
            "ioc_type": st.column_config.TextColumn("Type", width="small"),
            "value": st.column_config.TextColumn("IOC", width="medium"),
            "severity": st.column_config.TextColumn("Severity", width="small"),
            "source": st.column_config.TextColumn("Source", width="small"),
            "tags": st.column_config.TextColumn("Tags", width="small"),
            "description": st.column_config.TextColumn("Description", width="large"),
            "mitigation": st.column_config.TextColumn("Mitigation", width="large"),
        },
    )

    with st.expander("IOC detail & mitigation", expanded=False):
        options = page["value"].tolist()
        selected = st.selectbox("Select IOC", options, key="threat_feed_detail_select")
        if selected:
            row = page[page["value"] == selected].iloc[0]
            st.markdown(f"**Severity:** {severity_badge(row['severity'])}", unsafe_allow_html=True)
            st.write(f"**Type:** `{row['ioc_type']}`")
            st.write(f"**Source:** {row['source']}")
            st.write(f"**Tags:** {row['tags']}")
            st.write(f"**Description:** {row['description']}")
            st.success(mitigation_for_row(row))