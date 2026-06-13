import pandas as pd
import streamlit as st

from config import get_ioc_recent_days, get_ioc_ui_page_size, is_local_only
from src.api_client import DashboardAPIError
from src.feeds.aggregator import can_refresh_live, refresh_feeds
from src.feeds.kev_index import ensure_kev_index
from src.feeds.ioc_display import enrich_ioc_row, style_dataframe_rows, threat_table_css
from src.storage.repository import (
    count_iocs_filtered,
    list_ioc_distinct,
    list_iocs_filtered,
    save_iocs,
)
from src.ui.api_helpers import get_client
from src.ui.data_import import render_ioc_import_section
from src.ui.feed_settings import render_feed_settings
from src.ui.ioc_detail import render_selected_ioc_panel, show_ioc_detail_dialog

SORT_OPTIONS = {
    "Published Date (Newest)": "newest",
    "Highest Risk": "risk",
    "Published Date (Oldest)": "oldest",
}

RECENCY_FILTERS = {
    "All": None,
    "Last 7 days": "fresh",
    "8-30 days": "active",
    "Older (31+ days)": "older",
}

DISPLAY_COLUMNS = [
    "ioc_type",
    "value",
    "severity",
    "source",
    "last_seen",
    "recency",
    "tags",
    "description",
]


def render() -> None:
    st.title("Threat Feed Aggregator")
    st.write("Import your own IOCs or refresh live feeds when online.")

    if is_local_only():
        st.info(
            "Local-only mode: live refresh disabled. Cached feeds from a prior pull still display. "
            "Import IOCs via CSV/JSON or use Load Demo Data in the sidebar."
        )

    render_feed_settings()
    render_ioc_import_section()

    client = get_client()
    col1, col2 = st.columns(2)
    with col1:
        refresh_disabled = not can_refresh_live()
        if st.button("Refresh Live Feeds", type="primary", disabled=refresh_disabled):
            if client:
                try:
                    result = client.refresh_feeds()
                    st.session_state["feed_refresh"] = result
                    st.session_state["ioc_page"] = 0
                except DashboardAPIError as exc:
                    st.error(f"API error: {exc}")
            else:
                result = refresh_feeds(force_refresh=True)
                save_iocs(result.iocs)
                st.session_state["feed_refresh"] = _result_to_dict(result)
                st.session_state["ioc_page"] = 0
    with col2:
        if refresh_disabled:
            st.caption("Enable LOCAL_ONLY=false and Enable live feeds in settings.")
        else:
            st.caption(
                "Pulls OTX, URLhaus, ThreatFox, NVD, and CISA KEV into local JSON cache. "
                "See **Threat Intelligence Attribution** in feed settings."
            )

    _show_refresh_summary()
    _render_threat_intelligence_table(client)


def _render_threat_table_legend() -> None:
    st.markdown(threat_table_css(), unsafe_allow_html=True)
    st.markdown(
        """
        **Risk level colors** (row tint + severity badge):
        <span style="background:#C62828;color:#fff;padding:4px 10px;border-radius:6px;font-weight:700;margin-right:6px;">Critical</span>
        <span style="background:#F57C00;color:#fff;padding:4px 10px;border-radius:6px;font-weight:700;margin-right:6px;">High</span>
        <span style="background:#F9A825;color:#212121;padding:4px 10px;border-radius:6px;font-weight:700;margin-right:6px;">Medium</span>
        <span style="background:#1976D2;color:#fff;padding:4px 10px;border-radius:6px;font-weight:700;margin-right:12px;">Low</span>
        **Recency chips:**
        <span style="background:#2E7D32;color:#fff;padding:4px 10px;border-radius:6px;font-weight:600;margin-right:6px;">Last 7 days</span>
        <span style="background:#EF6C00;color:#fff;padding:4px 10px;border-radius:6px;font-weight:600;margin-right:6px;">8ΓÇô30 days</span>
        <span style="background:#455A64;color:#fff;padding:4px 10px;border-radius:6px;font-weight:600;">Older</span>
        """,
        unsafe_allow_html=True,
    )


def _render_recently_added() -> None:
    fresh_rows = [enrich_ioc_row(row) for row in list_iocs_filtered(limit=20, sort="newest", recency_tier="fresh")]
    if not fresh_rows:
        return

    st.markdown("#### Recently Added (Last 7 Days)")
    st.caption(f"{count_iocs_filtered(recency_tier='fresh')} indicator(s) in the last week ΓÇö showing top {len(fresh_rows)}.")
    _render_interactive_table(fresh_rows, table_key="ioc_recent_table")
    st.markdown("---")


def _selection_token(table_key: str, row: dict) -> tuple:
    return (
        table_key,
        row.get("value"),
        row.get("source"),
        row.get("ioc_type"),
        row.get("first_seen"),
    )


def _render_interactive_table(page_rows: list[dict], *, table_key: str) -> dict | None:
    if not page_rows:
        st.info("No IOCs on this page.")
        return None

    styled = style_dataframe_rows(pd.DataFrame(page_rows), DISPLAY_COLUMNS)
    event = st.dataframe(
        styled,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key=table_key,
    )

    selected: dict | None = None
    if event.selection and event.selection.rows:
        idx = event.selection.rows[0]
        if 0 <= idx < len(page_rows):
            selected = page_rows[idx]
            token = _selection_token(table_key, selected)
            if st.session_state.get("selected_ioc_token") != token:
                st.session_state["selected_ioc_token"] = token
                st.session_state["selected_ioc_row"] = selected
                show_ioc_detail_dialog(selected)

    return selected or st.session_state.get("selected_ioc_row")


def _build_filter_state() -> dict:
    filter_cols = st.columns([2, 1, 1])
    with filter_cols[0]:
        search = st.text_input(
            "Search CVE, IP, domain, hashΓÇª",
            placeholder="e.g. CVE-2024, 10.0.0.1, evil.example",
            key="ioc_search",
        ).strip()
    with filter_cols[1]:
        sort_label = st.selectbox("Sort by", list(SORT_OPTIONS.keys()), index=0)
        sort_key = SORT_OPTIONS[sort_label]
    with filter_cols[2]:
        recency_label = st.selectbox("Recency", list(RECENCY_FILTERS.keys()), index=0)
        recency_tier = RECENCY_FILTERS[recency_label]

    all_severities = list_ioc_distinct("severity")
    all_types = list_ioc_distinct("ioc_type")
    severity = st.multiselect("Severity", all_severities, default=all_severities)
    ioc_type = st.multiselect("IOC Type", all_types, default=all_types)

    state = {
        "search": search or None,
        "sort": sort_key,
        "recency_tier": recency_tier,
        "severities": severity or None,
        "ioc_types": ioc_type or None,
    }
    _sync_page_on_filter_change(state)
    return state


def _sync_page_on_filter_change(filters: dict) -> None:
    """Reset to page 1 when search/sort/filter controls change."""
    key = (
        filters.get("search"),
        filters.get("sort"),
        filters.get("recency_tier"),
        tuple(filters.get("severities") or ()),
        tuple(filters.get("ioc_types") or ()),
    )
    if st.session_state.get("ioc_filter_key") != key:
        st.session_state["ioc_filter_key"] = key
        st.session_state["ioc_page"] = 0


def _feed_source_totals() -> dict[str, int]:
    return {
        "total": count_iocs_filtered(),
        "nist": count_iocs_filtered(source="NIST NVD"),
        "cisa": count_iocs_filtered(source="CISA KEV"),
        "otx": count_iocs_filtered(source="AlienVault OTX"),
        "urlhaus": count_iocs_filtered(source="URLhaus"),
        "threatfox": count_iocs_filtered(source="ThreatFox"),
    }


def _render_totals_banner(
    start: int,
    end: int,
    filtered_total: int,
    *,
    totals: dict[str, int],
) -> None:
    st.info(
        f"**Showing {start:,}ΓÇô{end:,} of {filtered_total:,} matching IOCs** "
        f"({totals['total']:,} total ΓÇö NIST: {totals['nist']:,}, CISA KEV: {totals['cisa']:,}, "
        f"OTX: {totals['otx']:,}, URLhaus: {totals['urlhaus']:,}, ThreatFox: {totals['threatfox']:,})"
    )


def _render_pagination(page: int, total_pages: int, filtered_total: int, page_size: int) -> None:
    start = page * page_size
    end = min(start + page_size, filtered_total)

    nav1, nav2, nav3, nav4 = st.columns([1, 2, 1, 1])
    with nav1:
        if st.button("ΓùÇ Previous", disabled=page <= 0, key="ioc_prev"):
            st.session_state["ioc_page"] = page - 1
            st.rerun()
    with nav2:
        st.caption(f"Page {page + 1} of {total_pages:,} ({page_size} per page)")
    with nav3:
        if st.button("Next Γû╢", disabled=page >= total_pages - 1, key="ioc_next"):
            st.session_state["ioc_page"] = page + 1
            st.rerun()
    with nav4:
        if total_pages > 1:
            picked = st.selectbox(
                "Jump to",
                options=list(range(1, total_pages + 1)),
                index=page,
                key="ioc_page_select",
                label_visibility="collapsed",
            )
            if picked - 1 != page:
                st.session_state["ioc_page"] = picked - 1
                st.rerun()


def _render_threat_intelligence_table(client) -> None:
    page_size = get_ioc_ui_page_size()
    recent_days = get_ioc_recent_days()

    st.subheader("Threat Intelligence")
    ensure_kev_index()
    _render_threat_table_legend()
    st.caption(
        f"Paginated view ΓÇö {page_size} IOCs per page, no display cap. "
        f"Default sort: published date (newest first). "
        f"**Click a row** to open mitigation details."
    )

    totals = _feed_source_totals()
    if totals["total"] == 0 and not client:
        st.info("No IOCs yet. Import a CSV/JSON file, add one manually, refresh live feeds, or load demo data.")
        return

    _render_recently_added()

    if client:
        _render_api_threat_table(client, page_size, totals)
        return

    filters = _build_filter_state()
    filtered_total = count_iocs_filtered(
        severities=filters["severities"],
        ioc_types=filters["ioc_types"],
        search=filters["search"],
        recency_tier=filters["recency_tier"],
    )
    fresh_total = count_iocs_filtered(recency_tier="fresh")
    active_total = count_iocs_filtered(recency_tier="active")

    total_pages = max(1, (filtered_total + page_size - 1) // page_size)
    page = min(st.session_state.get("ioc_page", 0), total_pages - 1)
    st.session_state["ioc_page"] = page
    start = page * page_size
    end = min(start + page_size, filtered_total)

    _render_totals_banner(
        start + 1 if filtered_total else 0,
        end,
        filtered_total,
        totals=totals,
    )

    m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
    m1.metric("Total IOCs", f"{totals['total']:,}")
    m2.metric("NIST NVD", f"{totals['nist']:,}")
    m3.metric("CISA KEV", f"{totals['cisa']:,}")
    m4.metric("OTX", f"{totals['otx']:,}")
    m5.metric("URLhaus", f"{totals['urlhaus']:,}")
    m6.metric("ThreatFox", f"{totals['threatfox']:,}")
    m7.metric("Filtered", f"{filtered_total:,}")
    st.caption(f"Recency: {fresh_total:,} last 7d ┬╖ {active_total:,} 8ΓÇô30d")
    st.caption(f"Recent window for metrics: {recent_days} days")

    page_rows = [
        enrich_ioc_row(row)
        for row in list_iocs_filtered(
            severities=filters["severities"],
            ioc_types=filters["ioc_types"],
            search=filters["search"],
            recency_tier=filters["recency_tier"],
            sort=filters["sort"],
            limit=page_size,
            offset=page * page_size,
        )
    ]

    _render_interactive_table(page_rows, table_key="ioc_main_table")
    render_selected_ioc_panel(st.session_state.get("selected_ioc_row"))
    _render_pagination(page, total_pages, filtered_total, page_size)


def _render_api_threat_table(
    client,
    page_size: int,
    totals: dict[str, int],
) -> None:
    filters = _build_filter_state()
    page = st.session_state.get("ioc_page", 0)
    try:
        payload = client.get_threats(
            search=filters["search"],
            limit=page_size,
            offset=page * page_size,
            sort=filters["sort"],
        )
    except DashboardAPIError as exc:
        st.error(f"API error: {exc}")
        return

    api_total = payload.get("total", len(payload.get("iocs", [])))
    rows = payload.get("iocs", [])
    filtered_total = api_total
    total_pages = max(1, (filtered_total + page_size - 1) // page_size)
    page = min(page, total_pages - 1)
    st.session_state["ioc_page"] = page
    start = page * page_size
    end = min(start + len(rows), filtered_total)

    st.caption("API backend mode ΓÇö server-side pagination (no client cap).")
    api_totals = {**totals, "total": totals["total"] or filtered_total}
    _render_totals_banner(
        start + 1 if filtered_total else 0,
        end,
        filtered_total,
        totals=api_totals,
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total IOCs", f"{api_totals['total']:,}")
    m2.metric("NIST NVD", f"{api_totals['nist']:,}")
    m3.metric("CISA KEV", f"{api_totals['cisa']:,}")
    m4.metric("OTX / URLhaus / TFox", f"{api_totals['otx'] + api_totals['urlhaus'] + api_totals['threatfox']:,}")

    page_rows = [enrich_ioc_row(row) for row in rows]
    _render_interactive_table(page_rows, table_key="ioc_api_table")
    render_selected_ioc_panel(st.session_state.get("selected_ioc_row"))
    _render_pagination(page, total_pages, filtered_total, page_size)


def _show_refresh_summary() -> None:
    summary = st.session_state.get("feed_refresh")
    if not summary:
        return

    total = summary.get("total", 0)
    totals = _feed_source_totals()
    st.success(
        f"Loaded {total:,} IOC(s) from feeds. "
        f"Database now has {totals['total']:,} total "
        f"(NIST: {totals['nist']:,}, CISA: {totals['cisa']:,}, "
        f"OTX: {totals['otx']:,}, URLhaus: {totals['urlhaus']:,}, ThreatFox: {totals['threatfox']:,})."
    )
    for source in summary.get("sources", []):
        status_msg = source.get("status_message")
        if status_msg:
            if source.get("live") and source.get("count", 0) > 0:
                st.success(status_msg)
            elif source.get("rate_limited") or (source.get("error") and source.get("count", 0)):
                st.warning(status_msg)
            elif source.get("error"):
                st.error(status_msg)
            else:
                st.info(status_msg)
            continue
        if source.get("count", 0) == 0 and not source.get("error"):
            continue
        label = f"{source['name']}: {source.get('count', 0)}"
        if source.get("live"):
            label += " (live)"
        elif source.get("stale"):
            label += " (cached, stale)"
        elif source.get("count"):
            label += " (cached)"
        if source.get("rate_limited"):
            st.warning(f"{label} ΓÇö rate limited, using cache.")
        elif source.get("error") and source.get("count", 0):
            st.info(f"{label} ΓÇö fallback: {source['error']}")
        elif source.get("error"):
            st.caption(f"{source['name']}: {source['error']}")
        else:
            st.caption(label)


def _result_to_dict(result) -> dict:
    return {
        "total": result.total,
        "sources": [
            {
                "name": source.name,
                "count": source.count,
                "cached_at": source.cached_at.isoformat() if source.cached_at else None,
                "stale": source.stale,
                "live": source.live,
                "error": source.error,
                "rate_limited": source.rate_limited,
                "status_message": source.status_message,
            }
            for source in result.sources
        ],
    }
