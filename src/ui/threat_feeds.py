import pandas as pd
import streamlit as st

from config import is_local_only
from src.api_client import DashboardAPIError
from src.feeds.aggregator import can_refresh_live, refresh_feeds
from src.storage.repository import list_iocs, save_iocs
from src.ui.api_helpers import get_client
from src.ui.data_import import render_ioc_import_section
from src.ui.feed_settings import render_feed_settings


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
                except DashboardAPIError as exc:
                    st.error(f"API error: {exc}")
            else:
                result = refresh_feeds(force_refresh=True)
                save_iocs(result.iocs)
                st.session_state["feed_refresh"] = _result_to_dict(result)
    with col2:
        if refresh_disabled:
            st.caption("Enable LOCAL_ONLY=false and Enable live feeds in settings.")
        else:
            st.caption("Pulls URLhaus, OTX, NVD, and CISA KEV into local JSON cache.")

    _show_refresh_summary()

    if client:
        try:
            rows = client.get_threats(limit=500)["iocs"]
        except DashboardAPIError as exc:
            st.error(f"API error: {exc}")
            return
    else:
        rows = list_iocs()

    if not rows:
        st.info("No IOCs yet. Import a CSV/JSON file, add one manually, refresh live feeds, or load demo data.")
        return

    df = pd.DataFrame(rows)
    severity = st.multiselect("Severity", sorted(df["severity"].unique()), default=list(df["severity"].unique()))
    ioc_type = st.multiselect("IOC Type", sorted(df["ioc_type"].unique()), default=list(df["ioc_type"].unique()))
    filtered = df[df["severity"].isin(severity) & df["ioc_type"].isin(ioc_type)]

    st.metric("Visible IOCs", len(filtered))
    st.dataframe(
        filtered[["ioc_type", "value", "severity", "source", "tags", "description"]],
        use_container_width=True,
        hide_index=True,
    )


def _show_refresh_summary() -> None:
    summary = st.session_state.get("feed_refresh")
    if not summary:
        return

    total = summary.get("total", 0)
    st.success(f"Loaded {total} IOC(s) from feeds.")
    for source in summary.get("sources", []):
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
            st.warning(f"{label} — NVD rate limited, using cache.")
        elif source.get("error") and source.get("count", 0):
            st.info(f"{label} — fallback: {source['error']}")
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
            }
            for source in result.sources
        ],
    }


