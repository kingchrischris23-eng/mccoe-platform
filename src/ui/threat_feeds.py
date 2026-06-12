import pandas as pd
import streamlit as st

from config import is_local_only
from src.api_client import DashboardAPIError
from src.feeds.aggregator import aggregate_feeds
from src.storage.repository import list_iocs, save_iocs
from src.ui.api_helpers import get_client
from src.ui.data_import import render_ioc_import_section


def render() -> None:
    st.title("Threat Feed Aggregator")
    st.write("Import your own IOCs or fetch live feeds when not in local-only mode.")

    if is_local_only():
        st.info("Local-only mode: live feeds disabled. Import IOCs via CSV/JSON or use Load Demo Data in the sidebar.")

    render_ioc_import_section()

    client = get_client()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Fetch Live Feeds", type="primary"):
            if is_local_only():
                st.warning("Disable LOCAL_ONLY or import IOCs manually to populate threat data.")
            elif client:
                try:
                    result = client.get_threats(refresh=True, limit=500)
                    st.session_state["feeds_loaded"] = result["count"]
                except DashboardAPIError as exc:
                    st.error(f"API error: {exc}")
            else:
                iocs = aggregate_feeds()
                save_iocs(iocs)
                st.session_state["feeds_loaded"] = len(iocs)
    with col2:
        st.caption("Live feeds require LOCAL_ONLY=false and optional API keys.")

    if st.session_state.get("feeds_loaded") is not None:
        st.success(f"Loaded {st.session_state['feeds_loaded']} IOC(s) from live feeds.")

    if client:
        try:
            rows = client.get_threats(limit=500)["iocs"]
        except DashboardAPIError as exc:
            st.error(f"API error: {exc}")
            return
    else:
        rows = list_iocs()

    if not rows:
        st.info("No IOCs yet. Import a CSV/JSON file, add one manually, fetch live feeds, or load demo data.")
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