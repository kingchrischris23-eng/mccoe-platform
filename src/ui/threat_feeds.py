import pandas as pd
import streamlit as st

from config import is_local_only
from src.feeds.aggregator import aggregate_feeds
from src.storage.repository import list_iocs, save_iocs


def render() -> None:
    st.title("Threat Feed Aggregator")
    st.write("Aggregates OTX, URLhaus, and local sample IOCs with deduplication.")

    if is_local_only():
        st.info("Local-only mode: loading bundled sample IOCs only (no external API calls).")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Fetch & Merge Feeds", type="primary"):
            iocs = aggregate_feeds()
            save_iocs(iocs)
            st.session_state["feeds_loaded"] = len(iocs)
    with col2:
        if is_local_only():
            st.caption("Uses `data/samples/sample_iocs.csv` for portable offline labs.")
        else:
            st.caption("Without API keys, URLhaus + sample data are used automatically.")

    if st.session_state.get("feeds_loaded"):
        st.success(f"Loaded {st.session_state['feeds_loaded']} IOCs.")

    rows = list_iocs()
    if not rows:
        st.warning("No IOCs in database. Click 'Fetch & Merge Feeds'.")
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

    with st.expander("What is an IOC?"):
        st.markdown(
            "An **Indicator of Compromise (IOC)** is evidence that a system may have been breached — "
            "such as a malicious IP, domain, URL, or file hash. Trainees practice comparing IOCs against logs."
        )