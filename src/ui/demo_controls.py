import streamlit as st

from src.data_import.demo_loader import load_demo_data
from src.ui.clear_data import render_clear_data_sidebar_trigger


def _reset_threat_feeds_state() -> None:
    for key in (
        "selected_ioc_row",
        "selected_ioc_token",
        "mitigation_cache",
        "ioc_page",
        "ioc_filter_key",
        "ioc_search",
    ):
        st.session_state.pop(key, None)


def render_demo_controls() -> None:
    st.sidebar.markdown("### Data")
    st.sidebar.caption(
        "Demo pack: 55+ IOCs with published dates, color-coded severities, "
        "pagination, and click-for-mitigation CVE details."
    )
    if st.sidebar.button("Load Demo Data", type="secondary"):
        st.session_state["confirm_demo"] = True

    if st.session_state.get("confirm_demo"):
        st.sidebar.warning("Load demo IOCs, logs, and vuln data?")
        col1, col2 = st.sidebar.columns(2)
        if col1.button("Yes", key="demo_yes"):
            summary = load_demo_data()
            _reset_threat_feeds_state()
            st.session_state["demo_loaded"] = True
            st.session_state["confirm_demo"] = False
            breakdown = summary.get("ioc_breakdown", {})
            st.sidebar.success(
                f"Demo loaded: {summary['iocs']} IOCs ({breakdown.get('cves', 0)} CVEs), "
                f"{summary['alerts']} alerts, {summary['vuln_scans']} vuln scan(s)."
            )
            if breakdown:
                st.sidebar.info(
                    f"Threat Feeds ready: {breakdown.get('fresh', 0)} fresh / "
                    f"{breakdown.get('active', 0)} active / {breakdown.get('older', 0)} older — "
                    f"{summary.get('pages', 1)} page(s). Click any row for mitigation steps."
                )
            st.rerun()
        if col2.button("No", key="demo_no"):
            st.session_state["confirm_demo"] = False

    if st.session_state.get("demo_loaded"):
        st.sidebar.caption("Demo data active — open Threat Feeds to explore.")

    render_clear_data_sidebar_trigger()