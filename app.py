import streamlit as st

from config import is_local_only, settings
from src.data_import.demo_loader import load_demo_data
from src.storage.repository import get_overview_stats, init_db
from src.ui import (
    log_analyzer,
    log_parser,
    network_scanner,
    overview,
    settings_page,
    threat_feeds,
    threat_reporter,
    vuln_checker,
)
from src.ui.api_helpers import api_status_badge
from src.ui.demo_controls import render_demo_controls

PAGES = {
    "Overview": overview.render,
    "Threat Feeds": threat_feeds.render,
    "Log Parser": log_parser.render,
    "Log Analyzer": log_analyzer.render,
    "Vuln Checker": vuln_checker.render,
    "Network Scanner": network_scanner.render,
    "Threat Reporter": threat_reporter.render,
    "Settings": settings_page.render,
}


def main() -> None:
    st.set_page_config(
        page_title="MCCoE Cyber Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_db()

    if settings.auto_load_demo and not st.session_state.get("auto_demo_checked"):
        stats = get_overview_stats()
        if stats["ioc_count"] == 0 and stats["alert_count"] == 0 and stats["vuln_count"] == 0:
            load_demo_data()
            st.session_state["demo_loaded"] = True
        st.session_state["auto_demo_checked"] = True

    st.sidebar.title("MCCoE Cyber SOC")
    st.sidebar.caption("MCCoE cybersecurity dashboard | support@mccoe.org")
    selection = st.sidebar.radio("Navigate", list(PAGES.keys()))
    st.sidebar.markdown("---")

    if is_local_only():
        st.sidebar.success("**Local-only mode** — import your own data.")
    else:
        st.sidebar.info("**Online mode** — live feeds available.")

    api_status_badge()
    if settings.use_api_backend:
        st.sidebar.caption(f"API docs: {settings.api_base_url}/docs")

    st.sidebar.markdown("---")
    render_demo_controls()

    PAGES[selection]()


if __name__ == "__main__":
    main()