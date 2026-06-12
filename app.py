import streamlit as st

from config import is_local_only
from src.storage.repository import init_db
from src.ui import log_analyzer, log_parser, overview, threat_feeds, threat_reporter, vuln_checker

PAGES = {
    "Overview": overview.render,
    "Threat Feeds": threat_feeds.render,
    "Log Parser": log_parser.render,
    "Log Analyzer": log_analyzer.render,
    "Vuln Checker": vuln_checker.render,
    "Threat Reporter": threat_reporter.render,
}


def main() -> None:
    st.set_page_config(
        page_title="Cyber Training Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_db()

    st.sidebar.title("Cyber Training SOC")
    st.sidebar.caption("Nonprofit cybersecurity training dashboard")
    selection = st.sidebar.radio("Navigate", list(PAGES.keys()))
    st.sidebar.markdown("---")
    if is_local_only():
        st.sidebar.success("**Local-only mode** — bundled samples, no external APIs.")
    else:
        st.sidebar.info(
            "**Online mode** — live feeds enabled. Set `LOCAL_ONLY=true` for offline use."
        )

    PAGES[selection]()


if __name__ == "__main__":
    main()