import streamlit as st

from src.feeds.aggregator import aggregate_feeds
from src.storage.repository import get_overview_stats, list_log_sessions, list_reports, save_iocs


def render() -> None:
    st.title("MCCoE Cyber SOC Overview")
    st.caption("Production dashboard — starts empty until you import data.")

    stats = get_overview_stats()
    if stats["ioc_count"] == 0 and stats["alert_count"] == 0 and stats["vuln_count"] == 0:
        st.info(
            "No data loaded yet. Import IOCs in **Threat Feeds**, upload logs in **Log Parser**, "
            "or add vulnerabilities in **Vuln Checker**. Use **Load Demo Data** in the sidebar to try sample data."
        )

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Fetch Live Feeds"):
            iocs = aggregate_feeds()
            save_iocs(iocs)
            if iocs:
                st.success(f"Fetched {len(iocs)} IOC(s) from live feeds.")
            else:
                st.warning("No live feed data returned. Import IOCs or enable API keys.")
    with col2:
        st.caption("Requires LOCAL_ONLY=false and network access.")

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("IOCs", stats["ioc_count"])
    col2.metric("High/Critical IOCs", stats["high_iocs"])
    col3.metric("Log Alerts", stats["alert_count"])
    col4.metric("Vuln Findings", stats["vuln_count"])
    col5.metric("Reports", stats["report_count"])

    st.subheader("Recent Activity")
    sessions = list_log_sessions()[:5]
    reports = list_reports()[:5]

    if sessions:
        st.markdown("**Latest log sessions**")
        for session in sessions:
            st.write(
                f"- `{session['filename']}` — {session['line_count']} lines, "
                f"{session['alert_count']} alerts ({session['uploaded_at'][:19]})"
            )
    else:
        st.write("No log sessions yet.")

    if reports:
        st.markdown("**Latest threat reports**")
        for report in reports:
            st.write(f"- `{report['filename']}` — {report['summary']} ({report['generated_at'][:19]})")
    else:
        st.write("No reports generated yet.")

    st.subheader("Getting Started")
    st.markdown(
        """
        1. **Threat Feeds** — import CSV/JSON IOCs or fetch live feeds.
        2. **Log Parser** — upload your Apache/Nginx logs.
        3. **Log Analyzer** — review risk scores after parsing.
        4. **Vuln Checker** — scan localhost or add findings manually.
        5. **Threat Reporter** — generate MCCoE PDF/Markdown reports.
        """
    )