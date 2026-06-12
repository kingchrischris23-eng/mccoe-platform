import streamlit as st

from src.feeds.aggregator import aggregate_feeds
from src.storage.repository import get_overview_stats, list_log_sessions, list_reports, save_iocs


def render() -> None:
    st.title("Training SOC Overview")
    st.caption("Safe, educational MCCoE cybersecurity training dashboard.")

    if st.button("Refresh Threat Feeds"):
        iocs = aggregate_feeds()
        save_iocs(iocs)
        st.success(f"Loaded {len(iocs)} IOCs.")

    stats = get_overview_stats()
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("IOCs", stats["ioc_count"])
    col2.metric("High/Critical IOCs", stats["high_iocs"])
    col3.metric("Log Alerts", stats["alert_count"])
    col4.metric("Vuln Scans", stats["vuln_count"])
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
        st.info("No log sessions yet. Upload a sample log in Log Parser.")

    if reports:
        st.markdown("**Latest threat reports**")
        for report in reports:
            st.write(f"- `{report['filename']}` — {report['summary']} ({report['generated_at'][:19]})")

    st.subheader("Lab Objectives")
    st.markdown(
        """
        1. Refresh threat feeds and inspect high-severity IOCs.
        2. Upload the sample Apache attack log and review generated alerts.
        3. Use Log Analyzer to score risky source IPs and check IOC overlap.
        4. Run a localhost vulnerability check with the allowlist safeguards.
        5. Generate an automated PDF threat report for instructor review.
        """
    )