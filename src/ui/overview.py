import streamlit as st

from config import get_auto_feed_refresh_hours, is_auto_feed_refresh_enabled, reload_settings
from src.config.env_store import update_env_value
from src.feeds.aggregator import can_refresh_live, refresh_feeds
from src.monitoring.refresh import quick_refresh_all
from src.monitoring.state import read_monitoring_state
from src.monitoring.status import format_relative_time, get_dashboard_status
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

    _render_monitoring_controls()
    _render_last_updated()

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
        1. **Threat Feeds** — import CSV/JSON IOCs or refresh live feeds.
        2. **Log Parser** — upload your Apache/Nginx logs.
        3. **Log Analyzer** — review risk scores after parsing.
        4. **Vuln Checker** — scan localhost or add findings manually.
        5. **Threat Reporter** — generate MCCoE PDF/Markdown reports.
        """
    )


def _render_monitoring_controls() -> None:
    st.subheader("Monitoring")
    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        if st.button("Quick Refresh All", type="primary"):
            with st.spinner("Refreshing feeds and running quick localhost scan..."):
                result = quick_refresh_all()
            if result["errors"]:
                for err in result["errors"]:
                    st.warning(err)
            if result.get("feeds") and not result["feeds"].get("skipped"):
                st.success(f"Feeds: {result['feeds']['count']} IOC(s) loaded.")
            elif result.get("feeds", {}).get("skipped"):
                st.info("Feeds skipped (live feeds disabled).")
            if result.get("scan"):
                st.success(f"Scan: {result['scan']['summary']} on {result['scan']['target']}.")
            if not result["errors"] and (result.get("feeds") or result.get("scan")):
                st.rerun()

    with col2:
        if st.button("Refresh Live Feeds", disabled=not can_refresh_live()):
            result = refresh_feeds(force_refresh=True)
            save_iocs(result.iocs)
            if result.total:
                st.success(f"Refreshed {result.total} IOC(s) from live feeds.")
            else:
                st.warning("No feed data returned. Import IOCs or check feed settings.")
            st.rerun()

    with col3:
        refresh_hours = get_auto_feed_refresh_hours()
        auto_refresh_enabled = is_auto_feed_refresh_enabled()
        auto_refresh = st.toggle(
            f"Auto-refresh feeds every {refresh_hours}h (background)",
            value=auto_refresh_enabled,
            help="Uses a lightweight Streamlit daemon thread. No refresh runs while disabled.",
        )
        if auto_refresh != auto_refresh_enabled:
            update_env_value("ENABLE_AUTO_FEED_REFRESH", "true" if auto_refresh else "false")
            reload_settings()
            st.rerun()
        if can_refresh_live():
            st.caption("Quick Refresh pulls feeds (when online) plus a quick 127.0.0.1 port scan.")
        else:
            st.caption("Live feeds disabled — Quick Refresh runs the localhost scan only.")


def _render_last_updated() -> None:
    status = get_dashboard_status()
    state = read_monitoring_state()
    cols = st.columns(3)
    cols[0].metric("Feeds last updated", status.last_feed_refresh)
    cols[1].metric("Last network scan", status.last_network_scan)
    cols[2].metric("Last quick refresh", status.last_quick_refresh)

    if state.get("last_feed_refresh"):
        st.caption(f"Feed refresh timestamp: {state['last_feed_refresh'][:19]} UTC")
    if state.get("last_network_scan"):
        st.caption(f"Scan timestamp: {state['last_network_scan'][:19]} UTC")
    if state.get("last_auto_feed_refresh"):
        st.caption(
            f"Last auto-refresh: {format_relative_time(state['last_auto_feed_refresh'])} "
            f"({state['last_auto_feed_refresh'][:19]} UTC)"
        )