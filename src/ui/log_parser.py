import streamlit as st

from config import settings
from src.api_client import DashboardAPIError
from src.logs.detectors import detect_alerts
from src.logs.parser import load_sample_log, parse_log_file
from src.reports.generator import generate_threat_report
from src.storage.repository import create_log_session, get_alerts, get_latest_session_id, save_alerts, save_log_entries
from src.ui.api_helpers import get_client


def render() -> None:
    st.title("Log Parser")
    st.write("Upload Apache/Nginx combined logs or use the bundled attack sample.")

    uploaded = st.file_uploader("Log file", type=["log", "txt"])
    use_sample = st.button("Load Sample Attack Log")

    content = None
    filename = None
    if use_sample:
        content = load_sample_log()
        filename = "apache_attack.log"
    elif uploaded is not None:
        size_mb = uploaded.size / (1024 * 1024)
        if size_mb > settings.max_upload_mb:
            st.error(f"File exceeds {settings.max_upload_mb} MB limit.")
            return
        content = uploaded.getvalue().decode("utf-8", errors="replace")
        filename = uploaded.name

    if content and filename and st.button("Parse & Detect", type="primary"):
        client = get_client()
        if client:
            try:
                result = client.analyze_logs(filename, content)
                session_id = result["session_id"]
                alerts = result["alerts"]
                st.session_state["active_session_id"] = session_id
                st.success(
                    f"Parsed {result['entries_parsed']} entries and found {result['alerts_found']} alerts (via API)."
                )
            except DashboardAPIError as exc:
                st.error(f"API error: {exc}")
                return
        else:
            entries = parse_log_file(content)
            alerts = detect_alerts(entries)
            session_id = create_log_session(filename)
            save_log_entries(session_id, entries)
            save_alerts(session_id, alerts)
            st.session_state["active_session_id"] = session_id
            st.success(f"Parsed {len(entries)} entries and found {len(alerts)} alerts.")

        if settings.auto_report_on_upload and alerts:
            report_path = generate_threat_report(auto=True)
            st.info(f"Automated threat report generated: `{report_path.name}`")

    session_id = st.session_state.get("active_session_id") or get_latest_session_id()
    if not session_id:
        st.info("No parsed logs yet.")
        return

    alerts = get_alerts(session_id)
    st.subheader(f"Alerts for session #{session_id}")
    if not alerts:
        st.success("No alerts detected in this session.")
        return

    for alert in alerts:
        with st.expander(f"[{alert['severity'].upper()}] {alert['rule_name']} — {alert['source_ip']}"):
            st.write(alert["message"])
            st.code(alert.get("matched_line", ""))
            st.markdown(f"**Remediation:** {alert.get('remediation', 'Review and escalate as needed.')}")