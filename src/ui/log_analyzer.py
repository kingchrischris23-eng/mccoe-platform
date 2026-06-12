import pandas as pd
import plotly.express as px
import streamlit as st

from src.logs.analyzer import analyze_logs, export_analysis_json
from src.storage.repository import get_alerts, get_log_entries, get_latest_session_id, list_log_sessions


def render() -> None:
    st.title("Log Analyzer")
    st.write("Deep analysis, risk scoring, and IOC correlation for parsed log sessions.")

    sessions = list_log_sessions()
    if not sessions:
        st.info("Parse a log file first to enable analysis.")
        return

    labels = {session["id"]: f"#{session['id']} — {session['filename']}" for session in sessions}
    default_session = st.session_state.get("active_session_id") or get_latest_session_id()
    session_id = st.selectbox(
        "Log session",
        options=list(labels.keys()),
        format_func=lambda value: labels[value],
        index=list(labels.keys()).index(default_session) if default_session in labels else 0,
    )

    entries = get_log_entries(session_id)
    alerts = get_alerts(session_id)
    analysis = analyze_logs(entries, alerts)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Entries", analysis["total_entries"])
    col2.metric("Unique IPs", analysis["unique_ips"])
    col3.metric("Alerts", len(alerts))
    col4.metric("IOC Matches", len(analysis["correlations"]))

    if analysis["timeline"]:
        timeline_df = pd.DataFrame(analysis["timeline"])
        fig = px.bar(timeline_df, x="hour", y="count", title="Events Over Time")
        st.plotly_chart(fig, use_container_width=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Top Source IPs")
        st.dataframe(pd.DataFrame(analysis["top_ips"], columns=["source_ip", "requests"]), hide_index=True)
    with col_b:
        st.subheader("Status Code Distribution")
        st.dataframe(
            pd.DataFrame(list(analysis["status_counts"].items()), columns=["status_code", "count"]),
            hide_index=True,
        )

    st.subheader("Risk Scores by Source IP")
    risk_df = pd.DataFrame(analysis["risk_scores"])
    if not risk_df.empty:
        st.dataframe(risk_df, use_container_width=True, hide_index=True)
    else:
        st.write("No risk scores available.")

    st.subheader("IOC Correlations")
    if analysis["correlations"]:
        for item in analysis["correlations"]:
            st.warning(f"{item['source_ip']} — {item['message']} ({item['rule_id']})")
    else:
        st.success("No direct IOC overlaps detected for this session.")

    st.download_button(
        "Export Analysis JSON",
        data=export_analysis_json(analysis),
        file_name=f"log_analysis_{session_id}.json",
        mime="application/json",
    )

    with st.expander("Investigation View"):
        if alerts:
            selected = st.selectbox("Alert", alerts, format_func=lambda a: f"{a['rule_name']} — {a['source_ip']}")
            st.code(selected.get("matched_line", ""))
            related = [entry for entry in entries if entry.get("source_ip") == selected.get("source_ip")][:10]
            st.json(related)
        else:
            st.write("No alerts to investigate.")