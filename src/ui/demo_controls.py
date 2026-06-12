import streamlit as st

from src.data_import.demo_loader import load_demo_data
from src.storage.repository import clear_all_data


def render_demo_controls() -> None:
    st.sidebar.markdown("### Data")
    if st.sidebar.button("Load Demo Data", type="secondary"):
        st.session_state["confirm_demo"] = True

    if st.session_state.get("confirm_demo"):
        st.sidebar.warning("Load demo IOCs, logs, and vuln data?")
        col1, col2 = st.sidebar.columns(2)
        if col1.button("Yes", key="demo_yes"):
            summary = load_demo_data()
            st.session_state["demo_loaded"] = True
            st.session_state["confirm_demo"] = False
            st.sidebar.success(
                f"Demo loaded: {summary['iocs']} IOCs, {summary['alerts']} alerts, "
                f"{summary['vuln_scans']} vuln scan(s)."
            )
        if col2.button("No", key="demo_no"):
            st.session_state["confirm_demo"] = False

    if st.session_state.get("demo_loaded"):
        st.sidebar.caption("Demo data active")

    if st.sidebar.button("Clear All Data"):
        clear_all_data()
        st.session_state.pop("demo_loaded", None)
        st.session_state.pop("active_session_id", None)
        st.sidebar.success("All data cleared.")
        st.rerun()