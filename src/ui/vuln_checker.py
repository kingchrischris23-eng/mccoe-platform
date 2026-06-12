import streamlit as st

from config import is_local_only, settings
from src.api_client import DashboardAPIError
from src.storage.repository import list_vuln_scans, save_vuln_scan
from src.ui.api_helpers import get_client
from src.vuln.checker import allowed_targets, run_vuln_check


def render() -> None:
    st.title("Basic Vulnerability Checker")
    st.warning(
        "Training use only. Scan only approved targets. Unauthorized scanning may be illegal. "
        "Default allowlist: localhost and 127.0.0.1."
    )

    if is_local_only():
        st.info("Local-only mode: scans return bundled sample results from `data/samples/sample_vuln_scan.json`.")

    st.caption(f"Allowed targets: {', '.join(allowed_targets())}")
    target = st.text_input("Target host", value="127.0.0.1")
    ports = st.multiselect("Ports", options=[22, 80, 443, 3389, 8080], default=[80, 443, 8080])

    if st.button("Run Safe Scan", type="primary"):
        try:
            result = run_vuln_check(target, ports)
            save_vuln_scan(result)
            st.session_state["last_vuln_result"] = result
            st.success(f"Scan complete. Risk score: {result['risk_score']}")
        except PermissionError as exc:
            st.error(str(exc))
        except OSError as exc:
            st.error(f"Scan failed: {exc}")

    result = st.session_state.get("last_vuln_result")
    if result:
        st.subheader("Latest Scan Results")
        st.json(result)

    client = get_client()
    if client:
        try:
            history = client.get_vulnerabilities(limit=5)["scans"]
        except DashboardAPIError:
            history = list_vuln_scans()[:5]
    else:
        history = list_vuln_scans()[:5]
    if history:
        st.subheader("Recent Scans")
        for scan in history:
            st.write(
                f"- `{scan['target']}` — risk {scan['risk_score']}, "
                f"{len(scan['open_ports'])} open port(s) ({scan['scanned_at'][:19]})"
            )