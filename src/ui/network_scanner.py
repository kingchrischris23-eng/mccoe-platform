import pandas as pd
import streamlit as st

from config import settings
from src.network.scanner import run_network_scan
from src.storage.repository import list_network_scans
from src.vuln.checker import allowed_targets


def render() -> None:
    st.title("Network Scanner")
    st.markdown(
        """
        **Basic Network Scan** using Nmap (via `python-nmap`). For MCCoE training labs only.

        > **Permission warning:** Only scan networks and systems you own or have **explicit written
        > authorization** to test. Unauthorized scanning may violate law and organizational policy.
        """
    )

    st.error(
        "You must confirm permission before scanning. Default allowlist: "
        f"`{', '.join(allowed_targets())}`. "
        "Subnet scans (e.g. `192.168.1.0/24`) require `INSTRUCTOR_MODE=true` in `.env`."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        target = st.text_input(
            "Target",
            value="127.0.0.1",
            help="Single host (127.0.0.1) or CIDR (192.168.1.0/24) when instructor mode is enabled.",
            placeholder="127.0.0.1 or 192.168.1.0/24",
        )
    with col2:
        port_range = st.text_input("Port range", value="1-1000", help="Examples: 1-1000, 80,443, 22-443")
    with col3:
        scan_type = st.selectbox("Scan type", options=["Quick", "Full"], index=0)

    st.markdown(
        """
        | Scan type | Behavior |
        |-----------|----------|
        | **Quick** | TCP connect scan, faster timing (`-T4`), open ports only |
        | **Full** | TCP connect + service/version detection (`-sV`), slower (`-T3`) |
        """
    )

    permission = st.checkbox(
        "I have permission to scan this target and understand this is for authorized training use only.",
        value=False,
    )

    if st.button("Run Scan", type="primary", disabled=not permission):
        with st.status("Running network scan...", expanded=True) as status:
            st.write(f"Target: `{target}` | Ports: `{port_range}` | Type: **{scan_type}**")
            try:
                result = run_network_scan(target, port_range, scan_type)
                st.session_state["last_network_scan"] = result
                status.update(label="Scan complete", state="complete")
                st.success(f"{result['summary']} — saved to `{result['json_path']}`")
            except (PermissionError, ValueError) as exc:
                status.update(label="Scan blocked", state="error")
                st.error(str(exc))
            except RuntimeError as exc:
                status.update(label="Scan failed", state="error")
                st.error(str(exc))
            except Exception as exc:
                status.update(label="Scan failed", state="error")
                st.error(f"Unexpected error: {exc}")

    result = st.session_state.get("last_network_scan")
    if result:
        st.subheader("Scan Results")
        m1, m2, m3 = st.columns(3)
        m1.metric("Hosts up", result.get("hosts_up", 0))
        m2.metric("Open ports", result.get("open_port_count", 0))
        m3.metric("Scan type", result.get("scan_type", ""))

        rows = result.get("results", [])
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(
                df[["host", "port", "state", "service", "product", "version", "extrainfo"]],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No open ports found in the selected range.")

        with st.expander("Raw scan JSON"):
            st.json(result)

    st.subheader("Safety Notes")
    st.markdown(
        """
        - Install [Nmap](https://nmap.org/download.html) and ensure `nmap` is on your system `PATH`.
        - Use **127.0.0.1** for safe local practice.
        - Home lab subnets: set `INSTRUCTOR_MODE=true` and add targets to `ALLOWED_TARGETS` if needed.
        - Scan results are saved to `data/scans/*.json` and the local database for threat reports.
        - Current instructor mode: **{instructor}**
        """.format(instructor="enabled" if settings.instructor_mode else "disabled")
    )

    history = list_network_scans(limit=5)
    if history:
        st.subheader("Recent Network Scans")
        for scan in history:
            st.write(
                f"- `{scan['target']}` ({scan['scan_type']}, ports {scan['port_range']}) — "
                f"{scan['summary']} ({scan['scanned_at'][:19]})"
            )