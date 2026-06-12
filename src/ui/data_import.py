import streamlit as st

from src.data_import.ioc_importer import import_iocs_from_upload, parse_ioc_records
from src.data_import.validators import normalize_ioc_type, normalize_severity, parse_tags
from src.feeds.models import IOC
from src.storage.repository import save_iocs, save_vuln_scan
from datetime import datetime, timezone


def render_ioc_import_section() -> None:
    st.subheader("Import IOCs")
    uploaded = st.file_uploader("Upload IOC file (CSV or JSON)", type=["csv", "json"], key="ioc_upload")
    if uploaded and st.button("Import IOC File", key="import_ioc_file"):
        try:
            content = uploaded.getvalue().decode("utf-8", errors="replace")
            iocs = import_iocs_from_upload(uploaded.name, content)
            save_iocs(iocs)
            st.success(f"Imported {len(iocs)} IOC(s).")
        except (ValueError, KeyError) as exc:
            st.error(str(exc))

    with st.expander("Manual IOC Entry"):
        ioc_type = st.selectbox("Type", ["ip", "domain", "url", "hash", "email", "filename"])
        value = st.text_input("Value")
        severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
        source = st.text_input("Source", value="manual")
        tags = st.text_input("Tags (semicolon-separated)")
        description = st.text_area("Description")
        if st.button("Add IOC", key="add_ioc_manual"):
            if not value.strip():
                st.error("Value is required.")
            else:
                ioc = IOC(
                    ioc_type=normalize_ioc_type(ioc_type),
                    value=value.strip(),
                    severity=normalize_severity(severity),
                    source=source.strip() or "manual",
                    first_seen=datetime.now(timezone.utc),
                    tags=parse_tags(tags),
                    description=description.strip(),
                )
                save_iocs([ioc])
                st.success(f"Added IOC: {ioc.value}")


def render_vuln_manual_entry() -> None:
    with st.expander("Manual Vulnerability Entry"):
        target = st.text_input("Target", value="127.0.0.1", key="manual_vuln_target")
        ports_raw = st.text_input("Open ports (comma-separated)", value="80,443", key="manual_vuln_ports")
        cve_id = st.text_input("CVE ID", value="", key="manual_vuln_cve")
        cvss = st.number_input("CVSS score", min_value=0.0, max_value=10.0, value=0.0, key="manual_vuln_cvss")
        issue = st.text_input("Finding description", key="manual_vuln_issue")
        risk_score = st.number_input("Risk score", min_value=0.0, max_value=100.0, value=25.0, key="manual_vuln_risk")
        if st.button("Save Vulnerability", key="save_manual_vuln"):
            ports = []
            for item in ports_raw.split(","):
                item = item.strip()
                if item.isdigit():
                    port = int(item)
                    ports.append({"port": port, "service": "manual"})
            cve_findings = []
            if cve_id.strip():
                cve_findings.append(
                    {
                        "cve_id": cve_id.strip(),
                        "score": float(cvss),
                        "vector": "manual",
                        "description": issue.strip() or "Manual entry",
                    }
                )
            header_issues = []
            if issue.strip() and not cve_id.strip():
                header_issues.append({"header": "Manual", "issue": issue.strip()})
            save_vuln_scan(
                {
                    "target": target.strip() or "manual",
                    "open_ports": ports,
                    "header_issues": header_issues,
                    "cve_findings": cve_findings,
                    "risk_score": float(risk_score),
                }
            )
            st.success("Vulnerability finding saved.")