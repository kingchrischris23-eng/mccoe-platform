from pathlib import Path

import streamlit as st

from config import REPORTS_DIR
from src.reports.generator import (
    generate_threat_report,
    generate_threat_report_markdown,
    generate_threat_reports,
)
from src.storage.repository import list_reports


def render() -> None:
    st.title("Automated Threat Reporter")
    st.write(
        "MCCoE-branded reports combining threat feeds, log alerts, analyzer highlights, "
        "and vulnerability findings. Export as PDF (with charts) or Markdown."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Generate PDF", type="primary"):
            path = generate_threat_report(auto=False)
            st.session_state["last_report_pdf"] = str(path)
            st.success(f"PDF saved: `{path.name}`")
    with col2:
        if st.button("Generate Markdown"):
            path = generate_threat_report_markdown(auto=False)
            st.session_state["last_report_md"] = str(path)
            st.success(f"Markdown saved: `{path.name}`")
    with col3:
        if st.button("Generate Both"):
            paths = generate_threat_reports(auto=False)
            st.session_state["last_report_pdf"] = str(paths["pdf"])
            st.session_state["last_report_md"] = str(paths["markdown"])
            st.success(f"Saved `{paths['pdf'].name}` and `{paths['markdown'].name}`")

    st.caption(f"Reports directory: `{REPORTS_DIR}`")

    dl_col1, dl_col2 = st.columns(2)
    pdf_path = st.session_state.get("last_report_pdf")
    md_path = st.session_state.get("last_report_md")
    if pdf_path and Path(pdf_path).exists():
        dl_col1.download_button(
            "Download Latest PDF",
            data=Path(pdf_path).read_bytes(),
            file_name=Path(pdf_path).name,
            mime="application/pdf",
        )
    if md_path and Path(md_path).exists():
        dl_col2.download_button(
            "Download Latest Markdown",
            data=Path(md_path).read_text(encoding="utf-8"),
            file_name=Path(md_path).name,
            mime="text/markdown",
        )

    reports = list_reports()
    st.subheader("Report History")
    if not reports:
        st.info("No reports generated yet.")
        return

    for report in reports:
        report_path = REPORTS_DIR / report["filename"]
        cols = st.columns([3, 2, 1, 1])
        cols[0].write(f"`{report['filename']}`")
        cols[1].write(report["summary"])
        if report_path.exists():
            cols[2].download_button(
                "PDF",
                data=report_path.read_bytes(),
                file_name=report["filename"],
                mime="application/pdf",
                key=f"pdf_{report['id']}",
            )
        md_candidate = report_path.with_suffix(".md")
        if md_candidate.exists():
            cols[3].download_button(
                "MD",
                data=md_candidate.read_text(encoding="utf-8"),
                file_name=md_candidate.name,
                mime="text/markdown",
                key=f"md_{report['id']}",
            )