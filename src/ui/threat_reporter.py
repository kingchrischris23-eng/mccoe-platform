from pathlib import Path

import streamlit as st

from config import REPORTS_DIR, settings
from src.api_client import DashboardAPIError
from src.reports.filters import (
    DATE_RANGE_OPTIONS,
    DEFAULT_MAX_ITEMS,
    MAX_ITEMS_CEILING,
    SOURCE_OPTIONS,
    SEVERITY_OPTIONS,
    ReportFilters,
)
from src.reports.generator import (
    generate_threat_report,
    generate_threat_report_markdown,
    generate_threat_reports,
)
from src.storage.repository import count_iocs_filtered, list_reports
from src.ui.api_helpers import get_client


def _default_filter_state() -> dict:
    defaults = ReportFilters.defaults()
    return defaults.to_dict()


def _get_report_filters() -> ReportFilters:
    stored = st.session_state.get("report_filters")
    if not isinstance(stored, dict):
        stored = _default_filter_state()
        st.session_state["report_filters"] = stored
    return ReportFilters.from_dict(stored)


def _preview_counts(filters: ReportFilters) -> tuple[int, int, int]:
    query = filters.query_kwargs()
    dashboard_total = count_iocs_filtered()
    matching = count_iocs_filtered(**query)
    included = min(matching, filters.effective_limit())
    return dashboard_total, matching, included


def _render_report_filters() -> ReportFilters:
    st.subheader("Report Filters")
    st.caption(
        "Filters apply only to the exported report. Your full dataset stays intact in Threat Feeds."
    )

    state = st.session_state.setdefault("report_filters", _default_filter_state())
    col1, col2 = st.columns(2)

    with col1:
        selected_severities = st.multiselect(
            "Risk level",
            options=list(SEVERITY_OPTIONS),
            default=state.get("severities") or list(SEVERITY_OPTIONS),
            format_func=lambda s: s.title(),
        )
        date_label = next(
            (label for label, key in DATE_RANGE_OPTIONS.items() if key == state.get("date_range")),
            "Last 30 days",
        )
        picked_date_label = st.selectbox(
            "Date range",
            options=list(DATE_RANGE_OPTIONS.keys()),
            index=list(DATE_RANGE_OPTIONS.keys()).index(date_label),
        )
        source_label = next(
            (label for label, key in SOURCE_OPTIONS.items() if key == state.get("source")),
            "All sources",
        )
        picked_source_label = st.selectbox(
            "Source",
            options=list(SOURCE_OPTIONS.keys()),
            index=list(SOURCE_OPTIONS.keys()).index(source_label),
        )

    with col2:
        search = st.text_input(
            "Search term",
            value=state.get("search") or "",
            placeholder="CVE-2026, Ivanti, ransomware…",
        )
        max_items = st.slider(
            "Max items in report",
            min_value=50,
            max_value=min(500, MAX_ITEMS_CEILING),
            value=int(state.get("max_items") or DEFAULT_MAX_ITEMS),
            step=25,
            help=f"Default {DEFAULT_MAX_ITEMS}. Dashboard data is not truncated — only the report export is limited.",
        )

    reset_col, _ = st.columns([1, 3])
    with reset_col:
        if st.button("Reset filters to defaults"):
            st.session_state["report_filters"] = _default_filter_state()
            st.rerun()

    filters = ReportFilters(
        severities=selected_severities or list(SEVERITY_OPTIONS),
        date_range=DATE_RANGE_OPTIONS[picked_date_label],
        source=SOURCE_OPTIONS[picked_source_label],
        search=search.strip() or None,
        max_items=max_items,
    )
    st.session_state["report_filters"] = filters.to_dict()

    dashboard_total, matching, included = _preview_counts(filters)
    if matching == 0:
        st.warning(
            f"No IOCs match the current filters ({dashboard_total:,} total in dashboard). "
            "Adjust filters before generating."
        )
    else:
        st.info(
            f"**Generating report with {included:,} item(s)** — "
            f"{matching:,} match filters, {dashboard_total:,} total in dashboard."
        )

    with st.expander("Filter summary", expanded=False):
        for line in filters.summary_lines(
            matching=matching,
            included=included,
            dashboard_total=dashboard_total,
        ):
            st.markdown(f"- {line}")

    return filters


def _handle_api_report(fmt: str, filters: ReportFilters) -> dict | None:
    client = get_client()
    if not client:
        return None
    try:
        return client.generate_report(fmt=fmt, auto=False, filters=filters.to_dict())
    except DashboardAPIError as exc:
        st.error(f"API error: {exc}")
        return None


def render() -> None:
    st.title("Automated Threat Reporter")
    st.write(
        "MCCoE-branded reports combining threat feeds, log alerts, analyzer highlights, "
        "and vulnerability findings. Export as PDF (with charts) or Markdown."
    )

    filters = _render_report_filters()
    _, matching, _ = _preview_counts(filters)
    generate_disabled = matching == 0

    st.subheader("Generate")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Generate PDF", type="primary", disabled=generate_disabled):
            result = _handle_api_report("pdf", filters)
            if result:
                path = Path(result["files"][0]["path"])
                st.session_state["last_report_pdf"] = str(path)
                st.success(f"PDF saved via API: `{path.name}`")
            else:
                path = generate_threat_report(auto=False, filters=filters)
                st.session_state["last_report_pdf"] = str(path)
                st.success(f"PDF saved: `{path.name}`")
    with col2:
        if st.button("Generate Markdown", disabled=generate_disabled):
            result = _handle_api_report("markdown", filters)
            if result:
                path = Path(result["files"][0]["path"])
                st.session_state["last_report_md"] = str(path)
                st.success(f"Markdown saved via API: `{path.name}`")
            else:
                path = generate_threat_report_markdown(auto=False, filters=filters)
                st.session_state["last_report_md"] = str(path)
                st.success(f"Markdown saved: `{path.name}`")
    with col3:
        if st.button("Generate Both", disabled=generate_disabled):
            result = _handle_api_report("both", filters)
            if result:
                for item in result["files"]:
                    if item["format"] == "pdf":
                        st.session_state["last_report_pdf"] = item["path"]
                    if item["format"] == "markdown":
                        st.session_state["last_report_md"] = item["path"]
                st.success(f"Saved: {result['summary']}")
            else:
                paths = generate_threat_reports(auto=False, filters=filters)
                st.session_state["last_report_pdf"] = str(paths["pdf"])
                st.session_state["last_report_md"] = str(paths["markdown"])
                st.success(f"Saved `{paths['pdf'].name}` and `{paths['markdown'].name}`")

    st.caption(f"Reports directory: `{REPORTS_DIR}`")
    if settings.use_api_backend:
        st.caption(f"API endpoint: `{settings.api_base_url}/api/reports/generate`")

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