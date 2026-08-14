import tempfile
from datetime import datetime
from pathlib import Path

from fpdf import FPDF

from config import REPORTS_DIR, get_ioc_recent_days
from src.feeds.ioc_display import format_last_seen, pdf_highlight_for_row, recency_label
from src.reports.branding import (
    FOOTER_CONFIDENTIAL,
    FOOTER_TRAINING,
    IOC_TYPE_EXPLANATIONS,
    ORG_EMAIL,
    ORG_NAME,
    REPORT_TITLE,
    REPORT_VERSION,
    RISK_LEGEND,
    TRAINING_QUESTIONS,
)
from src.reports.charts import alert_breakdown_pie, vulnerability_risk_bar
from src.reports.data_collector import ReportData, collect_report_data, recommendations
from src.reports.filters import ReportFilters
from src.reports.markdown import generate_markdown_report
from src.reports.pdf_text import sanitize_pdf_text
from src.storage.repository import save_report


class MCCoEReportPDF(FPDF):
    def __init__(self, generated_at: datetime):
        super().__init__()
        self.generated_at = generated_at

    def cell(self, w, h=0, text="", *args, **kwargs):
        return super().cell(w, h, sanitize_pdf_text(text), *args, **kwargs)

    def multi_cell(self, w, h=0, text="", *args, **kwargs):
        return super().multi_cell(w, h, sanitize_pdf_text(text), *args, **kwargs)

    def header(self) -> None:
        self.set_fill_color(31, 78, 121)
        self.rect(10, 8, 16, 16, style="F")
        self.set_fill_color(220, 220, 220)
        self.rect(11, 9, 14, 14, style="F")
        self.set_xy(10, 13)
        self.set_font("Helvetica", "B", 5)
        self.set_text_color(80, 80, 80)
        self.cell(16, 4, "MCCoE", align="C")

        self.set_text_color(0, 0, 0)
        self.set_xy(30, 9)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 5, ORG_NAME, new_x="LMARGIN", new_y="NEXT")
        self.set_x(30)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(60, 60, 60)
        self.cell(0, 5, REPORT_TITLE)
        self.set_text_color(0, 0, 0)
        self.line(10, 26, 200, 26)
        self.ln(8)

    def footer(self) -> None:
        self.set_y(-20)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(180, 0, 0)
        self.cell(0, 4, FOOTER_TRAINING, align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(90, 90, 90)
        self.cell(0, 4, FOOTER_CONFIDENTIAL, align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(
            0,
            4,
            f"Generated {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')} | v{REPORT_VERSION} | {ORG_EMAIL} | Page {self.page_no()}",
            align="C",
        )

    def section_title(self, title: str) -> None:
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(240, 244, 248)
        self.cell(0, 7, f"  {title}", new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(2)

    def body_text(self, text: str, size: int = 9) -> None:
        self.set_font("Helvetica", "", size)
        self.multi_cell(0, 4.5, text)
        self.ln(1)

    def compact_line(self, text: str) -> None:
        self.set_font("Helvetica", "", 8)
        self.multi_cell(0, 4, text)
        self.ln(0.5)

    def highlighted_line(self, text: str, fill_rgb: tuple[int, int, int] | None, *, bold: bool = False) -> None:
        self.set_text_color(0, 0, 0)
        if fill_rgb:
            self.set_fill_color(*fill_rgb)
        self.set_font("Helvetica", "B" if bold else "", 8)
        self.multi_cell(0, 4, text, fill=bool(fill_rgb))
        self.set_fill_color(255, 255, 255)
        self.ln(0.5)


def _build_pdf(data: ReportData, output_path: Path) -> None:
    pdf = MCCoEReportPDF(data.timestamp)
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.set_margins(10, 28, 10)
    pdf.add_page()

    pdf.section_title("Executive Summary")
    pdf.body_text(
        f"Mode: {data.mode_label}  |  IOCs tracked: {data.ioc_total_count:,}  |  "
        f"NIST NVD: {data.ioc_nist_count:,}  |  CISA KEV: {data.ioc_cisa_count:,}  |  "
        f"OTX: {data.ioc_otx_count:,}  |  URLhaus: {data.ioc_urlhaus_count:,}  |  "
        f"ThreatFox: {data.ioc_threatfox_count:,}  |  "
        f"Recent ({get_ioc_recent_days()}d): {data.ioc_recent_count:,}  |  "
        f"Alerts: {len(data.alerts)}  |  Vuln scans: {len(data.vuln_scans)}"
    )

    if data.filter_summary:
        pdf.section_title("Report Filters Applied")
        for line in data.filter_summary:
            pdf.compact_line(f"  {line.replace('**', '')}")

    pdf.section_title("Risk Scoring Legend")
    for score_range, level, action in RISK_LEGEND:
        pdf.compact_line(f"  {score_range} ({level}): {action}")

    pdf.section_title("Threat Intelligence Sources")
    if data.feed_summary:
        for feed in data.feed_summary:
            mode = "live" if feed.get("live") else ("cached (stale)" if feed.get("stale") else "cached")
            cached = (feed.get("cached_at") or "n/a")[:19]
            pdf.compact_line(f"  {feed['name']}: {feed['count']} IOCs - {mode} - {cached}")
    else:
        pdf.body_text("No feed cache metadata available.")

    if data.recently_added:
        pdf.section_title("Recently Added (Last 7 Days)")
        pdf.body_text("Highest-priority new indicators from the last week.")
        for row in data.recently_added:
            ioc_type = row["ioc_type"]
            fill, bold = pdf_highlight_for_row(row)
            pdf.highlighted_line(
                f"[{row['severity'].upper()}] {ioc_type}: {row['value']}  "
                f"({row['source']}) Last seen: {format_last_seen(row)}",
                fill,
                bold=bold,
            )

    pdf.section_title("Threat Intelligence")
    if data.iocs:
        pdf.body_text(
            f"Showing {len(data.iocs):,} filtered IOCs "
            f"({data.ioc_filtered_count:,} matched filters / {data.ioc_total_count:,} dashboard total). "
            f"Newest first, max {data.ioc_report_limit:,}. "
            f"Green = last 7d | Yellow = 8-30d | Gray = older. Bold = critical/high."
        )
        for row in data.iocs:
            ioc_type = row["ioc_type"]
            hint = IOC_TYPE_EXPLANATIONS.get(ioc_type, "Threat indicator from intelligence feeds.")
            fill, bold = pdf_highlight_for_row(row)
            pdf.highlighted_line(
                f"[{recency_label(row)}] [{row['severity'].upper()}] {ioc_type}: {row['value']}  "
                f"({row['source']}) Last seen: {format_last_seen(row)} - {hint}",
                fill,
                bold=bold,
            )
        if data.ioc_filtered_count > len(data.iocs):
            pdf.compact_line(
                f"  ({data.ioc_filtered_count - len(data.iocs):,} additional matching IOCs omitted — "
                f"raise max items or adjust filters in Threat Reporter.)"
            )
    else:
        pdf.body_text("No IOCs available. Import IOCs, refresh feeds, or load demo data.")

    if data.kev_highlights:
        pdf.section_title("CISA KEV Highlights")
        for row in data.kev_highlights[:6]:
            pdf.compact_line(f"  [{row['severity'].upper()}] {row['value']}: {row.get('description', '')[:90]}")

    if data.nvd_highlights:
        pdf.section_title("NIST NVD Recent CVEs")
        for row in data.nvd_highlights[:6]:
            pdf.compact_line(f"  [{row['severity'].upper()}] {row['value']}: {row.get('description', '')[:90]}")

    pdf.add_page()

    pdf.section_title("Log Alert Breakdown")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        pie_path = alert_breakdown_pie(data.alert_breakdown, tmp / "alerts.png")
        if pie_path:
            pdf.image(str(pie_path), x=10, w=190)
            pdf.ln(58)
        else:
            pdf.body_text("No log alerts recorded. Upload a log file to populate this section.")

        if data.analysis:
            top = data.analysis["risk_scores"][0] if data.analysis["risk_scores"] else None
            summary = (
                f"Entries: {data.analysis['total_entries']}  |  "
                f"Unique IPs: {data.analysis['unique_ips']}"
            )
            if top:
                summary += f"  |  Top risk: {top['source_ip']} ({top['risk_score']})"
            if data.correlations:
                summary += f"  |  IOC matches: {len(data.correlations)}"
            pdf.compact_line(summary)

        pdf.ln(2)
        pdf.section_title("Network Scan Results")
        if data.network_scans:
            for scan in data.network_scans[:2]:
                pdf.compact_line(
                    f"  {scan['target']} ({scan['scan_type']}, {scan['port_range']}): {scan.get('summary', '')}"
                )
                for row in scan.get("results", [])[:6]:
                    svc = row.get("service") or "unknown"
                    pdf.compact_line(
                        f"    {row['host']}:{row['port']} {svc} {row.get('product', '')} {row.get('version', '')}"
                    )
        else:
            pdf.body_text("No network scans recorded.")

        pdf.ln(2)
        pdf.section_title("Vulnerability Findings")
        bar_path = vulnerability_risk_bar(data.vuln_scans, tmp / "vulns.png")
        if bar_path:
            pdf.image(str(bar_path), x=10, w=150)
            pdf.ln(42)
            latest = data.vuln_scans[0]
            pdf.compact_line(f"Latest target: {latest['target']} - risk score {latest['risk_score']}")
            for cve in latest.get("cve_findings", [])[:3]:
                pdf.compact_line(
                    f"  {cve['cve_id']} (CVSS {cve.get('score', 'N/A')}): {cve.get('description', '')[:90]}"
                )
        else:
            pdf.body_text("No vulnerability scans recorded.")

    pdf.add_page()

    pdf.section_title("Recommendations")
    for item in recommendations(data):
        pdf.compact_line(f"- {item}")

    pdf.ln(2)
    pdf.section_title("Training Notes")
    pdf.body_text("Discussion questions for MCCoE lab debrief:", size=9)
    for index, question in enumerate(TRAINING_QUESTIONS, start=1):
        pdf.compact_line(f"  {index}. {question}")

    pdf.output(str(output_path))


def _report_db_summary(data: ReportData) -> str:
    return (
        f"{len(data.iocs)} IOCs (filtered {data.ioc_filtered_count:,} / total {data.ioc_total_count:,}), "
        f"{len(data.alerts)} alerts"
    )


def generate_threat_report(auto: bool = False, filters: ReportFilters | None = None) -> Path:
    data = collect_report_data(auto=auto, filters=filters)
    timestamp = data.timestamp
    filename = f"threat_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = REPORTS_DIR / filename
    _build_pdf(data, output_path)
    save_report(
        {
            "filename": filename,
            "generated_at": timestamp.isoformat(),
            "summary": _report_db_summary(data),
            "ioc_count": data.ioc_total_count,
            "alert_count": len(data.alerts),
            "vuln_count": len(data.vuln_scans),
        }
    )
    return output_path


def generate_threat_report_markdown(auto: bool = False, filters: ReportFilters | None = None) -> Path:
    data = collect_report_data(auto=auto, filters=filters)
    return generate_markdown_report(data)


def generate_threat_reports(auto: bool = False, filters: ReportFilters | None = None) -> dict[str, Path]:
    data = collect_report_data(auto=auto, filters=filters)
    timestamp = data.timestamp
    base = f"threat_report_{timestamp.strftime('%Y%m%d_%H%M%S')}"

    pdf_path = REPORTS_DIR / f"{base}.pdf"
    _build_pdf(data, pdf_path)
    md_path = generate_markdown_report(data, save_db=False)

    save_report(
        {
            "filename": pdf_path.name,
            "generated_at": timestamp.isoformat(),
            "summary": f"{_report_db_summary(data)} (PDF+MD)",
            "ioc_count": data.ioc_total_count,
            "alert_count": len(data.alerts),
            "vuln_count": len(data.vuln_scans),
        }
    )
    return {"pdf": pdf_path, "markdown": md_path}