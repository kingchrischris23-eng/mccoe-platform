from pathlib import Path

from config import REPORTS_DIR, get_ioc_recent_days
from src.feeds.ioc_display import format_last_seen, is_high_risk, recency_label
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
from src.reports.data_collector import ReportData, recommendations
from src.storage.repository import save_report


def render_markdown_content(data: ReportData) -> str:
    timestamp = data.timestamp
    lines = [
        f"# {ORG_NAME}",
        f"## {REPORT_TITLE}",
        "",
        f"**Generated:** {timestamp.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Mode:** {data.mode_label}  ",
        f"**Version:** {REPORT_VERSION}  ",
        f"**Contact:** {ORG_EMAIL}  ",
        f"**{FOOTER_TRAINING}** - {FOOTER_CONFIDENTIAL}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"- Threat IOCs tracked: **{data.ioc_total_count:,}** "
        f"(NIST NVD: **{data.ioc_nist_count:,}**, CISA KEV: **{data.ioc_cisa_count:,}**, "
        f"OTX: **{data.ioc_otx_count:,}**, URLhaus: **{data.ioc_urlhaus_count:,}**, "
        f"ThreatFox: **{data.ioc_threatfox_count:,}**, "
        f"{data.ioc_recent_count:,} recent in last {get_ioc_recent_days()} days)",
        f"- Log alerts detected: **{len(data.alerts)}**",
        f"- Vulnerability scans on record: **{len(data.vuln_scans)}**",
        "",
    ]

    if data.filter_summary:
        lines.extend(["## Report Filters Applied", ""])
        for item in data.filter_summary:
            lines.append(f"- {item}")
        lines.append("")

    lines.extend([
        "## Risk Scoring Legend",
        "",
        "| Score Range | Level | Action |",
        "|-------------|-------|--------|",
    ])

    for score_range, level, action in RISK_LEGEND:
        lines.append(f"| {score_range} | {level} | {action} |")

    lines.extend(["", "## Threat Intelligence Sources", ""])
    if data.feed_summary:
        lines.append("| Source | IOCs | Mode | Last Updated |")
        lines.append("|--------|------|------|--------------|")
        for feed in data.feed_summary:
            mode = "live" if feed.get("live") else ("cached (stale)" if feed.get("stale") else "cached")
            cached = (feed.get("cached_at") or "—")[:19]
            lines.append(f"| {feed['name']} | {feed['count']} | {mode} | {cached} |")
    else:
        lines.append("_No feed cache metadata available._")

    if data.recently_added:
        lines.extend(["", "## Recently Added (Last 7 Days)", ""])
        for row in data.recently_added:
            risk = " **HIGH RISK**" if is_high_risk(row) else ""
            lines.append(
                f"- **[{row['severity'].upper()}]**{risk} `{row['ioc_type']}` — `{row['value']}` "
                f"(Last seen: {format_last_seen(row)})"
            )

    lines.extend(["", "## Threat Intelligence", ""])
    if data.iocs:
        lines.append(
            f"_Showing **{len(data.iocs):,}** filtered IOCs "
            f"(**{data.ioc_filtered_count:,}** matched filters / **{data.ioc_total_count:,}** dashboard total). "
            f"Newest first, max **{data.ioc_report_limit:,}**. "
            f"Green = last 7d | Yellow = 8-30d | Gray = older._"
        )
        lines.append("")
        for row in data.iocs:
            ioc_type = row["ioc_type"]
            age = recency_label(row)
            risk = " **HIGH RISK**" if is_high_risk(row) else ""
            explanation = IOC_TYPE_EXPLANATIONS.get(ioc_type, "Indicator observed in threat intelligence feeds.")
            lines.append(
                f"- **[{age}]** **[{row['severity'].upper()}]**{risk} `{ioc_type}` — `{row['value']}`  "
            )
            lines.append(
                f"  - Source: {row['source']} | Last seen: {format_last_seen(row)} | Tags: {row.get('tags', '')}"
            )
            lines.append(f"  - *{explanation}*")
        if data.ioc_filtered_count > len(data.iocs):
            lines.append(
                f"\n_{data.ioc_filtered_count - len(data.iocs):,} additional matching IOCs omitted — "
                f"raise max items or adjust filters in Threat Reporter._"
            )
    else:
        lines.append("_No IOCs available. Import IOCs, refresh feeds, or load demo data._")

    if data.kev_highlights:
        lines.extend(["", "## CISA KEV Highlights", ""])
        for row in data.kev_highlights[:8]:
            lines.append(f"- **[{row['severity'].upper()}]** `{row['value']}` — {row.get('description', '')[:120]}")

    if data.nvd_highlights:
        lines.extend(["", "## NIST NVD Recent CVEs", ""])
        for row in data.nvd_highlights[:8]:
            lines.append(f"- **[{row['severity'].upper()}]** `{row['value']}` — {row.get('description', '')[:120]}")

    lines.extend(["", "## Log Alert Breakdown", ""])
    if data.alert_breakdown:
        for rule_name, count in data.alert_breakdown.items():
            lines.append(f"- {rule_name}: **{count}** alert(s)")
    else:
        lines.append("_No log alerts recorded._")

    if data.analysis:
        lines.extend(["", "## Log Analyzer Highlights", ""])
        lines.append(f"- Total parsed entries: **{data.analysis['total_entries']}**")
        lines.append(f"- Unique source IPs: **{data.analysis['unique_ips']}**")
        if data.analysis["risk_scores"]:
            top = data.analysis["risk_scores"][0]
            lines.append(
                f"- Highest risk IP: `{top['source_ip']}` (score **{top['risk_score']}**, {top['risk_level']})"
            )
        if data.correlations:
            lines.append(f"- IOC correlations found: **{len(data.correlations)}**")

    lines.extend(["", "## Network Scan Results", ""])
    if data.network_scans:
        for scan in data.network_scans[:3]:
            lines.append(
                f"### `{scan['target']}` — {scan['scan_type']} (ports {scan['port_range']}) — {scan.get('summary', '')}"
            )
            for row in scan.get("results", [])[:8]:
                svc = row.get("service") or "unknown"
                lines.append(
                    f"- `{row['host']}`:{row['port']} **{svc}** "
                    f"{row.get('product', '')} {row.get('version', '')}".strip()
                )
            lines.append("")
    else:
        lines.append("_No network scans recorded._")

    lines.extend(["", "## Vulnerability Findings", ""])
    if data.vuln_scans:
        for scan in data.vuln_scans[:4]:
            lines.append(f"### Target: `{scan['target']}` — Risk **{scan['risk_score']}**")
            if scan["open_ports"]:
                ports = ", ".join(f"{p['port']}/{p['service']}" for p in scan["open_ports"][:6])
                lines.append(f"- Open ports: {ports}")
            for cve in scan.get("cve_findings", [])[:3]:
                lines.append(f"- {cve['cve_id']} (CVSS {cve.get('score', 'N/A')}): {cve.get('description', '')[:100]}")
            lines.append("")
    else:
        lines.append("_No vulnerability scans recorded._")

    lines.extend(["", "## Recommendations", ""])
    for item in recommendations(data):
        lines.append(f"- {item}")

    lines.extend(["", "## Training Notes", "", "_Discussion questions for MCCoE lab debrief:_", ""])
    for index, question in enumerate(TRAINING_QUESTIONS, start=1):
        lines.append(f"{index}. {question}")

    lines.extend(
        [
            "",
            "---",
            "",
            f"_{FOOTER_TRAINING} | {FOOTER_CONFIDENTIAL}_  ",
            f"_Report generated {timestamp.strftime('%Y-%m-%d %H:%M UTC')} - Version {REPORT_VERSION} - {ORG_EMAIL}_",
        ]
    )

    return "\n".join(lines)


def generate_markdown_report(data: ReportData | None = None, auto: bool = False, save_db: bool = True) -> Path:
    if data is None:
        from src.reports.data_collector import collect_report_data

        data = collect_report_data(auto=auto)

    timestamp = data.timestamp
    filename = f"threat_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.md"
    output_path = REPORTS_DIR / filename
    output_path.write_text(render_markdown_content(data), encoding="utf-8")

    if save_db:
        save_report(
            {
                "filename": filename,
                "generated_at": timestamp.isoformat(),
                "summary": (
                    f"{len(data.iocs)} IOCs (filtered {data.ioc_filtered_count:,} / "
                    f"total {data.ioc_total_count:,}), {len(data.alerts)} alerts (MD)"
                ),
                "ioc_count": data.ioc_total_count,
                "alert_count": len(data.alerts),
                "vuln_count": len(data.vuln_scans),
            }
        )
    return output_path