from dataclasses import dataclass, field
from pathlib import Path

from config import CACHE_DIR, REPORTS_DIR, SCANS_DIR
from src.feeds.demo_cve import reload_demo_cve_details
from src.storage.repository import get_connection

FEED_CACHE_FILES = (
    "nist_nvd.json",
    "cisa_kev.json",
    "cisa_kev_index.json",
    "urlhaus.json",
    "otx.json",
    "threatfox.json",
    "openphish.json",
)

FEED_IOC_SOURCES = (
    "NIST NVD",
    "CISA KEV",
    "URLhaus",
    "AlienVault OTX",
    "ThreatFox",
    "OpenPhish",
)

CLEAR_CATEGORIES = (
    "feed_cache",
    "logs",
    "manual_iocs",
    "scans",
    "reports",
    "all_user_data",
)


@dataclass
class ClearOption:
    key: str
    label: str
    description: str


CLEAR_OPTIONS: list[ClearOption] = [
    ClearOption(
        "feed_cache",
        "Clear Live Feed Cache",
        "Removes NIST NVD, CISA KEV, URLhaus, OTX, ThreatFox, and OpenPhish cache files plus matching IOCs.",
    ),
    ClearOption(
        "logs",
        "Clear Imported Logs and Alerts",
        "Deletes uploaded log sessions, parsed entries, and generated alerts.",
    ),
    ClearOption(
        "manual_iocs",
        "Clear Manual IOCs / Threats",
        "Removes imported, demo-loaded, and lab IOCs while keeping live feed-sourced indicators.",
    ),
    ClearOption(
        "scans",
        "Clear Scan Results",
        "Deletes vulnerability findings, network scans, scan audit history, and saved scan JSON files.",
    ),
    ClearOption(
        "reports",
        "Clear Generated Reports",
        "Deletes report metadata and PDF/Markdown files from the reports folder.",
    ),
    ClearOption(
        "all_user_data",
        "Clear All User Data",
        "Clears every category above in one step. Settings, API keys, and demo catalog files are preserved.",
    ),
]

PROTECTED_NOTICE = (
    "**Always protected:** `.env` settings, API keys, feed toggles, demo catalog files (`data/demo/`), "
    "and the Load Demo Data loader."
)


@dataclass
class ClearPreview:
    feed_cache_files: int = 0
    feed_iocs: int = 0
    log_sessions: int = 0
    log_entries: int = 0
    alerts: int = 0
    manual_iocs: int = 0
    vuln_scans: int = 0
    network_scans: int = 0
    scan_audit: int = 0
    scan_files: int = 0
    reports: int = 0
    report_files: int = 0
    categories: list[str] = field(default_factory=list)

    @property
    def total_items(self) -> int:
        return (
            self.feed_cache_files
            + self.feed_iocs
            + self.log_sessions
            + self.log_entries
            + self.alerts
            + self.manual_iocs
            + self.vuln_scans
            + self.network_scans
            + self.scan_audit
            + self.scan_files
            + self.reports
            + self.report_files
        )

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        if self.feed_cache_files or self.feed_iocs:
            lines.append(
                f"- Live feed cache: **{self.feed_cache_files}** file(s), **{self.feed_iocs}** IOC(s)"
            )
        if self.log_sessions or self.log_entries or self.alerts:
            lines.append(
                f"- Logs & alerts: **{self.log_sessions}** session(s), "
                f"**{self.log_entries}** entries, **{self.alerts}** alert(s)"
            )
        if self.manual_iocs:
            lines.append(f"- Manual IOCs / threats: **{self.manual_iocs}**")
        if self.vuln_scans or self.network_scans or self.scan_audit or self.scan_files:
            lines.append(
                f"- Scan results: **{self.vuln_scans}** vuln scan(s), "
                f"**{self.network_scans}** network scan(s), **{self.scan_audit}** audit row(s), "
                f"**{self.scan_files}** file(s)"
            )
        if self.reports or self.report_files:
            lines.append(f"- Generated reports: **{self.reports}** record(s), **{self.report_files}** file(s)")
        return lines


def _feed_source_clause(column: str = "source") -> tuple[str, list[str]]:
    parts = [f"{column} LIKE ?" for _ in FEED_IOC_SOURCES]
    params = [f"%{source}%" for source in FEED_IOC_SOURCES]
    return "(" + " OR ".join(parts) + ")", params


def _resolve_categories(selected: list[str]) -> set[str]:
    keys = {key for key in selected if key in CLEAR_CATEGORIES}
    if "all_user_data" in keys:
        return {"feed_cache", "logs", "manual_iocs", "scans", "reports"}
    return keys


def _count_table(conn, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])


def _count_feed_cache_files() -> int:
    return sum(1 for name in FEED_CACHE_FILES if (CACHE_DIR / name).exists())


def _count_report_files() -> int:
    if not REPORTS_DIR.exists():
        return 0
    return sum(1 for path in REPORTS_DIR.iterdir() if path.is_file())


def _count_scan_files() -> int:
    if not SCANS_DIR.exists():
        return 0
    return sum(1 for path in SCANS_DIR.iterdir() if path.is_file())


def preview_clear(selected: list[str]) -> ClearPreview:
    categories = sorted(_resolve_categories(selected))
    preview = ClearPreview(categories=categories)

    with get_connection() as conn:
        if "feed_cache" in categories:
            preview.feed_cache_files = _count_feed_cache_files()
            clause, params = _feed_source_clause()
            preview.feed_iocs = int(
                conn.execute(f"SELECT COUNT(*) AS c FROM iocs WHERE {clause}", params).fetchone()["c"]
            )
        if "logs" in categories:
            preview.log_sessions = _count_table(conn, "log_sessions")
            preview.log_entries = _count_table(conn, "log_entries")
            preview.alerts = _count_table(conn, "alerts")
        if "manual_iocs" in categories:
            clause, params = _feed_source_clause()
            preview.manual_iocs = int(
                conn.execute(f"SELECT COUNT(*) AS c FROM iocs WHERE NOT {clause}", params).fetchone()["c"]
            )
        if "scans" in categories:
            preview.vuln_scans = _count_table(conn, "vuln_scans")
            preview.network_scans = _count_table(conn, "network_scans")
            preview.scan_audit = _count_table(conn, "scan_audit")
            preview.scan_files = _count_scan_files()
        if "reports" in categories:
            preview.reports = _count_table(conn, "reports")
            preview.report_files = _count_report_files()

    return preview


def _delete_feed_cache_files() -> int:
    removed = 0
    for name in FEED_CACHE_FILES:
        path = CACHE_DIR / name
        if path.exists():
            path.unlink()
            removed += 1
    reload_demo_cve_details()
    return removed


def _delete_report_files() -> int:
    if not REPORTS_DIR.exists():
        return 0
    removed = 0
    for path in REPORTS_DIR.iterdir():
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def _delete_scan_files() -> int:
    if not SCANS_DIR.exists():
        return 0
    removed = 0
    for path in SCANS_DIR.iterdir():
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def _clear_monitoring_state() -> None:
    state_path = CACHE_DIR / "monitoring_state.json"
    if state_path.exists():
        state_path.unlink()


def execute_clear(selected: list[str]) -> ClearPreview:
    categories = _resolve_categories(selected)
    if not categories:
        return ClearPreview()

    preview = preview_clear(list(categories))

    with get_connection() as conn:
        if "logs" in categories:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM log_entries")
            conn.execute("DELETE FROM log_sessions")

        if "feed_cache" in categories:
            clause, params = _feed_source_clause()
            conn.execute(f"DELETE FROM iocs WHERE {clause}", params)
            preview.feed_cache_files = _delete_feed_cache_files()

        if "manual_iocs" in categories:
            clause, params = _feed_source_clause()
            conn.execute(f"DELETE FROM iocs WHERE NOT {clause}", params)

        if "scans" in categories:
            conn.execute("DELETE FROM vuln_scans")
            conn.execute("DELETE FROM network_scans")
            conn.execute("DELETE FROM scan_audit")
            preview.scan_files = _delete_scan_files()

        if "reports" in categories:
            conn.execute("DELETE FROM reports")
            preview.report_files = _delete_report_files()

    if categories == {"feed_cache", "logs", "manual_iocs", "scans", "reports"}:
        _clear_monitoring_state()

    preview.categories = sorted(categories)
    return preview


def clear_all_data() -> None:
    """Backward-compatible full clear of dashboard data (settings/demo files preserved)."""
    execute_clear(["all_user_data"])