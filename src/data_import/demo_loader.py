from pathlib import Path

from config import DEMO_DATA_DIR
from src.data_import.ioc_importer import import_iocs_from_file, import_iocs_from_json
from src.feeds.demo_cve import reload_demo_cve_details
from src.feeds.ioc_display import recency_tier
from src.feeds.models import IOC
from src.logs.detectors import detect_alerts
from src.logs.parser import parse_log_file
from src.storage.repository import create_log_session, save_alerts, save_iocs, save_log_entries, save_vuln_scan
import json


def _load_demo_iocs() -> list[IOC]:
    json_path = DEMO_DATA_DIR / "demo_iocs.json"
    csv_path = DEMO_DATA_DIR / "demo_iocs.csv"
    if json_path.exists():
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "iocs" in payload:
            return import_iocs_from_json(json.dumps(payload["iocs"]))
        return import_iocs_from_json(json_path.read_text(encoding="utf-8"))
    if csv_path.exists():
        return import_iocs_from_file(csv_path)
    return []


def _summarize_iocs(iocs: list[IOC]) -> dict:
    summary = {
        "total": len(iocs),
        "cves": 0,
        "critical": 0,
        "high": 0,
        "fresh": 0,
        "active": 0,
        "older": 0,
        "sources": {},
    }
    for ioc in iocs:
        if ioc.ioc_type == "cve" or str(ioc.value).upper().startswith("CVE-"):
            summary["cves"] += 1
        sev = ioc.severity.lower()
        if sev == "critical":
            summary["critical"] += 1
        elif sev == "high":
            summary["high"] += 1
        tier = recency_tier({"first_seen": ioc.first_seen.isoformat()})
        summary[tier] += 1
        summary["sources"][ioc.source] = summary["sources"].get(ioc.source, 0) + 1
    return summary


def load_demo_data() -> dict:
    summary = {
        "iocs": 0,
        "log_entries": 0,
        "alerts": 0,
        "vuln_scans": 0,
        "ioc_breakdown": {},
        "pages": 0,
    }

    reload_demo_cve_details()
    iocs = _load_demo_iocs()
    if iocs:
        save_iocs(iocs)
        breakdown = _summarize_iocs(iocs)
        summary["iocs"] = breakdown["total"]
        summary["ioc_breakdown"] = breakdown
        page_size = 50
        summary["pages"] = max(1, (breakdown["total"] + page_size - 1) // page_size)

    log_path = DEMO_DATA_DIR / "demo_attack.log"
    if log_path.exists():
        content = log_path.read_text(encoding="utf-8")
        entries = parse_log_file(content)
        alerts = detect_alerts(entries)
        session_id = create_log_session("demo_attack.log")
        save_log_entries(session_id, entries)
        save_alerts(session_id, alerts)
        summary["log_entries"] = len(entries)
        summary["alerts"] = len(alerts)

    vuln_path = DEMO_DATA_DIR / "demo_vuln_scan.json"
    if vuln_path.exists():
        result = json.loads(vuln_path.read_text(encoding="utf-8"))
        result["mode"] = "demo"
        save_vuln_scan(result)
        summary["vuln_scans"] = 1

    return summary