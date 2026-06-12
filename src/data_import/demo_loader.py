from pathlib import Path

from config import DEMO_DATA_DIR
from src.data_import.ioc_importer import import_iocs_from_file
from src.feeds.models import IOC
from src.logs.detectors import detect_alerts
from src.logs.parser import parse_log_file
from src.storage.repository import create_log_session, save_alerts, save_iocs, save_log_entries, save_vuln_scan
import json


def load_demo_data() -> dict:
    summary = {"iocs": 0, "log_entries": 0, "alerts": 0, "vuln_scans": 0}

    ioc_path = DEMO_DATA_DIR / "demo_iocs.csv"
    if ioc_path.exists():
        iocs = import_iocs_from_file(ioc_path)
        save_iocs(iocs)
        summary["iocs"] = len(iocs)

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