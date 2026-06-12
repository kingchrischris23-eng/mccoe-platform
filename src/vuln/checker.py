import json

from config import SAMPLES_DIR, is_local_only, settings
from src.storage.repository import log_scan_audit
from src.vuln.nvd_client import lookup_cves
from src.vuln.scanner import check_http_headers, check_tls, scan_ports


def allowed_targets() -> list[str]:
    targets = [item.strip() for item in settings.allowed_targets.split(",") if item.strip()]
    if settings.instructor_mode:
        targets.extend(["scanme.nmap.org"])
    return sorted(set(targets))


def is_target_allowed(target: str) -> bool:
    normalized = target.strip().lower()
    return normalized in {item.lower() for item in allowed_targets()}


def _sample_vuln_result(target: str) -> dict:
    sample_path = SAMPLES_DIR / "sample_vuln_scan.json"
    if sample_path.exists():
        result = json.loads(sample_path.read_text(encoding="utf-8"))
        result["target"] = target
        result["mode"] = "local_only_sample"
        return result
    return {
        "target": target,
        "open_ports": [{"port": 80, "service": "http"}],
        "header_issues": [{"header": "Sample", "issue": "Offline training sample result"}],
        "cve_findings": lookup_cves("http"),
        "risk_score": 25.0,
        "mode": "local_only_sample",
    }


def run_vuln_check(target: str, ports: list[int] | None = None) -> dict:
    if not is_target_allowed(target):
        raise PermissionError(f"Target '{target}' is not in the allowlist.")

    log_scan_audit(target, "vuln_scan_started")
    if is_local_only():
        result = _sample_vuln_result(target)
        log_scan_audit(target, "vuln_scan_completed")
        return result

    open_ports = scan_ports(target, ports)
    header_issues = check_http_headers(target) if any(port["port"] in (80, 443, 8080) for port in open_ports) else []
    tls_issues = check_tls(target) if any(port["port"] == 443 for port in open_ports) else []

    cve_findings: list[dict] = []
    for port_info in open_ports:
        service = port_info["service"]
        if service in {"http", "https", "http-alt"}:
            cve_findings.extend(lookup_cves(service))

    risk_score = min(
        100.0,
        len(open_ports) * 8
        + len(header_issues) * 10
        + len(tls_issues) * 15
        + sum(item.get("score", 0) for item in cve_findings),
    )

    result = {
        "target": target,
        "open_ports": open_ports,
        "header_issues": header_issues + tls_issues,
        "cve_findings": cve_findings,
        "risk_score": round(risk_score, 1),
    }
    log_scan_audit(target, "vuln_scan_completed")
    return result