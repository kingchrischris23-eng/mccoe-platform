from collections import defaultdict

from src.logs.patterns import INJECTION_PATTERNS

RULES = {
    "AUTH-001": {
        "name": "Brute Force Login Attempts",
        "severity": "high",
        "remediation": "Enable account lockout, MFA, and review auth logs for successful follow-up logins.",
    },
    "WEB-001": {
        "name": "Web Injection Attempt",
        "severity": "high",
        "remediation": "Validate inputs, deploy a WAF rule, and inspect application error logs.",
    },
    "NET-001": {
        "name": "Port Scan Behavior",
        "severity": "medium",
        "remediation": "Block or rate-limit the source IP and verify exposed services.",
    },
}


def detect_alerts(entries: list[dict]) -> list[dict]:
    alerts: list[dict] = []
    alerts.extend(_detect_bruteforce(entries))
    alerts.extend(_detect_injection(entries))
    alerts.extend(_detect_port_scan(entries))
    return alerts


def _detect_bruteforce(entries: list[dict]) -> list[dict]:
    failures_by_ip: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        if entry.get("status_code") in (401, 403) and "/login" in entry.get("path", ""):
            failures_by_ip[entry["source_ip"]].append(entry)

    alerts: list[dict] = []
    for source_ip, failed_entries in failures_by_ip.items():
        if len(failed_entries) >= 5:
            alerts.append(
                {
                    "rule_id": "AUTH-001",
                    "rule_name": RULES["AUTH-001"]["name"],
                    "severity": RULES["AUTH-001"]["severity"],
                    "source_ip": source_ip,
                    "message": f"{len(failed_entries)} failed login attempts from {source_ip}",
                    "matched_line": failed_entries[-1]["raw_line"],
                    "remediation": RULES["AUTH-001"]["remediation"],
                }
            )
    return alerts


def _detect_injection(entries: list[dict]) -> list[dict]:
    alerts: list[dict] = []
    for entry in entries:
        path = entry.get("path", "")
        if any(pattern.search(path) for pattern in INJECTION_PATTERNS):
            alerts.append(
                {
                    "rule_id": "WEB-001",
                    "rule_name": RULES["WEB-001"]["name"],
                    "severity": RULES["WEB-001"]["severity"],
                    "source_ip": entry.get("source_ip"),
                    "message": f"Injection pattern detected in request path from {entry.get('source_ip')}",
                    "matched_line": entry["raw_line"],
                    "remediation": RULES["WEB-001"]["remediation"],
                }
            )
    return alerts


def _detect_port_scan(entries: list[dict]) -> list[dict]:
    paths_by_ip: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        source_ip = entry.get("source_ip")
        path = entry.get("path", "")
        if source_ip and path.startswith("/port-probe/"):
            paths_by_ip[source_ip].add(path)

    alerts: list[dict] = []
    for source_ip, paths in paths_by_ip.items():
        if len(paths) >= 5:
            sample = next(entry for entry in entries if entry.get("source_ip") == source_ip)
            alerts.append(
                {
                    "rule_id": "NET-001",
                    "rule_name": RULES["NET-001"]["name"],
                    "severity": RULES["NET-001"]["severity"],
                    "source_ip": source_ip,
                    "message": f"Source {source_ip} probed {len(paths)} unique paths",
                    "matched_line": sample["raw_line"],
                    "remediation": RULES["NET-001"]["remediation"],
                }
            )
    return alerts