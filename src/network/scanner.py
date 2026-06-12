from datetime import datetime, timezone

from config import SCANS_DIR
from src.network.safety import parse_port_range, validate_scan_target
from src.storage.repository import log_scan_audit, save_network_scan


def _build_arguments(port_range: str, scan_type: str) -> str:
    ports = parse_port_range(port_range)
    if scan_type.lower() == "full":
        return f"-p {ports} -sT -sV -T3 --open"
    return f"-p {ports} -sT -T4 --open"


def _parse_results(nm, target: str) -> tuple[list[dict], int, int]:
    rows: list[dict] = []
    hosts_up = 0
    open_ports = 0

    for host in nm.all_hosts():
        host_state = nm[host].state()
        if host_state == "up":
            hosts_up += 1
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                if info.get("state") != "open":
                    continue
                open_ports += 1
                rows.append(
                    {
                        "host": host,
                        "protocol": proto,
                        "port": port,
                        "state": info.get("state", ""),
                        "service": info.get("name", ""),
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                        "extrainfo": info.get("extrainfo", ""),
                    }
                )
    rows.sort(key=lambda item: (item["host"], item["port"]))
    return rows, hosts_up, open_ports


def run_network_scan(target: str, port_range: str = "1-1000", scan_type: str = "Quick") -> dict:
    """Run a safe nmap scan against an allowlisted target."""
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError("python-nmap is not installed. Run: pip install python-nmap") from exc

    validated_target = validate_scan_target(target)
    arguments = _build_arguments(port_range, scan_type)
    log_scan_audit(validated_target, f"network_scan_started:{scan_type}")

    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=validated_target, arguments=arguments)
    except nmap.PortScannerError as exc:
        raise RuntimeError(
            f"Nmap failed: {exc}. Ensure Nmap is installed and on your PATH "
            "(https://nmap.org/download.html)."
        ) from exc

    rows, hosts_up, open_ports = _parse_results(scanner, validated_target)
    scanned_at = datetime.now(timezone.utc)

    result = {
        "target": validated_target,
        "port_range": parse_port_range(port_range),
        "scan_type": scan_type,
        "scanned_at": scanned_at.isoformat(),
        "arguments": arguments,
        "hosts_up": hosts_up,
        "open_port_count": open_ports,
        "results": rows,
        "summary": f"{hosts_up} host(s) up, {open_ports} open port(s)",
    }

    json_path = _write_json(result, scanned_at)
    result["json_path"] = str(json_path)
    save_network_scan(result)
    log_scan_audit(validated_target, "network_scan_completed")
    return result


def _write_json(result: dict, scanned_at: datetime) -> str:
    import json

    filename = f"network_scan_{scanned_at.strftime('%Y%m%d_%H%M%S')}.json"
    path = SCANS_DIR / filename
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path