import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

COMMON_PORTS = [22, 80, 443, 3389, 8080]
HEADER_CHECKS = {
    "Strict-Transport-Security": "Missing HSTS header",
    "X-Frame-Options": "Missing clickjacking protection",
    "X-Content-Type-Options": "Missing MIME-sniffing protection",
}


def scan_ports(target: str, ports: list[int] | None = None) -> list[dict]:
    ports = ports or COMMON_PORTS
    open_ports: list[dict] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                open_ports.append({"port": port, "service": _guess_service(port)})
    return open_ports


def check_http_headers(target: str) -> list[dict]:
    scheme = "https" if target != "localhost" else "http"
    url = f"{scheme}://{target}"
    issues: list[dict] = []
    try:
        response = httpx.get(url, timeout=5.0, follow_redirects=True)
        for header, message in HEADER_CHECKS.items():
            if header not in response.headers:
                issues.append({"header": header, "issue": message})
        server = response.headers.get("Server")
        if server and any(token in server.lower() for token in ("1.0", "2.0", "2.2")):
            issues.append(
                {
                    "header": "Server",
                    "issue": f"Potentially outdated server banner: {server}",
                }
            )
    except httpx.HTTPError as exc:
        issues.append({"header": "HTTP", "issue": f"HTTP check failed: {exc}"})
    return issues


def check_tls(target: str) -> list[dict]:
    findings: list[dict] = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=2.0) as sock:
            with context.wrap_socket(sock, server_hostname=target) as secure:
                cert = secure.getpeercert()
                expires = cert.get("notAfter")
                if expires:
                    expiry = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if expiry < datetime.now(timezone.utc):
                        findings.append({"issue": "TLS certificate expired", "detail": expires})
    except OSError:
        return findings
    return findings


def _guess_service(port: int) -> str:
    return {
        22: "ssh",
        80: "http",
        443: "https",
        3389: "rdp",
        8080: "http-alt",
    }.get(port, "unknown")