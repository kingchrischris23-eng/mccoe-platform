import ipaddress
import re

from config import settings
from src.vuln.checker import allowed_targets, is_target_allowed

_PORT_RANGE_PATTERN = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def parse_port_range(port_range: str) -> str:
    """Validate and normalize a port range like '1-1000' or '80'."""
    cleaned = port_range.strip().replace(" ", "")
    if not cleaned:
        raise ValueError("Port range is required.")

    parts = cleaned.split(",")
    normalized: list[str] = []
    for part in parts:
        match = _PORT_RANGE_PATTERN.match(part)
        if not match:
            raise ValueError(f"Invalid port range segment: {part}")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if start < 1 or end > 65535 or start > end:
            raise ValueError(f"Ports must be between 1 and 65535: {part}")
        normalized.append(f"{start}-{end}" if start != end else str(start))
    return ",".join(normalized)


def validate_scan_target(target: str) -> str:
    """Ensure scan target is permitted before running nmap."""
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target is required.")

    if "/" in cleaned:
        if not settings.instructor_mode:
            raise PermissionError(
                "Subnet scans (e.g. 192.168.1.0/24) require INSTRUCTOR_MODE=true in .env. "
                "Use a single allowlisted host such as 127.0.0.1 for training."
            )
        try:
            network = ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR target: {cleaned}") from exc
        if network.is_loopback or str(network) in {t for t in allowed_targets()}:
            return cleaned
        if not network.is_private:
            raise PermissionError("Only private or loopback subnets are allowed in instructor mode.")
        return cleaned

    if is_target_allowed(cleaned):
        return cleaned

    raise PermissionError(
        f"Target '{cleaned}' is not in the allowlist. "
        f"Allowed: {', '.join(allowed_targets())}. "
        "Set INSTRUCTOR_MODE=true for subnet scans."
    )