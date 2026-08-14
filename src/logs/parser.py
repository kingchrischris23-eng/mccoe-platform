def parse_apache_line(line: str) -> dict | None:
    from src.logs.patterns import APACHE_PATTERN

    match = APACHE_PATTERN.match(line.strip())
    if not match:
        return None
    groups = match.groupdict()
    return {
        "timestamp": groups["timestamp"],
        "source_ip": groups["source_ip"],
        "method": groups["method"],
        "path": groups["path"],
        "status_code": int(groups["status_code"]),
        "user_agent": groups["user_agent"],
        "raw_line": line.strip(),
    }


def parse_log_file(content: str) -> list[dict]:
    entries: list[dict] = []
    for line in content.splitlines():
        if not line.strip():
            continue
        parsed = parse_apache_line(line)
        if parsed:
            entries.append(parsed)
    return entries