from pathlib import Path

from src.logs.patterns import APACHE_PATTERN


def parse_apache_line(line: str) -> dict | None:
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


def load_sample_log() -> str:
    sample_path = Path(__file__).resolve().parents[2] / "data" / "samples" / "apache_attack.log"
    return sample_path.read_text(encoding="utf-8")