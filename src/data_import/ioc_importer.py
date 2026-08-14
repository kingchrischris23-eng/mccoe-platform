import csv
import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from src.data_import.validators import normalize_ioc_type, normalize_severity, parse_tags
from src.feeds.models import IOC

_DATE_FIELDS = ("first_seen", "published_date", "published", "last_seen")


def parse_first_seen_value(raw: str | None, *, default: datetime | None = None) -> datetime:
    fallback = default or datetime.now(timezone.utc)
    if raw is None or str(raw).strip() == "":
        return fallback
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return fallback
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_ioc_records(payload: list[dict]) -> list[IOC]:
    iocs: list[IOC] = []
    now = datetime.now(timezone.utc)
    for row in payload:
        value = str(row.get("value", "")).strip()
        if not value:
            continue
        seen = now
        for field in _DATE_FIELDS:
            if row.get(field):
                seen = parse_first_seen_value(row.get(field), default=now)
                break
        iocs.append(
            IOC(
                ioc_type=normalize_ioc_type(str(row.get("ioc_type", "unknown"))),
                value=value,
                severity=normalize_severity(str(row.get("severity", "medium"))),
                source=str(row.get("source", "import")).strip() or "import",
                first_seen=seen,
                tags=parse_tags(row.get("tags")),
                description=str(row.get("description", "")).strip(),
            )
        )
    if not iocs:
        raise ValueError("No valid IOC records found in import.")
    return iocs


def import_iocs_from_csv(content: str) -> list[IOC]:
    reader = csv.DictReader(StringIO(content))
    rows = list(reader)
    if not rows:
        raise ValueError("CSV file is empty or missing headers.")
    return parse_ioc_records(rows)


def import_iocs_from_json(content: str) -> list[IOC]:
    data = json.loads(content)
    if isinstance(data, dict) and "iocs" in data:
        data = data["iocs"]
    if not isinstance(data, list):
        raise ValueError("JSON must be a list of IOC objects or {'iocs': [...]}.")
    return parse_ioc_records(data)


def import_iocs_from_file(path: Path) -> list[IOC]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return import_iocs_from_json(text)
    return import_iocs_from_csv(text)


def import_iocs_from_upload(filename: str, content: str) -> list[IOC]:
    lower = filename.lower()
    if lower.endswith(".json"):
        return import_iocs_from_json(content)
    return import_iocs_from_csv(content)