import json
from pathlib import Path

import httpx

from config import CACHE_DIR

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INDEX_PATH = CACHE_DIR / "cisa_kev_index.json"

_KEV_FIELDS = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
)


def _entry_from_row(row: dict) -> dict:
    return {field: row.get(field, "") for field in _KEV_FIELDS}


def write_kev_index(rows: list[dict]) -> None:
    index = {row["cveID"]: _entry_from_row(row) for row in rows if row.get("cveID")}
    INDEX_PATH.write_text(json.dumps(index, indent=2), encoding="utf-8")


def _fetch_live_kev_rows() -> list[dict]:
    response = httpx.get(KEV_URL, timeout=30.0)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])


def ensure_kev_index() -> dict[str, dict]:
    if INDEX_PATH.exists():
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    try:
        rows = _fetch_live_kev_rows()
        write_kev_index(rows)
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except httpx.HTTPError:
        return {}


def lookup_kev_entry(cve_id: str) -> dict | None:
    index = ensure_kev_index()
    return index.get(cve_id.upper())