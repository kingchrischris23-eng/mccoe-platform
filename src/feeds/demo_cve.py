import json

from config import DEMO_DATA_DIR

_DETAILS_PATH = DEMO_DATA_DIR / "demo_cve_details.json"
_cache: dict[str, dict] | None = None


def _load_details() -> dict[str, dict]:
    global _cache
    if _cache is not None:
        return _cache
    if not _DETAILS_PATH.exists():
        _cache = {}
        return _cache
    payload = json.loads(_DETAILS_PATH.read_text(encoding="utf-8"))
    _cache = {str(k).upper(): v for k, v in payload.items()}
    return _cache


def lookup_demo_cve_entry(cve_id: str) -> dict | None:
    return _load_details().get(cve_id.strip().upper())


def reload_demo_cve_details() -> None:
    global _cache
    _cache = None