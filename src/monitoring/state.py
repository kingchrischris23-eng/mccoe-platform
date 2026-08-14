import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import CACHE_DIR

STATE_PATH = CACHE_DIR / "monitoring_state.json"


def read_monitoring_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def write_monitoring_state(state: dict[str, Any]) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def update_monitoring_state(**fields: Any) -> dict[str, Any]:
    state = read_monitoring_state()
    state.update(fields)
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    write_monitoring_state(state)
    return state


def get_state_timestamp(key: str) -> datetime | None:
    raw = read_monitoring_state().get(key)
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt