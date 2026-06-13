import os
import shutil
import sys
from pathlib import Path

from config import settings

WINDOWS_NMAP_PATHS = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


def _is_executable(path: str) -> bool:
    return bool(path) and Path(path).is_file()


def _configured_path() -> str:
    return (getattr(settings, "nmap_path", "") or os.getenv("NMAP_PATH", "")).strip()


def _candidate_paths() -> list[str]:
    candidates: list[str] = []

    configured = _configured_path()
    if configured:
        candidates.append(configured)

    if sys.platform == "win32":
        for path in WINDOWS_NMAP_PATHS:
            if _is_executable(path):
                candidates.append(path)

    on_path = shutil.which("nmap")
    if on_path:
        candidates.append(on_path)

    candidates.append("nmap")

    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def get_resolved_nmap_path() -> str | None:
    """Return the first Nmap executable that exists on disk (or on PATH)."""
    for candidate in _candidate_paths():
        if candidate == "nmap":
            on_path = shutil.which("nmap")
            if on_path:
                return on_path
            continue
        if _is_executable(candidate):
            return candidate
    return None


def resolve_nmap_search_path() -> tuple[str, ...]:
    """Paths for python-nmap — prefer a single known-good executable when found."""
    resolved = get_resolved_nmap_path()
    if resolved:
        return (resolved,)
    return tuple(_candidate_paths())


def nmap_bin_directory() -> str | None:
    resolved = get_resolved_nmap_path()
    if not resolved or resolved == "nmap":
        return None
    return str(Path(resolved).parent)


def apply_nmap_path_env() -> str | None:
    """Prepend Nmap's install folder to PATH for subprocess/DLL resolution."""
    nmap_dir = nmap_bin_directory()
    if not nmap_dir:
        return None
    current = os.environ.get("PATH", "")
    if nmap_dir.casefold() not in current.casefold():
        os.environ["PATH"] = nmap_dir + os.pathsep + current
    return nmap_dir


def ensure_nmap_path_configured() -> str | None:
    """Persist auto-detected Nmap path to .env when not already set."""
    resolved = get_resolved_nmap_path()
    if not resolved or _configured_path():
        return resolved

    try:
        from config import reload_settings
        from src.config.env_store import update_env_value

        update_env_value("NMAP_PATH", resolved)
        reload_settings()
    except OSError:
        pass
    return resolved