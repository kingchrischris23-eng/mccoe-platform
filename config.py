import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"


def _load_env() -> None:
    load_dotenv(ENV_FILE, override=True)


_load_env()

DATA_DIR = BASE_DIR / "data"
DEMO_DATA_DIR = DATA_DIR / "demo"
CACHE_DIR = DATA_DIR / "cache"
REPORTS_DIR = DATA_DIR / "reports"
SCANS_DIR = DATA_DIR / "scans"
DB_PATH = BASE_DIR / "db" / "dashboard.db"

for directory in (DEMO_DATA_DIR, CACHE_DIR, REPORTS_DIR, SCANS_DIR, DB_PATH.parent):
    directory.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    abuse_ch_auth_key: str = ""
    otx_api_key: str = ""
    nvd_api_key: str = ""
    enable_live_feeds: bool = False
    enable_auto_feed_refresh: bool = False
    auto_feed_refresh_hours: int = 24
    enable_urlhaus: bool = True
    enable_otx: bool = True
    enable_threatfox: bool = True
    enable_openphish: bool = False
    enable_nvd_feed: bool = True
    enable_cisa_kev: bool = True
    abusech_auth_key: str = ""
    feed_stale_fallback: bool = True
    instructor_mode: bool = False
    allowed_targets: str = "127.0.0.1,localhost"
    nmap_path: str = ""
    feed_cache_ttl_minutes: int = 15
    max_upload_mb: int = 50
    max_iocs_display: int = 50000  # legacy — no UI cap; pagination handles display
    max_iocs_report: int = 5000
    ioc_ui_page_size: int = 50
    ioc_recent_days: int = 30
    auto_report_on_upload: bool = True
    local_only: bool = True
    auto_load_demo: bool = False
    api_base_url: str = "http://127.0.0.1:8000"
    use_api_backend: bool = False
    api_auth_enabled: bool = True
    api_key: str = "mccoe-training-key"
    api_basic_user: str = "mccoe"
    api_basic_password: str = "training"


settings = Settings()


def ensure_settings_compat(target: Settings | None = None) -> Settings:
    """Patch missing fields on a long-lived settings singleton (restart-safe)."""
    obj = target or settings
    fresh = Settings()
    for field_name in Settings.model_fields:
        if not hasattr(obj, field_name):
            object.__setattr__(obj, field_name, getattr(fresh, field_name))
    return obj


def is_auto_feed_refresh_enabled() -> bool:
    ensure_settings_compat()
    return bool(getattr(settings, "enable_auto_feed_refresh", False))


def get_auto_feed_refresh_hours() -> int:
    ensure_settings_compat()
    return int(getattr(settings, "auto_feed_refresh_hours", 24))


IOC_HARD_CAP = 50000


def get_max_iocs_display() -> int:
    """Legacy alias — UI loads all IOCs via pagination (no practical cap)."""
    ensure_settings_compat()
    return max(5000, int(getattr(settings, "max_iocs_display", IOC_HARD_CAP)))


def get_max_iocs_report() -> int:
    ensure_settings_compat()
    report_val = int(getattr(settings, "max_iocs_report", 5000))
    return max(100, min(IOC_HARD_CAP, report_val))


def get_ioc_ui_page_size() -> int:
    ensure_settings_compat()
    return max(10, min(200, int(getattr(settings, "ioc_ui_page_size", 50))))


def get_ioc_recent_days() -> int:
    ensure_settings_compat()
    return max(1, int(getattr(settings, "ioc_recent_days", 30)))


def get_ioc_page_size() -> int:
    """Alias for UI pagination page size."""
    return get_ioc_ui_page_size()


ensure_settings_compat(settings)


def reload_settings() -> Settings:
    """Reload .env and refresh the shared settings object in-place."""
    _load_env()
    fresh = Settings()
    for field_name in Settings.model_fields:
        object.__setattr__(settings, field_name, getattr(fresh, field_name))
    return ensure_settings_compat(settings)


def get_nvd_api_key() -> str:
    """Resolve NVD API key: .env file first, then os.environ, then settings."""
    from src.config.env_store import read_env_value

    file_val = read_env_value("NVD_API_KEY")
    if file_val is not None:
        return file_val.strip()

    _load_env()
    env_val = os.getenv("NVD_API_KEY", "").strip()
    if env_val:
        return env_val

    return settings.nvd_api_key.strip()


def has_nvd_api_key() -> bool:
    return bool(get_nvd_api_key())


def get_otx_api_key() -> str:
    """Resolve OTX API key: .env file first, then os.environ, then settings."""
    from src.config.env_store import read_env_value

    file_val = read_env_value("OTX_API_KEY")
    if file_val is not None:
        return file_val.strip()

    _load_env()
    env_val = os.getenv("OTX_API_KEY", "").strip()
    if env_val:
        return env_val

    return settings.otx_api_key.strip()


def has_otx_api_key() -> bool:
    return bool(get_otx_api_key())


def get_abusech_auth_key() -> str:
    """Resolve abuse.ch Auth-Key (ThreatFox, URLhaus): .env first, then settings."""
    from src.config.env_store import read_env_value

    for env_name in ("ABUSECH_AUTH_KEY", "ABUSE_CH_AUTH_KEY"):
        file_val = read_env_value(env_name)
        if file_val is not None and file_val.strip():
            return file_val.strip()

    _load_env()
    for env_name in ("ABUSECH_AUTH_KEY", "ABUSE_CH_AUTH_KEY"):
        env_val = os.getenv(env_name, "").strip()
        if env_val:
            return env_val

    return (settings.abusech_auth_key or settings.abuse_ch_auth_key).strip()


def has_abusech_auth_key() -> bool:
    return bool(get_abusech_auth_key())


def get_nvd_key_debug_info() -> dict:
    """Diagnostic snapshot for the Settings page (no full secrets exposed)."""
    from src.config.env_store import ENV_PATH, mask_secret, read_env_value

    file_raw = read_env_value("NVD_API_KEY")
    file_key = (file_raw or "").strip()
    _load_env()
    env_key = os.getenv("NVD_API_KEY", "").strip()
    settings_key = settings.nvd_api_key.strip()
    resolved = get_nvd_api_key()

    return {
        "env_file_exists": ENV_PATH.exists(),
        "env_file_path": str(ENV_PATH),
        "env_file_key_masked": mask_secret(file_key),
        "env_file_key_length": len(file_key),
        "dotenv_key_length": len(env_key),
        "settings_key_length": len(settings_key),
        "resolved_key_masked": mask_secret(resolved),
        "resolved_key_length": len(resolved),
        "has_key": bool(resolved),
        "keys_in_sync": file_key == env_key == settings_key,
        "rate_mode": "with_key" if resolved else "no_key",
    }


def is_local_only() -> bool:
    return settings.local_only