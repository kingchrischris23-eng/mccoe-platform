from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DEMO_DATA_DIR = DATA_DIR / "demo"
CACHE_DIR = DATA_DIR / "cache"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = BASE_DIR / "db" / "dashboard.db"

for directory in (DEMO_DATA_DIR, CACHE_DIR, REPORTS_DIR, DB_PATH.parent):
    directory.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    otx_api_key: str = ""
    nvd_api_key: str = ""
    instructor_mode: bool = False
    allowed_targets: str = "127.0.0.1,localhost"
    feed_cache_ttl_minutes: int = 15
    max_upload_mb: int = 50
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


def is_local_only() -> bool:
    return settings.local_only