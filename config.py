from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = DATA_DIR / "samples"
CACHE_DIR = DATA_DIR / "cache"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = BASE_DIR / "db" / "dashboard.db"

for directory in (SAMPLES_DIR, CACHE_DIR, REPORTS_DIR, DB_PATH.parent):
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
    local_only: bool = False


settings = Settings()


def is_local_only() -> bool:
    return settings.local_only