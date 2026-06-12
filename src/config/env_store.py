import re
from pathlib import Path

from config import BASE_DIR

ENV_PATH = BASE_DIR / ".env"
ENV_EXAMPLE_PATH = BASE_DIR / ".env.example"
_ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def ensure_env_file() -> Path:
    if not ENV_PATH.exists():
        if ENV_EXAMPLE_PATH.exists():
            ENV_PATH.write_text(ENV_EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            ENV_PATH.write_text("", encoding="utf-8")
    return ENV_PATH


def read_env_value(key: str) -> str | None:
    if not _ENV_KEY_PATTERN.match(key):
        raise ValueError(f"Invalid env key: {key}")
    if not ENV_PATH.exists():
        return None
    prefix = f"{key}="
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix) :]
    return None


def update_env_value(key: str, value: str) -> None:
    if not _ENV_KEY_PATTERN.match(key):
        raise ValueError(f"Invalid env key: {key}")
    path = ensure_env_file()
    lines = path.read_text(encoding="utf-8").splitlines()
    prefix = f"{key}="
    updated = False
    new_lines: list[str] = []

    for line in lines:
        if line.strip().startswith(prefix):
            new_lines.append(f"{key}={value}")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        new_lines.append(f"{key}={value}")

    path.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")


def mask_secret(value: str) -> str:
    if not value:
        return "Not configured"
    if len(value) <= 4:
        return "Configured (hidden)"
    return f"Configured (ends with ...{value[-4:]})"