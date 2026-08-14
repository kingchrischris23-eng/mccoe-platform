import secrets

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials

from config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
http_basic = HTTPBasic(auto_error=False)


def verify_api_auth(
    api_key: str | None = Security(api_key_header),
    credentials: HTTPBasicCredentials | None = Depends(http_basic),
) -> str:
    if not settings.api_auth_enabled:
        return "auth-disabled"

    if api_key and secrets.compare_digest(api_key, settings.api_key):
        return "api-key"

    if credentials:
        user_ok = secrets.compare_digest(credentials.username, settings.api_basic_user)
        pass_ok = secrets.compare_digest(credentials.password, settings.api_basic_password)
        if user_ok and pass_ok:
            return "basic-auth"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing credentials. Provide X-API-Key header or HTTP Basic auth.",
        headers={"WWW-Authenticate": "Basic"},
    )