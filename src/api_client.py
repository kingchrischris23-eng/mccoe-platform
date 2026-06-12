from typing import Any

import httpx

from config import settings


class DashboardAPIError(Exception):
    pass


class DashboardAPI:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        basic_user: str | None = None,
        basic_password: str | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = (base_url or settings.api_base_url).rstrip("/")
        self.api_key = api_key or settings.api_key
        self.basic_user = basic_user or settings.api_basic_user
        self.basic_password = basic_password or settings.api_basic_password
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _auth(self) -> tuple[str, str] | None:
        if self.basic_user and self.basic_password:
            return (self.basic_user, self.basic_password)
        return None

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = httpx.request(
                method,
                url,
                headers=self._headers(),
                auth=self._auth(),
                timeout=self.timeout,
                **kwargs,
            )
            response.raise_for_status()
            if response.headers.get("content-type", "").startswith("application/json"):
                return response.json()
            return response.content
        except httpx.HTTPError as exc:
            raise DashboardAPIError(str(exc)) from exc

    def health(self) -> dict:
        return self._request("GET", "/api/health")

    def is_available(self) -> bool:
        try:
            result = self.health()
            return result.get("status") == "ok"
        except DashboardAPIError:
            return False

    def get_threats(
        self,
        severity: str | None = None,
        ioc_type: str | None = None,
        source: str | None = None,
        search: str | None = None,
        limit: int = 100,
        refresh: bool = False,
    ) -> dict:
        params = {"limit": limit, "refresh": refresh}
        if severity:
            params["severity"] = severity
        if ioc_type:
            params["ioc_type"] = ioc_type
        if source:
            params["source"] = source
        if search:
            params["search"] = search
        return self._request("GET", "/api/threats", params=params)

    def analyze_logs(self, filename: str, content: str) -> dict:
        return self._request(
            "POST",
            "/api/logs/analyze",
            json={"filename": filename, "content": content},
        )

    def analyze_logs_upload(self, filename: str, content: bytes) -> dict:
        return self._request(
            "POST",
            "/api/logs/analyze/upload",
            files={"file": (filename, content, "text/plain")},
        )

    def get_vulnerabilities(self, target: str | None = None, limit: int = 20) -> dict:
        params: dict[str, Any] = {"limit": limit}
        if target:
            params["target"] = target
        return self._request("GET", "/api/vulnerabilities", params=params)

    def generate_report(self, fmt: str = "pdf", auto: bool = False) -> dict:
        return self._request(
            "POST",
            "/api/reports/generate",
            json={"format": fmt, "auto": auto},
        )

    def import_iocs(self, iocs: list[dict]) -> dict:
        return self._request("POST", "/api/threats/import", json={"iocs": iocs})

    def add_vulnerability(self, payload: dict) -> dict:
        return self._request("POST", "/api/vulnerabilities", json=payload)

    def load_demo_data(self) -> dict:
        return self._request("POST", "/api/demo/load")

    def clear_data(self) -> dict:
        return self._request("DELETE", "/api/data")


def get_api_client() -> DashboardAPI | None:
    if not settings.use_api_backend:
        return None
    return DashboardAPI()