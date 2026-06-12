import pytest
from fastapi.testclient import TestClient

from config import Settings
from src.feeds.sources import load_sample_iocs
from src.storage.repository import init_db, save_iocs, save_vuln_scan


@pytest.fixture
def api_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    monkeypatch.setenv("LOCAL_ONLY", "true")
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("config.settings", Settings())
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs(load_sample_iocs())
    save_vuln_scan(
        {
            "target": "127.0.0.1",
            "open_ports": [{"port": 80, "service": "http"}],
            "header_issues": [],
            "cve_findings": [],
            "risk_score": 30.0,
        }
    )
    from api.main import app

    return TestClient(app)


def test_health(api_settings):
    response = api_settings.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_list_threats(api_settings):
    response = api_settings.get("/api/threats", params={"severity": "high"})
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 1
    assert all(item["severity"] == "high" for item in data["iocs"])


def test_analyze_logs(api_settings):
    log_line = (
        '198.51.100.42 - - [10/Jun/2026:08:01:01 +0000] "POST /login HTTP/1.1" 403 512 "-" "bot"\n'
    ) * 6
    response = api_settings.post(
        "/api/logs/analyze",
        json={"filename": "test.log", "content": log_line},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["entries_parsed"] == 6
    assert data["alerts_found"] >= 1


def test_vulnerabilities(api_settings):
    response = api_settings.get("/api/vulnerabilities")
    assert response.status_code == 200
    assert response.json()["count"] >= 1


def test_generate_report(api_settings, monkeypatch, tmp_path):
    monkeypatch.setattr("src.reports.generator.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.reports.markdown.REPORTS_DIR", tmp_path)
    response = api_settings.post("/api/reports/generate", json={"format": "markdown", "auto": False})
    assert response.status_code == 200
    assert response.json()["files"][0]["format"] == "markdown"


def test_auth_required(monkeypatch, tmp_path):
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    monkeypatch.setenv("API_KEY", "secret-key")
    monkeypatch.setattr("config.DB_PATH", tmp_path / "auth.db")
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("api.auth.settings", settings)
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "auth.db")
    init_db()
    from api.main import app

    client = TestClient(app)
    denied = client.get("/api/threats")
    assert denied.status_code == 401

    allowed = client.get("/api/threats", headers={"X-API-Key": "secret-key"})
    assert allowed.status_code == 200