from config import Settings
from src.feeds.cisa_kev import fetch_cisa_kev


class FakeResponse:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _online_env(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_ONLY", "false")
    monkeypatch.setenv("ENABLE_LIVE_FEEDS", "true")
    monkeypatch.setenv("ENABLE_CISA_KEV", "true")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.cisa_kev.settings", settings)
    monkeypatch.setattr("src.feeds.cache.settings", settings)


def test_cisa_kev_parses_catalog(monkeypatch, tmp_path):
    _online_env(monkeypatch, tmp_path)

    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Apache",
                "product": "HTTP Server",
                "dueDate": "2024-12-01",
                "knownRansomwareCampaignUse": "Known",
                "shortDescription": "Test KEV entry",
            }
        ]
    }

    monkeypatch.setattr(
        "src.feeds.cisa_kev.httpx.get",
        lambda *args, **kwargs: FakeResponse(payload),
    )

    result = fetch_cisa_kev(force_refresh=True)
    assert result.count == 1
    assert result.iocs[0].value == "CVE-2024-1234"
    assert result.iocs[0].severity == "critical"
    assert result.live is True


def test_cisa_kev_uses_cache_when_local_only(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_ONLY", "true")
    monkeypatch.setenv("ENABLE_CISA_KEV", "true")
    _online_env(monkeypatch, tmp_path)

    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-9999",
                "vendorProject": "Test",
                "product": "App",
                "dueDate": "2024-12-01",
                "knownRansomwareCampaignUse": "Unknown",
                "shortDescription": "Cached KEV",
            }
        ]
    }
    monkeypatch.setattr(
        "src.feeds.cisa_kev.httpx.get",
        lambda *args, **kwargs: FakeResponse(payload),
    )
    fetch_cisa_kev(force_refresh=True)

    monkeypatch.setenv("LOCAL_ONLY", "true")
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.cisa_kev.settings", settings)

    cached = fetch_cisa_kev(force_refresh=False)
    assert cached.count == 1
    assert cached.iocs[0].value == "CVE-2024-9999"
    assert cached.live is False