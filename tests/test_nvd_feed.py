from datetime import datetime, timezone

from config import Settings
from src.feeds.common import ioc_to_dict
from src.feeds.nvd_feed import fetch_nvd_feed


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.status_code = status_code
        self._payload = payload
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self):
        return self._payload


def _online_env(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCAL_ONLY", "false")
    monkeypatch.setenv("ENABLE_LIVE_FEEDS", "true")
    monkeypatch.setenv("ENABLE_NVD_FEED", "true")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)
    settings = Settings()
    monkeypatch.setattr("config.settings", settings)
    monkeypatch.setattr("src.feeds.nvd_feed.settings", settings)
    monkeypatch.setattr("src.feeds.cache.settings", settings)



def test_nvd_feed_parses_cves(monkeypatch, tmp_path):
    _online_env(monkeypatch, tmp_path)
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-5678",
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]
                    },
                }
            }
        ]
    }

    monkeypatch.setattr(
        "src.feeds.nvd_feed.httpx.get",
        lambda *args, **kwargs: FakeResponse(payload),
    )
    monkeypatch.setattr(
        "src.feeds.nvd_feed.request_with_backoff",
        lambda source, interval, fn, **kwargs: fn(),
    )

    result = fetch_nvd_feed(force_refresh=True)
    assert result.count == 1
    assert result.iocs[0].value == "CVE-2024-5678"
    assert result.iocs[0].severity == "critical"
    assert result.live is True


def test_nvd_rate_limit_falls_back_to_cache(monkeypatch, tmp_path):
    _online_env(monkeypatch, tmp_path)
    from src.feeds.cache import write_cache
    from src.feeds.models import IOC

    ioc = IOC(
        ioc_type="cve",
        value="CVE-2024-0001",
        severity="high",
        source="NIST NVD",
        first_seen=datetime.now(timezone.utc),
        tags=["nvd"],
        description="cached",
    )
    write_cache("nist_nvd", [ioc_to_dict(ioc)], source="NIST NVD")

    def raise_rate_limit():
        return FakeResponse({}, status_code=429)

    monkeypatch.setattr(
        "src.feeds.nvd_feed.request_with_backoff",
        lambda source, interval, fn, **kwargs: (_ for _ in ()).throw(
            __import__("httpx").HTTPStatusError("rate limited", request=None, response=FakeResponse({}, 429))
        ),
    )

    result = fetch_nvd_feed(force_refresh=True)
    assert result.count == 1
    assert result.iocs[0].value == "CVE-2024-0001"
    assert result.stale is True