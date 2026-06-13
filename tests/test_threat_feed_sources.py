import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import httpx
import pytest

from config import Settings
from src.feeds.cache import read_cache, write_cache
from src.feeds.common import ioc_to_dict
from src.feeds.models import IOC
from src.feeds.sources import (
    THREATFOX_SOURCE,
    URLHAUS_SOURCE,
    fetch_otx,
    fetch_threatfox,
    fetch_urlhaus,
)


def _patch_feed_env(monkeypatch, tmp_path, **settings_kwargs):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr("config.CACHE_DIR", cache_dir)
    monkeypatch.setattr("src.feeds.cache.CACHE_DIR", cache_dir)

    settings = Settings(local_only=False, enable_live_feeds=True, **settings_kwargs)
    monkeypatch.setattr("config.settings", settings)
    for module in (
        "src.feeds.sources",
        "src.feeds.cache",
        "src.feeds.nvd_feed",
        "src.feeds.cisa_kev",
    ):
        monkeypatch.setattr(f"{module}.settings", settings)

    otx_key = settings_kwargs.get("_otx_key", "test-otx-key")
    abusech_key = settings_kwargs.get("_abusech_key", "test-auth-key")
    monkeypatch.setattr("config.get_otx_api_key", lambda: otx_key)
    monkeypatch.setattr("config.get_abusech_auth_key", lambda: abusech_key)
    monkeypatch.setattr("config.has_abusech_auth_key", lambda: bool(abusech_key))
    monkeypatch.setattr("src.feeds.sources.get_otx_api_key", lambda: otx_key)
    monkeypatch.setattr("src.feeds.sources.get_abusech_auth_key", lambda: abusech_key)
    monkeypatch.setattr("src.feeds.sources.has_abusech_auth_key", lambda: bool(abusech_key))
    return cache_dir


def test_fetch_urlhaus_parses_and_caches(monkeypatch, tmp_path):
    _patch_feed_env(monkeypatch, tmp_path, enable_urlhaus=True)

    payload = {
        "query_status": "ok",
        "urls": [
            {
                "url": "http://evil.example/malware",
                "threat": "malware_download",
                "tags": ["emotet", "exe"],
                "url_status": "online",
                "date_added": "2024-06-01 12:00:00 UTC",
            }
        ],
    }
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    monkeypatch.setattr("src.feeds.sources.urlhaus_get_recent", lambda **kwargs: response)

    result = fetch_urlhaus(force_refresh=True)
    assert result.live is True
    assert result.count == 1
    assert result.iocs[0].source == URLHAUS_SOURCE
    assert result.iocs[0].value == "http://evil.example/malware"
    assert "Successfully pulled" in (result.status_message or "")

    cached, meta = read_cache("urlhaus")
    assert cached is not None
    assert len(cached) == 1
    assert meta.stale is False


def test_fetch_urlhaus_rate_limit_uses_stale_cache(monkeypatch, tmp_path):
    cache_dir = _patch_feed_env(monkeypatch, tmp_path, enable_urlhaus=True)
    now = datetime.now(timezone.utc)
    cached_ioc = IOC("url", "http://cached.test", "high", URLHAUS_SOURCE, now, ["malware"], "cached")
    write_cache("urlhaus", [ioc_to_dict(cached_ioc)], source=URLHAUS_SOURCE)

    def _raise_rate_limit(*args, **kwargs):
        request = httpx.Request("GET", "https://example.test")
        response = httpx.Response(429, request=request)
        raise httpx.HTTPStatusError("rate limited", request=request, response=response)

    monkeypatch.setattr("src.feeds.sources.urlhaus_get_recent", lambda **kwargs: (_raise_rate_limit()))

    result = fetch_urlhaus(force_refresh=True)
    assert result.rate_limited is True
    assert result.stale is True
    assert result.count == 1
    assert result.iocs[0].value == "http://cached.test"


def test_fetch_threatfox_requires_auth_key(monkeypatch, tmp_path):
    _patch_feed_env(monkeypatch, tmp_path, enable_threatfox=True, _abusech_key="")
    monkeypatch.setattr("config.get_abusech_auth_key", lambda: "")
    monkeypatch.setattr("src.feeds.sources.get_abusech_auth_key", lambda: "")

    result = fetch_threatfox(force_refresh=True)
    assert result.error == "missing_auth_key"
    assert result.count == 0


def test_fetch_threatfox_parses_api_response(monkeypatch, tmp_path):
    _patch_feed_env(monkeypatch, tmp_path, enable_threatfox=True)

    payload = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil-c2.example",
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "threat_type_desc": "Botnet C&C",
                "malware_printable": "Dridex",
                "confidence_level": 80,
                "first_seen": "2024-06-01 10:00:00 UTC",
                "tags": ["banking"],
            }
        ],
    }
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    monkeypatch.setattr("src.feeds.sources.threatfox_post", lambda payload, **kwargs: response)

    result = fetch_threatfox(force_refresh=True)
    assert result.live is True
    assert result.count == 1
    assert result.iocs[0].source == THREATFOX_SOURCE
    assert result.iocs[0].severity == "high"
    assert "Dridex" in result.iocs[0].tags
    assert "Successfully pulled" in (result.status_message or "")


def test_fetch_otx_missing_key_serves_cache(monkeypatch, tmp_path):
    _patch_feed_env(monkeypatch, tmp_path, enable_otx=True, _otx_key="")
    monkeypatch.setattr("config.get_otx_api_key", lambda: "")
    monkeypatch.setattr("src.feeds.sources.get_otx_api_key", lambda: "")

    now = datetime.now(timezone.utc)
    cached_ioc = IOC("domain", "bad.otx", "medium", "AlienVault OTX", now, ["otx"], "pulse")
    write_cache("otx", [ioc_to_dict(cached_ioc)], source="AlienVault OTX")

    result = fetch_otx(force_refresh=True)
    assert result.error == "missing_api_key"
    assert result.count == 1
    assert result.iocs[0].value == "bad.otx"


def test_aggregator_includes_threatfox(monkeypatch, tmp_path):
    from src.feeds.aggregator import refresh_feeds

    cache_dir = _patch_feed_env(
        monkeypatch,
        tmp_path,
        enable_urlhaus=False,
        enable_otx=False,
        enable_threatfox=True,
        enable_nvd_feed=False,
        enable_cisa_kev=False,
    )
    now = datetime.now(timezone.utc).isoformat()
    (cache_dir / "threatfox.json").write_text(
        json.dumps(
            {
                "cached_at": now,
                "source": "ThreatFox",
                "items": [
                    {
                        "ioc_type": "domain",
                        "value": "tf.example",
                        "severity": "high",
                        "source": "ThreatFox",
                        "first_seen": now,
                        "tags": ["c2"],
                        "description": "ThreatFox test",
                    }
                ],
                "meta": {},
            }
        ),
        encoding="utf-8",
    )

    result = refresh_feeds(force_refresh=False)
    names = [source.name for source in result.sources if source.count]
    assert "threatfox" in names
    assert any(ioc.value == "tf.example" for ioc in result.iocs)