from config import Settings, get_nvd_api_key, has_nvd_api_key, reload_settings


def _patch_env(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    monkeypatch.setattr("config.ENV_FILE", env_file)
    monkeypatch.setattr("config.BASE_DIR", tmp_path)
    monkeypatch.setattr("src.config.env_store.ENV_PATH", env_file)
    monkeypatch.setattr("src.config.env_store.BASE_DIR", tmp_path)
    return env_file


def test_has_nvd_api_key_reads_from_env_file(monkeypatch, tmp_path):
    env_file = _patch_env(monkeypatch, tmp_path)
    env_file.write_text("NVD_API_KEY=abc123-test-key\n", encoding="utf-8")

    monkeypatch.setattr("config.settings", Settings(_env_file=str(env_file)))
    assert has_nvd_api_key() is True
    assert get_nvd_api_key() == "abc123-test-key"


def test_has_nvd_api_key_false_when_empty(monkeypatch, tmp_path):
    env_file = _patch_env(monkeypatch, tmp_path)
    env_file.write_text("NVD_API_KEY=\n", encoding="utf-8")
    monkeypatch.setattr("config.settings", Settings(_env_file=str(env_file)))

    assert has_nvd_api_key() is False
    assert get_nvd_api_key() == ""


def test_reload_settings_updates_shared_object(monkeypatch, tmp_path):
    env_file = _patch_env(monkeypatch, tmp_path)
    env_file.write_text("NVD_API_KEY=first\n", encoding="utf-8")
    settings = Settings(_env_file=str(env_file))
    monkeypatch.setattr("config.settings", settings)

    env_file.write_text("NVD_API_KEY=second\nLOCAL_ONLY=true\n", encoding="utf-8")
    reload_settings()

    assert settings.nvd_api_key == "second"
    assert get_nvd_api_key() == "second"
    assert has_nvd_api_key() is True


def test_probe_nvd_api_connection_success(monkeypatch):
    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"totalResults": 999}

    monkeypatch.setattr(
        "src.feeds.nvd_probe.request_with_backoff",
        lambda source, interval, fn, **kwargs: fn(),
    )
    monkeypatch.setattr("src.feeds.nvd_probe.httpx.get", lambda *a, **k: FakeResponse())
    monkeypatch.setattr("src.feeds.nvd_probe.has_nvd_api_key", lambda: True)
    monkeypatch.setattr("src.feeds.nvd_probe.get_nvd_api_key", lambda: "test-key")

    from src.feeds.nvd_probe import probe_nvd_api_connection

    result = probe_nvd_api_connection()
    assert result["success"] is True
    assert "999" in result["message"]