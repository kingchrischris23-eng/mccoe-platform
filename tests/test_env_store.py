from src.config.env_store import ensure_env_file, mask_secret, read_env_value, update_env_value


def test_update_and_read_env_value(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("LOCAL_ONLY=true\n", encoding="utf-8")
    monkeypatch.setattr("src.config.env_store.ENV_PATH", env_file)
    monkeypatch.setattr("src.config.env_store.ENV_EXAMPLE_PATH", tmp_path / ".env.example")

    update_env_value("NVD_API_KEY", "test-key-value")
    assert read_env_value("NVD_API_KEY") == "test-key-value"
    content = env_file.read_text(encoding="utf-8")
    assert "LOCAL_ONLY=true" in content
    assert "NVD_API_KEY=test-key-value" in content


def test_update_existing_env_value(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("NVD_API_KEY=old\nOTHER=1\n", encoding="utf-8")
    monkeypatch.setattr("src.config.env_store.ENV_PATH", env_file)

    update_env_value("NVD_API_KEY", "new")
    assert read_env_value("NVD_API_KEY") == "new"
    assert read_env_value("OTHER") == "1"


def test_clear_env_value(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("NVD_API_KEY=secret\n", encoding="utf-8")
    monkeypatch.setattr("src.config.env_store.ENV_PATH", env_file)

    update_env_value("NVD_API_KEY", "")
    assert read_env_value("NVD_API_KEY") == ""


def test_mask_secret_hides_value():
    assert mask_secret("") == "Not configured"
    assert "ends with" in mask_secret("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    assert "aaaaaaaa" not in mask_secret("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def test_ensure_env_file_from_example(tmp_path, monkeypatch):
    example = tmp_path / ".env.example"
    example.write_text("LOCAL_ONLY=true\n", encoding="utf-8")
    env_file = tmp_path / ".env"
    monkeypatch.setattr("src.config.env_store.ENV_PATH", env_file)
    monkeypatch.setattr("src.config.env_store.ENV_EXAMPLE_PATH", example)

    ensure_env_file()
    assert env_file.exists()
    assert "LOCAL_ONLY=true" in env_file.read_text(encoding="utf-8")