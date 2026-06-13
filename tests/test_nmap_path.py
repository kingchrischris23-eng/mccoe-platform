import pytest

from src.network.nmap_path import get_resolved_nmap_path, resolve_nmap_search_path


def _clear_configured_nmap(monkeypatch):
    monkeypatch.setattr("src.network.nmap_path.settings.nmap_path", "")
    monkeypatch.setenv("NMAP_PATH", "")


def test_resolve_uses_single_known_path(tmp_path, monkeypatch):
    nmap_exe = tmp_path / "nmap.exe"
    nmap_exe.write_bytes(b"stub")

    _clear_configured_nmap(monkeypatch)
    monkeypatch.setattr("src.network.nmap_path.WINDOWS_NMAP_PATHS", (str(nmap_exe),))
    monkeypatch.setattr("src.network.nmap_path.shutil.which", lambda _: None)

    paths = resolve_nmap_search_path()
    assert paths == (str(nmap_exe),)


def test_configured_nmap_path_is_first(tmp_path, monkeypatch):
    custom = tmp_path / "nmap.exe"
    custom.write_bytes(b"stub")
    monkeypatch.setattr("src.network.nmap_path.settings.nmap_path", str(custom))
    monkeypatch.setattr("src.network.nmap_path.WINDOWS_NMAP_PATHS", ())
    monkeypatch.setattr("src.network.nmap_path.shutil.which", lambda _: None)

    paths = resolve_nmap_search_path()
    assert paths == (str(custom),)


def test_get_resolved_nmap_path_prefers_existing_file(tmp_path, monkeypatch):
    nmap_exe = tmp_path / "nmap.exe"
    nmap_exe.write_bytes(b"stub")
    _clear_configured_nmap(monkeypatch)
    monkeypatch.setattr("src.network.nmap_path.WINDOWS_NMAP_PATHS", (str(nmap_exe),))
    monkeypatch.setattr("src.network.nmap_path.shutil.which", lambda _: None)

    assert get_resolved_nmap_path() == str(nmap_exe)


def test_get_resolved_nmap_path_returns_none_when_missing(monkeypatch):
    _clear_configured_nmap(monkeypatch)
    monkeypatch.setattr("src.network.nmap_path.WINDOWS_NMAP_PATHS", ())
    monkeypatch.setattr("src.network.nmap_path.shutil.which", lambda _: None)

    assert get_resolved_nmap_path() is None