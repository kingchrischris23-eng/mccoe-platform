import json
from types import SimpleNamespace

import pytest

from src.network.safety import parse_port_range, validate_scan_target
from src.network.scanner import run_network_scan


def test_parse_port_range_valid():
    assert parse_port_range("1-1000") == "1-1000"
    assert parse_port_range("80,443") == "80,443"


def test_parse_port_range_invalid():
    with pytest.raises(ValueError):
        parse_port_range("0-80")
    with pytest.raises(ValueError):
        parse_port_range("abc")


def test_validate_single_host_allowlisted(monkeypatch):
    monkeypatch.setattr("src.network.safety.settings.instructor_mode", False)
    assert validate_scan_target("127.0.0.1") == "127.0.0.1"


def test_validate_subnet_requires_instructor(monkeypatch):
    monkeypatch.setattr("src.network.safety.settings.instructor_mode", False)
    with pytest.raises(PermissionError):
        validate_scan_target("192.168.1.0/24")


def test_validate_subnet_instructor_mode(monkeypatch):
    monkeypatch.setattr("src.network.safety.settings.instructor_mode", True)
    assert validate_scan_target("192.168.1.0/24") == "192.168.1.0/24"


def test_run_network_scan_parses_results(monkeypatch, tmp_path):
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    monkeypatch.setattr("config.SCANS_DIR", scans_dir)
    monkeypatch.setattr("src.network.scanner.SCANS_DIR", scans_dir)
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    from src.storage.repository import init_db

    init_db()

    class TCPInfo:
        def keys(self):
            return [80]

        def __getitem__(self, port):
            return {
                "state": "open",
                "name": "http",
                "product": "Apache",
                "version": "2.4",
                "extrainfo": "",
            }

    class HostScan:
        def state(self):
            return "up"

        def all_protocols(self):
            return ["tcp"]

        def __getitem__(self, proto):
            return TCPInfo()

    class FakePortScanner:
        def scan(self, hosts, arguments):
            self._host = HostScan()

        def all_hosts(self):
            return ["127.0.0.1"]

        def __getitem__(self, host):
            return self._host

    fake_nmap = SimpleNamespace(PortScanner=lambda: FakePortScanner(), PortScannerError=RuntimeError)
    monkeypatch.setitem(__import__("sys").modules, "nmap", fake_nmap)

    result = run_network_scan("127.0.0.1", "1-1000", "Quick")
    assert result["hosts_up"] == 1
    assert result["open_port_count"] == 1
    assert result["results"][0]["port"] == 80
    json_files = list((tmp_path / "scans").glob("network_scan_*.json"))
    assert len(json_files) == 1
    saved = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert saved["target"] == "127.0.0.1"