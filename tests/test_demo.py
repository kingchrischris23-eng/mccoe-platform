import json

from src.data_import.demo_loader import load_demo_data
from src.storage.repository import get_overview_stats, init_db


def test_demo_loader_explicit_only(tmp_path, monkeypatch):
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    (demo_dir / "demo_iocs.csv").write_text(
        "ioc_type,value,severity,source,tags,description\nip,9.9.9.9,high,demo,test,Demo IP\n",
        encoding="utf-8",
    )
    (demo_dir / "demo_attack.log").write_text(
        '9.9.9.9 - - [10/Jun/2026:08:01:01 +0000] "POST /login HTTP/1.1" 403 512 "-" "bot"\n' * 6,
        encoding="utf-8",
    )
    (demo_dir / "demo_vuln_scan.json").write_text(
        json.dumps(
            {
                "target": "127.0.0.1",
                "open_ports": [{"port": 80, "service": "http"}],
                "header_issues": [],
                "cve_findings": [],
                "risk_score": 10.0,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("config.DEMO_DATA_DIR", demo_dir)
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.data_import.demo_loader.DEMO_DATA_DIR", demo_dir)
    init_db()

    summary = load_demo_data()
    stats = get_overview_stats()
    assert summary["iocs"] == 1
    assert summary["alerts"] >= 1
    assert summary["vuln_scans"] == 1
    assert stats["ioc_count"] == 1


def test_demo_loader_uses_json_catalog(tmp_path, monkeypatch):
    demo_dir = tmp_path / "demo"
    demo_dir.mkdir()
    (demo_dir / "demo_iocs.json").write_text(
        json.dumps(
            {
                "iocs": [
                    {
                        "ioc_type": "cve",
                        "value": "CVE-2026-90001",
                        "severity": "critical",
                        "source": "MCCoE Lab Feed",
                        "tags": "lab;demo",
                        "description": "Lab scenario",
                        "first_seen": "2026-06-09T10:00:00+00:00",
                    },
                    {
                        "ioc_type": "ip",
                        "value": "198.51.100.42",
                        "severity": "high",
                        "source": "MCCoE Lab Feed",
                        "tags": "scanner",
                        "description": "Scanner IP",
                        "first_seen": "2026-05-01T10:00:00+00:00",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("config.DEMO_DATA_DIR", demo_dir)
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.data_import.demo_loader.DEMO_DATA_DIR", demo_dir)
    init_db()

    summary = load_demo_data()
    assert summary["iocs"] == 2
    assert summary["ioc_breakdown"]["cves"] == 1
    assert summary["ioc_breakdown"]["fresh"] >= 1
    assert summary["ioc_breakdown"]["older"] >= 1