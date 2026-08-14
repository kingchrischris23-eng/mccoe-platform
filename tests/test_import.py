from src.data_import.ioc_importer import import_iocs_from_csv, import_iocs_from_json, parse_first_seen_value
from src.storage.repository import init_db, list_iocs, save_iocs


def test_import_csv(tmp_path, monkeypatch):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    csv_content = "ioc_type,value,severity,source,tags,description\nip,1.2.3.4,high,home,test,Test IP\n"
    iocs = import_iocs_from_csv(csv_content)
    save_iocs(iocs)
    rows = list_iocs()
    assert len(rows) == 1
    assert rows[0]["value"] == "1.2.3.4"


def test_import_json():
    json_content = '[{"ioc_type":"domain","value":"evil.example","severity":"critical","source":"import"}]'
    iocs = import_iocs_from_json(json_content)
    assert len(iocs) == 1
    assert iocs[0].value == "evil.example"


def test_import_csv_with_published_date():
    csv_content = (
        "ioc_type,value,severity,source,tags,description,first_seen\n"
        "cve,CVE-2024-0001,high,NIST NVD,nvd,Test CVE,2026-06-01T10:00:00+00:00\n"
    )
    iocs = import_iocs_from_csv(csv_content)
    assert iocs[0].value == "CVE-2024-0001"
    assert iocs[0].first_seen.year == 2026
    assert iocs[0].first_seen.month == 6


def test_parse_first_seen_accepts_date_only():
    dt = parse_first_seen_value("2026-05-15")
    assert dt.year == 2026 and dt.month == 5 and dt.day == 15