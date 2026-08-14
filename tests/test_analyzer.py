from src.data_import.ioc_importer import import_iocs_from_file
from src.logs.analyzer import analyze_logs
from src.logs.detectors import detect_alerts
from src.logs.parser import parse_log_file
from src.storage.repository import init_db, save_iocs


def test_analyzer_risk_scores(fixtures_dir, tmp_path, monkeypatch):
    monkeypatch.setattr("config.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("src.storage.repository.DB_PATH", tmp_path / "test.db")
    init_db()
    save_iocs(import_iocs_from_file(fixtures_dir / "demo_iocs.csv"))
    content = (fixtures_dir / "demo_attack.log").read_text(encoding="utf-8")
    entries = parse_log_file(content)
    alerts = detect_alerts(entries)
    analysis = analyze_logs(entries, alerts)

    assert analysis["total_entries"] > 0
    assert analysis["risk_scores"]
    assert analysis["risk_scores"][0]["risk_score"] > 0