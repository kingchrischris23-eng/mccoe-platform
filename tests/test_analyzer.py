from src.logs.analyzer import analyze_logs
from src.logs.detectors import detect_alerts
from src.logs.parser import load_sample_log, parse_log_file
from src.storage.repository import init_db, save_iocs
from src.feeds.sources import load_sample_iocs


def test_analyzer_risk_scores():
    init_db()
    save_iocs(load_sample_iocs())
    entries = parse_log_file(load_sample_log())
    alerts = detect_alerts(entries)
    analysis = analyze_logs(entries, alerts)

    assert analysis["total_entries"] > 0
    assert analysis["risk_scores"]
    assert analysis["risk_scores"][0]["risk_score"] > 0