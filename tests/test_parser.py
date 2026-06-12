from src.logs.detectors import detect_alerts
from src.logs.parser import load_sample_log, parse_log_file


def test_parse_sample_log():
    content = load_sample_log()
    entries = parse_log_file(content)
    assert len(entries) >= 10
    assert entries[0]["source_ip"] == "198.51.100.42"


def test_detect_bruteforce_and_injection():
    content = load_sample_log()
    entries = parse_log_file(content)
    alerts = detect_alerts(entries)
    rule_ids = {alert["rule_id"] for alert in alerts}
    assert "AUTH-001" in rule_ids
    assert "WEB-001" in rule_ids
    assert "NET-001" in rule_ids