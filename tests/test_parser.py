from src.logs.detectors import detect_alerts
from src.logs.parser import parse_log_file


def test_parse_fixture_log(fixtures_dir):
    content = (fixtures_dir / "demo_attack.log").read_text(encoding="utf-8")
    entries = parse_log_file(content)
    assert len(entries) >= 10
    assert entries[0]["source_ip"] == "198.51.100.42"


def test_detect_bruteforce_and_injection(fixtures_dir):
    content = (fixtures_dir / "demo_attack.log").read_text(encoding="utf-8")
    entries = parse_log_file(content)
    alerts = detect_alerts(entries)
    rule_ids = {alert["rule_id"] for alert in alerts}
    assert "AUTH-001" in rule_ids
    assert "WEB-001" in rule_ids
    assert "NET-001" in rule_ids