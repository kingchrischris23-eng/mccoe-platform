from src.feeds.common import normalize_tags, score_severity


def test_normalize_tags_flattens_urlhaus_shape():
    tags = normalize_tags("malware_download", ["elf", "mirai"])
    assert tags == ["malware_download", "elf", "mirai"]


def test_score_severity_accepts_normalized_tags():
    tags = normalize_tags("malware_download", ["ransomware"])
    assert score_severity(tags, "URLhaus entry: online") == "critical"