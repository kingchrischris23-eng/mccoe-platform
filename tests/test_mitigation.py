from datetime import datetime, timezone

import pytest

from src.feeds.cve_detail import is_cve, parse_nvd_detail
from src.feeds.mitigation import build_mitigation_brief


def test_is_cve_pattern():
    assert is_cve("CVE-2024-12345")
    assert not is_cve("10.0.0.1")


def test_build_cve_brief_uses_kev_required_action(monkeypatch):
    monkeypatch.setattr(
        "src.feeds.mitigation.collect_cve_context",
        lambda row: {
            "sources": ["CISA KEV"],
            "kev": {
                "cveID": "CVE-2026-10520",
                "vendorProject": "Ivanti",
                "product": "Sentry",
                "vulnerabilityName": "Ivanti Sentry OS Command Injection Vulnerability",
                "shortDescription": "Remote unauthenticated OS command injection allows root-level RCE.",
                "requiredAction": "Apply mitigations in accordance with vendor instructions.",
                "dueDate": "2026-06-14",
                "knownRansomwareCampaignUse": "Unknown",
            },
            "nvd": None,
        },
    )
    row = {
        "ioc_type": "cve",
        "value": "CVE-2026-10520",
        "severity": "critical",
        "source": "CISA KEV",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "tags": ["Ivanti"],
        "description": "Ivanti Sentry command injection | Due: 2026-06-14",
    }
    brief = build_mitigation_brief(row)
    assert brief.patch_available.startswith("Yes")
    assert brief.kev_required_action
    assert brief.kev_due_date == "2026-06-14"
    assert any("firewall" in step.lower() or "isolate" in step.lower() for step in brief.steps)
    assert brief.firewall_rules


def test_build_cve_brief_from_nvd_description(monkeypatch):
    monkeypatch.setattr(
        "src.feeds.mitigation.collect_cve_context",
        lambda row: {
            "sources": ["NIST NVD"],
            "kev": None,
            "nvd": {
                "cve_id": "CVE-2016-6129",
                "description": "Heap-based buffer overflow allows remote attackers to cause denial of service.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "references": [
                    {"url": "https://example.com/patch", "label": "Patch", "tags": ["Patch"]},
                ],
                "weaknesses": ["CWE-119"],
            },
        },
    )
    row = {
        "ioc_type": "cve",
        "value": "CVE-2016-6129",
        "severity": "high",
        "source": "NIST NVD",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "tags": ["nvd"],
        "description": "CVSS 7.5: Heap-based buffer overflow",
    }
    brief = build_mitigation_brief(row)
    assert "NIST NVD" in brief.data_sources
    assert brief.workarounds or brief.service_actions
    assert len(brief.steps) >= 4


def test_build_generic_ip_brief():
    row = {
        "ioc_type": "ip",
        "value": "203.0.113.50",
        "severity": "high",
        "source": "URLhaus",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "tags": [],
        "description": "Malicious C2 IP",
    }
    brief = build_mitigation_brief(row)
    assert brief.patch_available == "N/A"
    assert any("firewall" in rule.lower() or "block" in rule.lower() for rule in brief.firewall_rules)


def test_demo_lab_cve_uses_demo_details(monkeypatch):
    monkeypatch.setattr(
        "src.feeds.demo_cve._DETAILS_PATH",
        __import__("pathlib").Path(__file__).resolve().parents[1] / "data" / "demo" / "demo_cve_details.json",
    )
    monkeypatch.setattr("src.feeds.demo_cve._cache", None)
    row = {
        "ioc_type": "cve",
        "value": "CVE-2026-90001",
        "severity": "critical",
        "source": "MCCoE Lab Feed",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "tags": ["lab"],
        "description": "MCCoE training scenario VPN RCE",
    }
    brief = build_mitigation_brief(row)
    assert "MCCoE Lab Scenario" in brief.data_sources
    assert brief.kev_required_action
    assert brief.vendor == "BorderGuard"


def test_parse_nvd_detail_extracts_description():
    parsed = parse_nvd_detail(
        {
            "id": "CVE-2016-6129",
            "descriptions": [{"lang": "en", "value": "Example vulnerability description."}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}
                ]
            },
            "references": [{"url": "https://example.com", "tags": ["Vendor Advisory"]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-119"}]}],
        }
    )
    assert parsed["description"] == "Example vulnerability description."
    assert parsed["cvss_score"] == 7.5
    assert parsed["references"]