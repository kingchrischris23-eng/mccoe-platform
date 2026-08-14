"""Generate data/demo/demo_iocs.json from the curated catalog."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "demo" / "demo_iocs.json"

NOW = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


def d(days_ago: int, hour: int = 10) -> str:
    return (NOW - timedelta(days=days_ago)).replace(hour=hour).isoformat()


def row(ioc_type, value, severity, source, tags, description, days_ago: int) -> dict:
    return {
        "ioc_type": ioc_type,
        "value": value,
        "severity": severity,
        "source": source,
        "tags": tags,
        "description": description,
        "first_seen": d(days_ago),
    }


def build_catalog() -> list[dict]:
    items: list[dict] = []

    kev_cves = [
        ("CVE-2026-10520", "critical", 1, "Ivanti Sentry OS command injection — actively exploited"),
        ("CVE-2026-11645", "critical", 2, "Google Chromium V8 out-of-bounds R/W — remote code execution"),
        ("CVE-2026-7473", "critical", 3, "Arista EOS tunnel decapsulation flaw — network appliance exposure"),
        ("CVE-2026-20245", "critical", 4, "Cisco ASA/FTD VPN web service RCE under active exploitation"),
        ("CVE-2025-54236", "critical", 5, "Adobe Commerce/Magento sessionReaper — unauthenticated RCE"),
        ("CVE-2024-3400", "critical", 12, "Palo Alto PAN-OS GlobalProtect command injection — KEV priority"),
        ("CVE-2024-21762", "critical", 18, "Fortinet FortiOS out-of-bound write — edge device exposure"),
        ("CVE-2023-4966", "critical", 25, "Citrix Bleed — session token leak enabling bypass"),
        ("CVE-2023-34362", "critical", 40, "Progress MOVEit Transfer SQL injection — widespread exploitation"),
        ("CVE-2022-26134", "critical", 55, "Atlassian Confluence OGNL injection — unauthenticated RCE"),
        ("CVE-2021-44228", "critical", 90, "Log4Shell — JNDI injection in Java logging libraries"),
        ("CVE-2020-1472", "critical", 120, "Zerologon — Netlogon elevation of privilege"),
        ("CVE-2018-14558", "critical", 200, "Totolink router command injection — legacy edge device risk"),
        ("CVE-2017-0144", "critical", 300, "EternalBlue — SMBv1 remote code execution"),
        ("CVE-2014-0160", "high", 450, "Heartbleed — OpenSSL TLS heartbeat information disclosure"),
    ]
    for cve, severity, age, desc in kev_cves:
        items.append(row("cve", cve, severity, "CISA KEV", "kev;exploit;demo", desc, age))

    nvd_cves = [
        ("CVE-2016-6129", "high", 6, "CVSS 7.5: LibTomCrypt RSA verify hash validation flaw"),
        ("CVE-2017-2784", "critical", 8, "CVSS 9.8: ARM mbed TLS x509 stack pointer free vulnerability"),
        ("CVE-2017-7563", "high", 14, "CVSS 8.1: ARM Trusted Firmware executable RO memory mapping"),
        ("CVE-2015-5291", "low", 22, "CVSS 0.0: PolarSSL/mbed TLS heap buffer overflow"),
        ("CVE-2019-0708", "critical", 35, "CVSS 9.8: Windows RDP BlueKeep remote code execution"),
        ("CVE-2024-3094", "critical", 9, "XZ Utils backdoor — supply chain compromise in liblzma"),
        ("CVE-2023-22515", "critical", 16, "Atlassian Confluence broken access control — privilege escalation"),
        ("CVE-2022-41082", "high", 28, "Microsoft Exchange Server SSRF leading to remote code execution"),
    ]
    for cve, severity, age, desc in nvd_cves:
        items.append(row("cve", cve, severity, "NIST NVD", "nvd;cve;demo", desc, age))

    lab_cves = [
        ("CVE-2026-90001", "critical", 2, "MCCoE scenario: unauthenticated VPN portal RCE on border firewall"),
        ("CVE-2026-90002", "high", 7, "MCCoE scenario: ADCS template misconfiguration enables domain escalation"),
        ("CVE-2026-90003", "high", 15, "MCCoE scenario: public-facing Jenkins script console exposed"),
        ("CVE-2026-90004", "medium", 21, "MCCoE scenario: outdated Apache Tomcat manager interface reachable"),
        ("CVE-2026-90005", "medium", 33, "MCCoE scenario: SNMP default community on network management platform"),
    ]
    for cve, severity, age, desc in lab_cves:
        items.append(row("cve", cve, severity, "MCCoE Lab Feed", "lab;training;demo", desc, age))

    network = [
        ("ip", "198.51.100.42", "high", 3, "bruteforce;auth", "Repeated SSH and web login failures from residential ISP range"),
        ("ip", "203.0.113.77", "medium", 10, "scanner;recon", "Multi-port HTTP probe activity across /admin and /api paths"),
        ("ip", "192.0.2.58", "critical", 1, "malware;dropper", "Host serving follow-up payloads after phishing click"),
        ("ip", "198.18.0.44", "high", 4, "c2;beacon", "Short-interval HTTPS beaconing consistent with Cobalt Strike staging"),
        ("ip", "203.0.113.201", "high", 11, "c2;emotet", "Emotet epoch C2 node observed in emulated enterprise traffic"),
        ("ip", "198.51.100.88", "medium", 19, "scanner;shodan", "Internet-wide scanning for exposed RDP services"),
        ("ip", "192.0.2.101", "critical", 2, "ransomware;exfil", "Staging server for double-extortion data exfiltration drill"),
        ("ip", "203.0.113.55", "low", 27, "noise;scan", "Low-volume UDP probe activity on DNS resolvers"),
        ("domain", "secure-login-missouri.example", "critical", 2, "phishing;bec", "Typosquat domain impersonating university SSO portal"),
        ("domain", "cdn-updates-service.example", "high", 6, "malware;downloader", "Parked domain rotating A records to bulletproof hosting"),
        ("domain", "mail-delivery-alert.example", "medium", 13, "spam;credential", "SMTP HELO mismatch and suspicious attachment patterns"),
        ("domain", "vpn-access-portal.example", "critical", 3, "phishing;mfa", "Fake MFA portal harvesting Okta-style session cookies"),
        ("domain", "patch-windows-update.example", "high", 9, "malware;dropper", "Domain mimicking software update channel for DLL sideload"),
        ("domain", "hr-benefits-portal.example", "medium", 17, "phishing;hr", "HR-themed lure domain used in finance payroll drill"),
        ("url", "http://malware-lab.example/payload.exe", "high", 5, "malware;exe", "Direct EXE download linked to Emotet-style campaigns"),
        ("url", "https://cdn-updates-service.example/update.dll", "high", 8, "malware;dll", "DLL sideloading artifact masquerading as software update"),
        ("url", "http://198.18.0.44/gate.php", "critical", 1, "c2;webshell", "Web shell callback endpoint with encoded POST bodies"),
        ("url", "https://vpn-access-portal.example/auth/login", "critical", 2, "phishing;credential", "Credential harvesting page cloned from legitimate VPN vendor"),
        ("url", "http://203.0.113.201/beacon", "high", 4, "c2;https", "HTTPS C2 callback with jittered 90-second intervals"),
        ("hash", "9b1c7f4e2a8d6c0b5e3f1a9c7d2e4b6a", "critical", 3, "ransomware;lockbit", "LockBit-variant loader from healthcare tabletop exercise"),
        ("hash", "a3f5c8d1e7b2094f6c2d8a1e5b0c9f3d", "high", 7, "trojan;dropper", "PDF dropper hash from simulated spear-phishing exercise"),
        ("hash", "5d41402abc4b2a76b9719d911017c592", "medium", 20, "sample;md5", "Legacy MD5 sample used for hash-lookup training labs"),
        ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "low", 30, "sample;sha256", "Benign empty-file hash for negative-control hunting drills"),
        ("email", "alerts@secure-login-missouri.example", "high", 6, "phishing;bec", "Sender aligned with credential harvesting landing page"),
        ("email", "it-helpdesk@vpn-access-portal.example", "critical", 2, "phishing;urgent", "Urgent password-reset lure impersonating campus IT"),
        ("filename", "invoice_Q2_2026_macro.xlsm", "medium", 11, "malware;office", "Macro-enabled spreadsheet from finance-themed lure"),
        ("filename", "benefits_update_2026.pdf.exe", "high", 5, "malware;doubleext", "Double-extension payload from HR phishing simulation"),
    ]
    for ioc_type, value, severity, age, tags, desc in network:
        items.append(row(ioc_type, value, severity, "MCCoE Lab Feed", tags, desc, age))

    return items


def main() -> None:
    catalog = build_catalog()
    payload = {
        "title": "MCCoE Cyber Dashboard Demo IOC Catalog",
        "generated_at": NOW.isoformat(),
        "count": len(catalog),
        "iocs": catalog,
    }
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {len(catalog)} IOCs to {OUT}")


if __name__ == "__main__":
    main()