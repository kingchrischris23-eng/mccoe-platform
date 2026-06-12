REPORT_VERSION = "1.1"
ORG_NAME = "Missouri Cybersecurity Center of Excellence"
ORG_EMAIL = "support@mccoe.org"
REPORT_TITLE = "Threat Intelligence Training Report"
FOOTER_TRAINING = "FOR TRAINING PURPOSES ONLY"
FOOTER_CONFIDENTIAL = "CONFIDENTIAL - MCCoE Internal Training Use Only"

IOC_TYPE_EXPLANATIONS: dict[str, str] = {
    "ip": "Network address associated with attacks, scanning, or command-and-control activity.",
    "domain": "Hostname used in phishing campaigns, malware staging, or botnet infrastructure.",
    "url": "Web address delivering exploits, credential harvesters, or malicious payloads.",
    "hash": "File fingerprint (MD5/SHA) matching a known malware sample in threat intel feeds.",
    "email": "Sender address or mailbox linked to phishing or business email compromise.",
    "filename": "Observed malicious file name dropped during an intrusion or download event.",
}

RISK_LEGEND: list[tuple[str, str, str]] = [
    ("0-24", "Low", "Log and monitor; confirm against asset inventory."),
    ("25-49", "Medium", "Review within 24 hours; correlate with logs and feeds."),
    ("50-74", "High", "Prioritize investigation; prepare containment steps."),
    ("75-100", "Critical", "Escalate immediately; assume active compromise."),
]

TRAINING_QUESTIONS: list[str] = [
    "Which IOC type would you block first at the perimeter, and why?",
    "How would you distinguish a port-scan alert from a brute-force alert in the parsed logs?",
    "Two alerts share the same source IP as a threat-feed IOC - what is your first response step?",
    "A CVE with CVSS 7.5 affects an open service on the scanned host - walk through your patch-or-mitigate decision.",
    "What additional log sources would strengthen this report for a real SOC handoff?",
]