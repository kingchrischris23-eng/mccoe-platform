from dataclasses import dataclass, field
import re

from src.feeds.cve_detail import collect_cve_context, is_cve

PATCH_TAGS = {"patch", "vendor advisory", "mitigation", "release notes"}
WORKAROUND_TAGS = {"workaround", "temporary fix", "mitigation"}


@dataclass
class MitigationBrief:
    title: str
    summary: str
    severity: str
    ioc_type: str
    value: str
    source: str
    patch_available: str
    patch_notes: str
    workarounds: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    firewall_rules: list[str] = field(default_factory=list)
    service_actions: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    kev_required_action: str = ""
    kev_due_date: str = ""
    vendor: str = ""
    product: str = ""
    data_sources: list[str] = field(default_factory=list)


def build_mitigation_brief(row: dict) -> MitigationBrief:
    ioc_type = str(row.get("ioc_type", "unknown")).lower()
    value = str(row.get("value", "")).strip()
    severity = str(row.get("severity", "medium")).upper()
    source = str(row.get("source", "Unknown"))
    description = str(row.get("description", "")).strip()

    if is_cve(value):
        return _build_cve_brief(row, value, severity, source, description)

    return _build_generic_ioc_brief(row, ioc_type, value, severity, source, description)


def _build_cve_brief(row: dict, cve_id: str, severity: str, source: str, description: str) -> MitigationBrief:
    context = collect_cve_context(row)
    kev = context.get("kev") or {}
    nvd = context.get("nvd") or {}

    summary = (
        kev.get("shortDescription")
        or nvd.get("description")
        or _strip_cvss_prefix(description)
        or "No description available."
    )
    vendor = kev.get("vendorProject", "")
    product = kev.get("product", "")
    title = kev.get("vulnerabilityName") or f"{cve_id} — {vendor} {product}".strip(" —")

    refs = _normalize_references(nvd.get("references", []))
    patch_refs = [r for r in refs if _has_tag(r, PATCH_TAGS)]
    workaround_refs = [r for r in refs if _has_tag(r, WORKAROUND_TAGS)]

    patch_available, patch_notes = _assess_patch(
        description=summary,
        kev=kev,
        patch_refs=patch_refs,
        nvd=nvd,
    )
    workarounds = _extract_workarounds(kev, workaround_refs, summary)
    service_actions = _service_actions(summary, kev)
    firewall_rules = _firewall_rules(summary, ioc_type="cve", value=cve_id)
    steps = _ordered_steps(
        cve_id=cve_id,
        severity=severity,
        kev=kev,
        patch_available=patch_available,
        workarounds=workarounds,
        service_actions=service_actions,
        firewall_rules=firewall_rules,
        summary=summary,
    )

    data_sources = list(context.get("sources") or [])
    if not data_sources:
        data_sources = [source]

    return MitigationBrief(
        title=title,
        summary=summary,
        severity=severity,
        ioc_type="cve",
        value=cve_id,
        source=source,
        patch_available=patch_available,
        patch_notes=patch_notes,
        workarounds=workarounds,
        steps=steps,
        firewall_rules=firewall_rules,
        service_actions=service_actions,
        references=refs[:8],
        kev_required_action=kev.get("requiredAction", ""),
        kev_due_date=kev.get("dueDate", ""),
        vendor=vendor,
        product=product,
        data_sources=data_sources,
    )


def _build_generic_ioc_brief(
    row: dict,
    ioc_type: str,
    value: str,
    severity: str,
    source: str,
    description: str,
) -> MitigationBrief:
    summary = description or f"{ioc_type.upper()} indicator observed in threat feeds."
    firewall_rules = _firewall_rules(summary, ioc_type=ioc_type, value=value)
    service_actions = []
    workarounds = []

    if ioc_type in {"ip", "domain", "url"}:
        service_actions.append("Block or sinkhole this indicator at the perimeter firewall/proxy.")
        service_actions.append("Search SIEM and proxy logs for historical connections to this indicator.")
    elif ioc_type == "hash":
        service_actions.append("Hunt for matching file hashes across endpoints and quarantine matches.")
    else:
        service_actions.append("Validate whether this indicator appears in authentication or access logs.")

    steps = [
        "Confirm whether the indicator is present in your environment (logs, EDR, DNS, proxy).",
        *service_actions,
        *firewall_rules,
        "Document findings and remove temporary blocks only after threat hunt closure.",
    ]

    return MitigationBrief(
        title=f"{ioc_type.upper()} — {value}",
        summary=summary,
        severity=severity,
        ioc_type=ioc_type,
        value=value,
        source=source,
        patch_available="N/A",
        patch_notes="Patch guidance applies to CVEs. Use containment steps for network/file indicators.",
        workarounds=workarounds,
        steps=steps,
        firewall_rules=firewall_rules,
        service_actions=service_actions,
        references=[],
        data_sources=[source] if source else [],
    )


def _strip_cvss_prefix(text: str) -> str:
    return re.sub(r"^CVSS\s+[\d.]+:\s*", "", text or "").strip()


def _normalize_references(refs: list[dict]) -> list[dict]:
    normalized = []
    for ref in refs:
        url = ref.get("url", "")
        if not url:
            continue
        tags = [str(t) for t in (ref.get("tags") or [])]
        label = tags[0] if tags else ref.get("source") or "Reference"
        normalized.append({"url": url, "label": label, "tags": tags})
    return normalized


def _has_tag(ref: dict, tags: set[str]) -> bool:
    ref_tags = {t.lower() for t in ref.get("tags", [])}
    return bool(ref_tags & tags)


def _assess_patch(
    *,
    description: str,
    kev: dict,
    patch_refs: list[dict],
    nvd: dict,
) -> tuple[str, str]:
    text = description.lower()
    if kev:
        return (
            "Yes — vendor remediation required",
            "Listed in CISA Known Exploited Vulnerabilities (KEV). Apply vendor mitigations/patches per CISA guidance.",
        )
    if patch_refs:
        return (
            "Likely — vendor advisory available",
            f"NIST NVD lists {len(patch_refs)} vendor advisory/patch reference(s). Review before applying.",
        )
    if any(word in text for word in ("patch", "fixed in", "update to", "upgrade to")):
        return ("Likely — update available", "Description references a fix version; verify vendor security advisory.")
    if any(word in text for word in ("no fix", "won't fix", "will not fix", "unpatched")):
        return ("No known patch", "No fix mentioned; use compensating controls and isolation.")
    if nvd:
        return ("Unknown — check vendor advisory", "CVE is in NIST NVD; confirm patch status with the vendor.")
    return ("Unknown", "Patch status not confirmed from available feeds.")


def _extract_workarounds(kev: dict, workaround_refs: list[dict], description: str) -> list[str]:
    items: list[str] = []
    if kev.get("requiredAction"):
        items.append(kev["requiredAction"])
    for ref in workaround_refs[:3]:
        items.append(f"See vendor workaround: {ref['url']}")
    text = description.lower()
    if "workaround" in text or "mitigation" in text:
        items.append("Vendor description mentions mitigations — review the advisory for interim steps.")
    if "disable" in text:
        items.append("Disable affected feature or service until patching is complete.")
    if "restrict" in text or "limit access" in text:
        items.append("Restrict access to affected interfaces (VPN, ACL, or management network segmentation).")
    return _dedupe(items)


def _service_actions(summary: str, kev: dict) -> list[str]:
    text = summary.lower()
    actions: list[str] = []
    if kev:
        actions.append("Treat as actively exploited — prioritize emergency change window.")
    if any(k in text for k in ("remote code execution", "command injection", "arbitrary code")):
        actions.append("Disable or isolate internet-exposed instances of the affected service.")
    if "authentication bypass" in text:
        actions.append("Disable affected authentication paths and enforce MFA on adjacent systems.")
    if "denial of service" in text or "dos" in text:
        actions.append("Enable rate limiting and monitor resource exhaustion on affected services.")
    if "privilege escalation" in text:
        actions.append("Limit administrative access and audit privileged account activity.")
    if "firmware" in text or "embedded" in text:
        actions.append("Schedule firmware upgrade during maintenance; validate device inventory for affected models.")
    if not actions:
        actions.append("Update affected software/firmware to the latest vendor-supported release.")
    return _dedupe(actions)


def _firewall_rules(summary: str, *, ioc_type: str, value: str) -> list[str]:
    text = summary.lower()
    rules: list[str] = []
    if ioc_type in {"ip", "domain", "url"}:
        rules.append(f"Deny outbound/inbound traffic involving `{value}` at the firewall or proxy.")
    if any(k in text for k in ("remote", "unauthenticated", "internet", "externally reachable")):
        rules.append("Block external access to the vulnerable service until patched; allow management only via jump host.")
    if "sql injection" in text:
        rules.append("Deploy WAF/IPS rule to block known exploit patterns for this vulnerability class.")
    if ioc_type == "cve" and "c2" not in text:
        rules.append("Restrict lateral movement with network segmentation around assets running the vulnerable component.")
    return _dedupe(rules)


def _ordered_steps(
    *,
    cve_id: str,
    severity: str,
    kev: dict,
    patch_available: str,
    workarounds: list[str],
    service_actions: list[str],
    firewall_rules: list[str],
    summary: str,
) -> list[str]:
    steps: list[str] = [
        f"Identify assets running software affected by {cve_id} (CMDB, vulnerability scan, EDR inventory).",
    ]
    if kev.get("dueDate"):
        steps.append(f"CISA KEV remediation due date: {kev['dueDate']} — escalate if past due.")
    if severity in {"CRITICAL", "HIGH"} or kev:
        steps.append("Open an emergency change ticket and notify system owners.")
    steps.append(f"Patch status: {patch_available}. {patch_notes_if_short(patch_available)}")
    steps.extend(service_actions)
    steps.extend(workarounds)
    steps.extend(firewall_rules)
    steps.append("Validate remediation with a follow-up scan and monitor for exploitation attempts.")
    if "ransomware" in summary.lower() or kev.get("knownRansomwareCampaignUse", "").lower() == "known":
        steps.append("Hunt for ransomware precursors (backup deletion, suspicious SMB, credential dumping).")
    return _dedupe(steps)


def patch_notes_if_short(patch_available: str) -> str:
    if patch_available.startswith("Yes"):
        return "Apply vendor patches immediately."
    if patch_available.startswith("Likely"):
        return "Confirm fixed version with vendor bulletin."
    if patch_available.startswith("No"):
        return "Use isolation and compensating controls."
    return "Confirm with vendor security advisory."


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(item.strip())
    return result