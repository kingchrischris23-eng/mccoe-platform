import re

import httpx

from src.feeds.demo_cve import lookup_demo_cve_entry
from src.feeds.kev_index import lookup_kev_entry
from src.feeds.nvd_auth import nvd_request_headers
from src.feeds.rate_limit import nvd_interval_seconds, request_with_backoff

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def is_cve(value: str) -> bool:
    return bool(CVE_PATTERN.match(str(value or "").strip()))


def fetch_nvd_cve_detail(cve_id: str) -> dict | None:
    cve_id = cve_id.strip().upper()
    if not is_cve(cve_id):
        return None

    def _do_request():
        return httpx.get(
            NVD_URL,
            params={"cveId": cve_id},
            headers=nvd_request_headers(),
            timeout=25.0,
        )

    try:
        response = request_with_backoff("nvd", nvd_interval_seconds(), _do_request)
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        return vulnerabilities[0].get("cve", {})
    except httpx.HTTPError:
        return None


def parse_nvd_detail(cve_payload: dict | None) -> dict:
    if not cve_payload:
        return {}

    descriptions = [
        d.get("value", "")
        for d in cve_payload.get("descriptions", [])
        if d.get("lang") == "en" and d.get("value")
    ]
    metrics = cve_payload.get("metrics", {}).get("cvssMetricV31", [])
    cvss_score = None
    vector = ""
    if metrics:
        cvss_data = metrics[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString", "")

    references = []
    for ref in cve_payload.get("references", []):
        url = ref.get("url", "")
        if not url:
            continue
        tags = ref.get("tags") or []
        references.append({"url": url, "tags": tags, "source": ref.get("source", "")})

    weaknesses = []
    for weakness in cve_payload.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                weaknesses.append(desc.get("value", ""))

    return {
        "cve_id": cve_payload.get("id", ""),
        "description": descriptions[0] if descriptions else "",
        "cvss_score": cvss_score,
        "cvss_vector": vector,
        "references": references,
        "weaknesses": weaknesses,
        "published": cve_payload.get("published", ""),
        "last_modified": cve_payload.get("lastModified", ""),
    }


def collect_cve_context(row: dict) -> dict:
    """Merge IOC row, CISA KEV index, and optional live NVD lookup."""
    value = str(row.get("value", "")).strip()
    context = {
        "ioc": row,
        "kev": None,
        "nvd": None,
        "sources": [],
    }

    if is_cve(value):
        demo = lookup_demo_cve_entry(value)
        if demo:
            context["kev"] = demo
            context["sources"].append("MCCoE Lab Scenario")

        kev = lookup_kev_entry(value)
        if kev:
            context["kev"] = kev
            if "CISA KEV" not in context["sources"]:
                context["sources"].append("CISA KEV")

        nvd_payload = fetch_nvd_cve_detail(value)
        if nvd_payload:
            context["nvd"] = parse_nvd_detail(nvd_payload)
            context["sources"].append("NIST NVD")

    if not context["sources"]:
        source = str(row.get("source", ""))
        if source:
            context["sources"].append(source)

    return context