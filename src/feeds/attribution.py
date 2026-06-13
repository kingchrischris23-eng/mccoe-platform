"""Attribution and metadata for third-party threat intelligence feeds."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FeedAttribution:
    key: str
    display_name: str
    provider: str
    url: str
    license_note: str
    api_key_env: str | None = None


FEED_ATTRIBUTIONS: dict[str, FeedAttribution] = {
    "urlhaus": FeedAttribution(
        key="urlhaus",
        display_name="URLhaus",
        provider="abuse.ch",
        url="https://urlhaus.abuse.ch/",
        license_note="Community API under abuse.ch fair-use principles.",
    ),
    "otx": FeedAttribution(
        key="otx",
        display_name="AlienVault OTX",
        provider="AT&T Cybersecurity / AlienVault",
        url="https://otx.alienvault.com/",
        license_note="Free API key required for live pulls; pulses subject to OTX terms.",
        api_key_env="OTX_API_KEY",
    ),
    "threatfox": FeedAttribution(
        key="threatfox",
        display_name="ThreatFox",
        provider="abuse.ch",
        url="https://threatfox.abuse.ch/",
        license_note="Community API; free Auth-Key from auth.abuse.ch required.",
        api_key_env="ABUSECH_AUTH_KEY",
    ),
    "openphish": FeedAttribution(
        key="openphish",
        display_name="OpenPhish",
        provider="OpenPhish",
        url="https://openphish.com/",
        license_note="Public phishing feed; attribution required when redistributing.",
    ),
    "nist_nvd": FeedAttribution(
        key="nist_nvd",
        display_name="NIST NVD",
        provider="NIST",
        url="https://nvd.nist.gov/",
        license_note="U.S. government CVE data; optional NVD API key improves rate limits.",
        api_key_env="NVD_API_KEY",
    ),
    "cisa_kev": FeedAttribution(
        key="cisa_kev",
        display_name="CISA KEV",
        provider="CISA",
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        license_note="U.S. government Known Exploited Vulnerabilities catalog.",
    ),
}


def attribution_lines() -> list[str]:
    """Markdown-friendly attribution bullets for the Threat Feeds UI."""
    lines: list[str] = []
    for feed in FEED_ATTRIBUTIONS.values():
        key_note = ""
        if feed.api_key_env:
            key_note = f" API key: `{feed.api_key_env}` in Settings."
        lines.append(
            f"**{feed.display_name}** — [{feed.provider}]({feed.url}). "
            f"{feed.license_note}{key_note}"
        )
    return lines