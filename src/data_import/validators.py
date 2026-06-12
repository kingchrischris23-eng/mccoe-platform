VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "filename", "unknown"}


def normalize_severity(value: str) -> str:
    severity = (value or "medium").strip().lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{value}'. Use: {', '.join(sorted(VALID_SEVERITIES))}")
    return severity


def normalize_ioc_type(value: str) -> str:
    ioc_type = (value or "unknown").strip().lower()
    if ioc_type not in VALID_IOC_TYPES:
        return "unknown"
    return ioc_type


def parse_tags(raw: str | list[str] | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(tag).strip() for tag in raw if str(tag).strip()]
    return [tag.strip() for tag in str(raw).replace(",", ";").split(";") if tag.strip()]