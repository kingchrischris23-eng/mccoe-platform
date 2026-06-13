from dataclasses import dataclass, field

SEVERITY_OPTIONS = ("critical", "high", "medium", "low")
DATE_RANGE_OPTIONS = {
    "Last 7 days": "7d",
    "Last 30 days": "30d",
    "Last 90 days": "90d",
    "All time": "all",
}
SOURCE_OPTIONS = {
    "All sources": "all",
    "NIST NVD only": "nist_nvd",
    "CISA KEV only": "cisa_kev",
    "AlienVault OTX only": "otx",
    "URLhaus only": "urlhaus",
    "ThreatFox only": "threatfox",
}

DEFAULT_MAX_ITEMS = 150
MAX_ITEMS_CEILING = 5000


@dataclass
class ReportFilters:
    severities: list[str] = field(default_factory=lambda: list(SEVERITY_OPTIONS))
    date_range: str = "30d"
    source: str = "all"
    search: str | None = None
    max_items: int = DEFAULT_MAX_ITEMS

    @classmethod
    def defaults(cls) -> "ReportFilters":
        return cls()

    def recent_days(self) -> int | None:
        mapping = {"7d": 7, "30d": 30, "90d": 90, "all": None}
        return mapping.get(self.date_range)

    def source_filter(self) -> str | None:
        mapping = {
            "nist_nvd": "NIST NVD",
            "cisa_kev": "CISA KEV",
            "otx": "AlienVault OTX",
            "urlhaus": "URLhaus",
            "threatfox": "ThreatFox",
            "all": None,
        }
        return mapping.get(self.source)

    def normalized_severities(self) -> list[str] | None:
        selected = [s.lower() for s in (self.severities or []) if s]
        if not selected or set(selected) == set(SEVERITY_OPTIONS):
            return None
        return selected

    def query_kwargs(self) -> dict:
        return {
            "severities": self.normalized_severities(),
            "source": self.source_filter(),
            "search": (self.search or "").strip() or None,
            "recent_days": self.recent_days(),
        }

    def effective_limit(self) -> int:
        return max(10, min(MAX_ITEMS_CEILING, int(self.max_items)))

    def severity_label(self) -> str:
        selected = self.normalized_severities()
        if not selected:
            return "All severities"
        return ", ".join(s.title() for s in selected)

    def date_label(self) -> str:
        for label, key in DATE_RANGE_OPTIONS.items():
            if key == self.date_range:
                return label
        return "All time"

    def source_label(self) -> str:
        for label, key in SOURCE_OPTIONS.items():
            if key == self.source:
                return label
        return "All sources"

    def summary_lines(self, *, matching: int, included: int, dashboard_total: int) -> list[str]:
        lines = [
            f"Risk level: {self.severity_label()}",
            f"Date range: {self.date_label()}",
            f"Source: {self.source_label()}",
            f"Max items: {self.effective_limit()}",
        ]
        if self.search:
            lines.append(f"Search: `{self.search}`")
        lines.append(
            f"Report scope: **{included}** IOC(s) included "
            f"({matching:,} matching filters / {dashboard_total:,} total in dashboard)"
        )
        return lines

    def to_dict(self) -> dict:
        return {
            "severities": self.severities,
            "date_range": self.date_range,
            "source": self.source,
            "search": self.search,
            "max_items": self.effective_limit(),
        }

    @classmethod
    def from_dict(cls, payload: dict | None) -> "ReportFilters":
        if not payload:
            return cls.defaults()
        return cls(
            severities=list(payload.get("severities") or SEVERITY_OPTIONS),
            date_range=str(payload.get("date_range") or "30d"),
            source=str(payload.get("source") or "all"),
            search=payload.get("search"),
            max_items=int(payload.get("max_items") or DEFAULT_MAX_ITEMS),
        )