from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class IOC:
    ioc_type: str
    value: str
    severity: str
    source: str
    first_seen: datetime
    tags: list[str] = field(default_factory=list)
    description: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.ioc_type, self.value.lower())


@dataclass
class FeedSourceResult:
    name: str
    iocs: list[IOC] = field(default_factory=list)
    count: int = 0
    cached_at: datetime | None = None
    stale: bool = False
    live: bool = False
    error: str | None = None
    rate_limited: bool = False


@dataclass
class FeedResult:
    iocs: list[IOC]
    sources: list[FeedSourceResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.iocs)