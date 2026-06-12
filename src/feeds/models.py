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