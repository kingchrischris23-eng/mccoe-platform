from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    version: str
    local_only: bool


class IOCResponse(BaseModel):
    id: int | None = None
    ioc_type: str
    value: str
    severity: str
    source: str
    first_seen: str
    tags: str = ""
    description: str = ""


class ThreatListResponse(BaseModel):
    count: int
    total: int | None = None
    iocs: list[IOCResponse]


class LogAnalyzeRequest(BaseModel):
    filename: str = "uploaded.log"
    content: str = Field(..., min_length=1)


class LogAnalyzeResponse(BaseModel):
    session_id: int
    filename: str
    entries_parsed: int
    alerts_found: int
    alerts: list[dict]
    analysis: dict


class VulnerabilityScanResponse(BaseModel):
    id: int
    target: str
    scanned_at: str
    open_ports: list[dict]
    header_issues: list[dict]
    cve_findings: list[dict]
    risk_score: float


class VulnerabilityListResponse(BaseModel):
    count: int
    scans: list[VulnerabilityScanResponse]


class ReportFilterOptions(BaseModel):
    severities: list[str] | None = None
    date_range: str = "30d"
    source: str = "all"
    search: str | None = None
    max_items: int = 150


class ReportGenerateRequest(BaseModel):
    format: Literal["pdf", "markdown", "both"] = "pdf"
    auto: bool = False
    filters: ReportFilterOptions | None = None


class ReportGenerateResponse(BaseModel):
    format: str
    files: list[dict]
    summary: str


class IOCImportRequest(BaseModel):
    iocs: list[dict] = Field(..., min_length=1)


class IOCImportResponse(BaseModel):
    imported: int
    message: str


class VulnerabilityCreateRequest(BaseModel):
    target: str
    open_ports: list[dict] = Field(default_factory=list)
    header_issues: list[dict] = Field(default_factory=list)
    cve_findings: list[dict] = Field(default_factory=list)
    risk_score: float = 0.0


class DemoLoadResponse(BaseModel):
    loaded: dict
    message: str


class DataClearRequest(BaseModel):
    feed_cache: bool = False
    logs: bool = False
    manual_iocs: bool = False
    scans: bool = False
    reports: bool = False
    all_user_data: bool = False


class DataClearResponse(BaseModel):
    message: str
    cleared: dict | None = None


class FeedSourceStatus(BaseModel):
    name: str
    count: int = 0
    cached_at: str | None = None
    stale: bool = False
    live: bool = False
    error: str | None = None
    rate_limited: bool = False


class FeedStatusResponse(BaseModel):
    sources: list[FeedSourceStatus]


class FeedRefreshResponse(BaseModel):
    total: int
    sources: list[FeedSourceStatus]
    message: str