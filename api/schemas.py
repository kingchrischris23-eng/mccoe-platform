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


class ReportGenerateRequest(BaseModel):
    format: Literal["pdf", "markdown", "both"] = "pdf"
    auto: bool = False


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


class DataClearResponse(BaseModel):
    message: str