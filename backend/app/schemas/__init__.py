"""
BugHawk AI 2.0 — Pydantic Schemas
Request/response schemas for all API endpoints.
"""

from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database: str
    demo_mode: bool
    timestamp: str


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int


class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    email: str
    role: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10)
    full_name: Optional[str] = None
    role: str = "analyst"


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    is_demo: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    is_demo: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime
    # Computed counts
    asset_count: int = 0
    finding_count: int = 0
    critical_count: int = 0

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------

class ScopeCreate(BaseModel):
    scope_value: str = Field(..., min_length=1, max_length=255)
    notes: Optional[str] = None
    authorized_by: Optional[str] = None

    @field_validator("scope_value")
    @classmethod
    def validate_scope_format(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("Scope value cannot be empty")
        return v


class ScopeResponse(BaseModel):
    id: str
    project_id: str
    scope_value: str
    is_wildcard: bool
    is_active: bool
    notes: Optional[str]
    authorized_by: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScopeValidateRequest(BaseModel):
    target: str
    project_id: str


class ScopeValidateResponse(BaseModel):
    target: str
    normalized_host: str
    decision: str
    matched_rule: Optional[str]
    reason: str
    is_allowed: bool


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    asset_type: str = "subdomain"
    notes: Optional[str] = None


class AssetImportItem(BaseModel):
    hostname: str
    asset_type: Optional[str] = "subdomain"
    ip_addresses: Optional[List[str]] = None
    technologies: Optional[List[str]] = None
    http_status_code: Optional[int] = None
    title: Optional[str] = None
    discovery_source: Optional[str] = "import"


class AssetImportRequest(BaseModel):
    project_id: str
    assets: List[AssetImportItem]


class AssetResponse(BaseModel):
    id: str
    project_id: str
    hostname: str
    asset_type: str
    status: str
    ip_addresses: Optional[List[str]]
    technologies: Optional[List[str]]
    http_status_code: Optional[int]
    title: Optional[str]
    discovery_source: Optional[str]
    is_in_scope: bool
    is_demo: bool
    last_seen: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    project_id: str
    name: str = Field(..., min_length=1, max_length=255)
    target: str = Field(..., min_length=1)
    modules: List[str] = Field(..., min_length=1)


class ScanResponse(BaseModel):
    id: str
    project_id: str
    name: str
    target: str
    modules: List[str]
    status: str
    scope_validated: bool
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    findings_count: int
    error_message: Optional[str]
    is_demo: bool
    created_at: datetime
    result_summary: Optional[dict] = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class FindingImportItem(BaseModel):
    title: str
    vulnerability_type: Optional[str] = None
    severity: str = "unknown"
    endpoint: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    source_tool: Optional[str] = None
    raw_finding: Optional[Dict[str, Any]] = None


class FindingImportRequest(BaseModel):
    project_id: str
    scan_job_id: Optional[str] = None
    findings: List[FindingImportItem]


class FindingResponse(BaseModel):
    id: str
    project_id: str
    asset_id: Optional[str]
    scan_job_id: Optional[str]
    title: str
    vulnerability_type: Optional[str]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    endpoint: Optional[str]
    scanner_severity: str
    ai_severity: Optional[str]
    effective_severity: str
    description: Optional[str]
    impact: Optional[str]
    remediation: Optional[str]
    evidence: Optional[Dict[str, Any]]
    confidence: str
    validation_status: str
    risk_score: Optional[float]
    risk_factors: Optional[Dict[str, Any]]
    source_tool: Optional[str]
    is_demo: bool
    needs_human_review: bool
    ai_explanation: Optional[str]
    ai_analyzed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# AI Agent
# ---------------------------------------------------------------------------

class AgentChatMessage(BaseModel):
    role: str  # user | assistant
    content: str


class AgentChatRequest(BaseModel):
    project_id: str
    messages: List[AgentChatMessage]
    finding_id: Optional[str] = None


class AgentChatResponse(BaseModel):
    response: str
    finding_context: Optional[Dict[str, Any]] = None
    agent_execution_id: Optional[str] = None
    is_demo: bool = False


class AgentAnalyzeRequest(BaseModel):
    project_id: str


class AgentAnalyzeResponse(BaseModel):
    finding_id: str
    execution_id: str
    status: str
    explanation: Optional[str]
    severity_assessment: Optional[str]
    confidence: Optional[str]
    impact: Optional[str]
    remediation_summary: Optional[str]
    verification_steps: Optional[List[str]]
    is_demo: bool


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportGenerateRequest(BaseModel):
    project_id: str
    title: Optional[str] = None
    format: str = "json"
    include_evidence: bool = True
    include_remediation: bool = True


class ReportResponse(BaseModel):
    id: str
    project_id: str
    title: str
    report_format: str
    file_path: Optional[str]
    file_size: Optional[int]
    findings_count: int
    is_demo: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

class RemediationResponse(BaseModel):
    id: str
    finding_id: str
    root_cause: Optional[str]
    impact: Optional[str]
    recommendation: Optional[str]
    secure_code_example: Optional[str]
    code_language: Optional[str]
    verification_checklist: Optional[List[str]]
    status: str
    ai_generated: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class RemediationStatusUpdate(BaseModel):
    status: str  # pending | accepted | in_progress | completed | wont_fix


# ---------------------------------------------------------------------------
# Dashboard / Stats
# ---------------------------------------------------------------------------

class DashboardStats(BaseModel):
    total_assets: int
    live_assets: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    potential_duplicates: int
    findings_pending_review: int
    total_scans: int
    active_scans: int


class SeverityDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int
