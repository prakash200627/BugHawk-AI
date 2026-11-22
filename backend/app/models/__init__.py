"""
BugHawk AI 2.0 — SQLAlchemy ORM Models
All database tables are defined here and imported by Alembic.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    String, Text, Boolean, Integer, Float, DateTime,
    ForeignKey, JSON, Enum as SAEnum, Index, UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.database.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AssetStatus(str, enum.Enum):
    LIVE = "live"
    DOWN = "down"
    UNKNOWN = "unknown"
    OUT_OF_SCOPE = "out_of_scope"


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanModule(str, enum.Enum):
    SUBFINDER = "subfinder"
    HTTPX = "httpx"
    NUCLEI = "nuclei"
    SEMGREP = "semgrep"
    ZAP = "zap"
    IMPORT = "import"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class ValidationStatus(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    DUPLICATE = "duplicate"


class RemediationStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    WONT_FIX = "wont_fix"


class AgentStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    WAITING_HUMAN = "waiting_human"


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    JSON = "json"
    HTML = "html"


class AuditAction(str, enum.Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    SCAN_START = "scan_start"
    SCOPE_VALIDATE = "scope_validate"
    AGENT_EXECUTE = "agent_execute"
    REPORT_GENERATE = "report_generate"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Relationships
    projects: Mapped[List["Project"]] = relationship("Project", back_populates="owner")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="projects")
    authorized_scopes: Mapped[List["AuthorizedScope"]] = relationship("AuthorizedScope", back_populates="project")
    assets: Mapped[List["Asset"]] = relationship("Asset", back_populates="project")
    scan_jobs: Mapped[List["ScanJob"]] = relationship("ScanJob", back_populates="project")
    findings: Mapped[List["SecurityFinding"]] = relationship("SecurityFinding", back_populates="project")
    reports: Mapped[List["SecurityReport"]] = relationship("SecurityReport", back_populates="project")


class AuthorizedScope(Base):
    __tablename__ = "authorized_scopes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    scope_value: Mapped[str] = mapped_column(String(255), nullable=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    authorized_by: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="authorized_scopes")

    __table_args__ = (
        UniqueConstraint("project_id", "scope_value", name="uq_scope_project_value"),
        Index("ix_authorized_scopes_project_active", "project_id", "is_active"),
    )


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[AssetType] = mapped_column(SAEnum(AssetType), default=AssetType.SUBDOMAIN)
    status: Mapped[AssetStatus] = mapped_column(SAEnum(AssetStatus), default=AssetStatus.UNKNOWN)
    ip_addresses: Mapped[Optional[list]] = mapped_column(JSON)
    technologies: Mapped[Optional[list]] = mapped_column(JSON)
    http_status_code: Mapped[Optional[int]] = mapped_column(Integer)
    title: Mapped[Optional[str]] = mapped_column(String(512))
    discovery_source: Mapped[Optional[str]] = mapped_column(String(100))
    is_in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="assets")
    findings: Mapped[List["SecurityFinding"]] = relationship("SecurityFinding", back_populates="asset")

    __table_args__ = (
        UniqueConstraint("project_id", "hostname", name="uq_asset_project_hostname"),
        Index("ix_assets_project_status", "project_id", "status"),
    )


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    modules: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    scope_validated: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    raw_output: Mapped[Optional[dict]] = mapped_column(JSON)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="scan_jobs")
    findings: Mapped[List["SecurityFinding"]] = relationship("SecurityFinding", back_populates="scan_job")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    scan_job_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scan_jobs.id"), index=True)

    # Identification
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    vulnerability_type: Mapped[Optional[str]] = mapped_column(String(255))
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50))
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255))

    # Location
    endpoint: Mapped[Optional[str]] = mapped_column(String(1024))
    parameter: Mapped[Optional[str]] = mapped_column(String(255))

    # Severity (source vs AI-assessed)
    scanner_severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.UNKNOWN)
    ai_severity: Mapped[Optional[Severity]] = mapped_column(SAEnum(Severity))
    effective_severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.UNKNOWN)

    # Content
    description: Mapped[Optional[str]] = mapped_column(Text)
    impact: Mapped[Optional[str]] = mapped_column(Text)
    remediation: Mapped[Optional[str]] = mapped_column(Text)

    # Evidence & Confidence
    evidence: Mapped[Optional[dict]] = mapped_column(JSON)
    confidence: Mapped[ConfidenceLevel] = mapped_column(SAEnum(ConfidenceLevel), default=ConfidenceLevel.UNVERIFIED)
    validation_status: Mapped[ValidationStatus] = mapped_column(SAEnum(ValidationStatus), default=ValidationStatus.PENDING)

    # Risk Score (explainable, NOT CVSS)
    risk_score: Mapped[Optional[float]] = mapped_column(Float)
    risk_factors: Mapped[Optional[dict]] = mapped_column(JSON)

    # Source
    source_tool: Mapped[Optional[str]] = mapped_column(String(100))
    source_template: Mapped[Optional[str]] = mapped_column(String(255))
    raw_finding: Mapped[Optional[dict]] = mapped_column(JSON)

    # Deduplication
    finding_hash: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    duplicate_of_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("security_findings.id"))

    # Flags
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    needs_human_review: Mapped[bool] = mapped_column(Boolean, default=False)

    # AI Analysis
    ai_explanation: Mapped[Optional[str]] = mapped_column(Text)
    ai_analyzed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="findings")
    asset: Mapped[Optional["Asset"]] = relationship("Asset", back_populates="findings")
    scan_job: Mapped[Optional["ScanJob"]] = relationship("ScanJob", back_populates="findings")
    evidence_items: Mapped[List["FindingEvidence"]] = relationship("FindingEvidence", back_populates="finding")
    remediation_suggestions: Mapped[List["RemediationSuggestion"]] = relationship("RemediationSuggestion", back_populates="finding")
    duplicate_of: Mapped[Optional["SecurityFinding"]] = relationship("SecurityFinding", remote_side="SecurityFinding.id")

    __table_args__ = (
        Index("ix_findings_project_severity", "project_id", "effective_severity"),
        Index("ix_findings_validation", "project_id", "validation_status"),
    )


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_findings.id"), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(100))  # http_request, http_response, code_snippet, screenshot
    title: Mapped[Optional[str]] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    finding: Mapped["SecurityFinding"] = relationship("SecurityFinding", back_populates="evidence_items")


class AgentExecution(Base):
    __tablename__ = "agent_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("projects.id"), index=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("security_findings.id"), index=True)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[AgentStatus] = mapped_column(SAEnum(AgentStatus), default=AgentStatus.PENDING)
    input_data: Mapped[Optional[dict]] = mapped_column(JSON)
    output_data: Mapped[Optional[dict]] = mapped_column(JSON)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    llm_calls: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_agent_executions_project_status", "project_id", "status"),
    )


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    nodes: Mapped[list] = mapped_column(JSON, default=list)  # React Flow nodes
    edges: Mapped[list] = mapped_column(JSON, default=list)  # React Flow edges
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.MEDIUM)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class RemediationSuggestion(Base):
    __tablename__ = "remediation_suggestions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_findings.id"), nullable=False, index=True)
    root_cause: Mapped[Optional[str]] = mapped_column(Text)
    impact: Mapped[Optional[str]] = mapped_column(Text)
    recommendation: Mapped[Optional[str]] = mapped_column(Text)
    secure_code_example: Mapped[Optional[str]] = mapped_column(Text)
    code_language: Mapped[Optional[str]] = mapped_column(String(50))
    verification_checklist: Mapped[Optional[list]] = mapped_column(JSON)
    status: Mapped[RemediationStatus] = mapped_column(SAEnum(RemediationStatus), default=RemediationStatus.PENDING)
    ai_generated: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    finding: Mapped["SecurityFinding"] = relationship("SecurityFinding", back_populates="remediation_suggestions")


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_format: Mapped[ReportFormat] = mapped_column(SAEnum(ReportFormat), default=ReportFormat.JSON)
    file_path: Mapped[Optional[str]] = mapped_column(String(512))
    file_size: Mapped[Optional[int]] = mapped_column(Integer)
    report_data: Mapped[Optional[dict]] = mapped_column(JSON)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    scope_summary: Mapped[Optional[str]] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    action: Mapped[AuditAction] = mapped_column(SAEnum(AuditAction), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100))
    resource_id: Mapped[Optional[str]] = mapped_column(String(36))
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_action_created", "action", "created_at"),
    )
