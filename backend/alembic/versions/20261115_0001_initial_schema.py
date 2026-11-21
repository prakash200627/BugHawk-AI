"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


userrole = postgresql.ENUM(
    "ADMIN", "ANALYST", "VIEWER",
    name="userrole",
    create_type=False,
)
assetstatus = postgresql.ENUM(
    "LIVE", "DOWN", "UNKNOWN", "OUT_OF_SCOPE",
    name="assetstatus",
    create_type=False,
)
assettype = postgresql.ENUM(
    "DOMAIN", "SUBDOMAIN", "IP", "URL",
    name="assettype",
    create_type=False,
)
scanstatus = postgresql.ENUM(
    "PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED",
    name="scanstatus",
    create_type=False,
)
severity = postgresql.ENUM(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN",
    name="severity",
    create_type=False,
)
confidencelevel = postgresql.ENUM(
    "HIGH", "MEDIUM", "LOW", "UNVERIFIED",
    name="confidencelevel",
    create_type=False,
)
validationstatus = postgresql.ENUM(
    "PENDING", "CONFIRMED", "FALSE_POSITIVE", "NEEDS_REVIEW", "DUPLICATE",
    name="validationstatus",
    create_type=False,
)
remediationstatus = postgresql.ENUM(
    "PENDING", "ACCEPTED", "IN_PROGRESS", "COMPLETED", "WONT_FIX",
    name="remediationstatus",
    create_type=False,
)
agentstatus = postgresql.ENUM(
    "PENDING", "RUNNING", "COMPLETED", "FAILED", "WAITING_HUMAN",
    name="agentstatus",
    create_type=False,
)
reportformat = postgresql.ENUM(
    "PDF", "JSON", "HTML",
    name="reportformat",
    create_type=False,
)
auditaction = postgresql.ENUM(
    "CREATE", "UPDATE", "DELETE", "LOGIN", "LOGOUT",
    "SCAN_START", "SCOPE_VALIDATE", "AGENT_EXECUTE", "REPORT_GENERATE",
    name="auditaction",
    create_type=False,
)

ENUM_TYPES = (
    userrole,
    assetstatus,
    assettype,
    scanstatus,
    severity,
    confidencelevel,
    validationstatus,
    remediationstatus,
    agentstatus,
    reportformat,
    auditaction,
)


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in ENUM_TYPES:
        enum_type.create(bind, checkfirst=False)

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("role", userrole, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name="fk_projects_owner_id_users"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
    )
    op.create_index("ix_projects_owner_id", "projects", ["owner_id"], unique=False)

    op.create_table(
        "authorized_scopes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("scope_value", sa.String(length=255), nullable=False),
        sa.Column("is_wildcard", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("authorized_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_authorized_scopes_project_id_projects",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_authorized_scopes"),
        sa.UniqueConstraint(
            "project_id", "scope_value", name="uq_scope_project_value"
        ),
    )
    op.create_index(
        "ix_authorized_scopes_project_id",
        "authorized_scopes",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_authorized_scopes_project_active",
        "authorized_scopes",
        ["project_id", "is_active"],
        unique=False,
    )

    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("asset_type", assettype, nullable=False),
        sa.Column("status", assetstatus, nullable=False),
        sa.Column("ip_addresses", sa.JSON(), nullable=True),
        sa.Column("technologies", sa.JSON(), nullable=True),
        sa.Column("http_status_code", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("discovery_source", sa.String(length=100), nullable=True),
        sa.Column("is_in_scope", sa.Boolean(), nullable=False),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_assets_project_id_projects"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
        sa.UniqueConstraint(
            "project_id", "hostname", name="uq_asset_project_hostname"
        ),
    )
    op.create_index("ix_assets_project_id", "assets", ["project_id"], unique=False)
    op.create_index("ix_assets_hostname", "assets", ["hostname"], unique=False)
    op.create_index(
        "ix_assets_project_status",
        "assets",
        ["project_id", "status"],
        unique=False,
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("modules", sa.JSON(), nullable=False),
        sa.Column("status", scanstatus, nullable=False),
        sa.Column("scope_validated", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("raw_output", sa.JSON(), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_scan_jobs_project_id_projects"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scan_jobs"),
    )
    op.create_index("ix_scan_jobs_project_id", "scan_jobs", ["project_id"], unique=False)

    op.create_table(
        "security_findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("scan_job_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("vulnerability_type", sa.String(length=255), nullable=True),
        sa.Column("cve_id", sa.String(length=50), nullable=True),
        sa.Column("cwe_id", sa.String(length=50), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("endpoint", sa.String(length=1024), nullable=True),
        sa.Column("parameter", sa.String(length=255), nullable=True),
        sa.Column("scanner_severity", severity, nullable=False),
        sa.Column("ai_severity", severity, nullable=True),
        sa.Column("effective_severity", severity, nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("confidence", confidencelevel, nullable=False),
        sa.Column("validation_status", validationstatus, nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_factors", sa.JSON(), nullable=True),
        sa.Column("source_tool", sa.String(length=100), nullable=True),
        sa.Column("source_template", sa.String(length=255), nullable=True),
        sa.Column("raw_finding", sa.JSON(), nullable=True),
        sa.Column("finding_hash", sa.String(length=64), nullable=True),
        sa.Column("duplicate_of_id", sa.String(length=36), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("needs_human_review", sa.Boolean(), nullable=False),
        sa.Column("ai_explanation", sa.Text(), nullable=True),
        sa.Column("ai_analyzed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_security_findings_project_id_projects",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="fk_security_findings_asset_id_assets"
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name="fk_security_findings_scan_job_id_scan_jobs",
        ),
        sa.ForeignKeyConstraint(
            ["duplicate_of_id"],
            ["security_findings.id"],
            name="fk_security_findings_duplicate_of_id_security_findings",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_security_findings"),
    )
    op.create_index(
        "ix_security_findings_project_id",
        "security_findings",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_findings_asset_id",
        "security_findings",
        ["asset_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_findings_scan_job_id",
        "security_findings",
        ["scan_job_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_findings_cve_id", "security_findings", ["cve_id"], unique=False
    )
    op.create_index(
        "ix_security_findings_finding_hash",
        "security_findings",
        ["finding_hash"],
        unique=False,
    )
    op.create_index(
        "ix_findings_project_severity",
        "security_findings",
        ["project_id", "effective_severity"],
        unique=False,
    )
    op.create_index(
        "ix_findings_validation",
        "security_findings",
        ["project_id", "validation_status"],
        unique=False,
    )

    op.create_table(
        "finding_evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_type", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("is_sensitive", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["security_findings.id"],
            name="fk_finding_evidence_finding_id_security_findings",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_evidence"),
    )
    op.create_index(
        "ix_finding_evidence_finding_id",
        "finding_evidence",
        ["finding_id"],
        unique=False,
    )

    op.create_table(
        "agent_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("finding_id", sa.String(length=36), nullable=True),
        sa.Column("agent_name", sa.String(length=100), nullable=False),
        sa.Column("status", agentstatus, nullable=False),
        sa.Column("input_data", sa.JSON(), nullable=True),
        sa.Column("output_data", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("llm_calls", sa.Integer(), nullable=False),
        sa.Column("tokens_used", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_agent_executions_project_id_projects",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["security_findings.id"],
            name="fk_agent_executions_finding_id_security_findings",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_agent_executions"),
    )
    op.create_index(
        "ix_agent_executions_project_id",
        "agent_executions",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_executions_finding_id",
        "agent_executions",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_executions_project_status",
        "agent_executions",
        ["project_id", "status"],
        unique=False,
    )

    op.create_table(
        "attack_paths",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("nodes", sa.JSON(), nullable=False),
        sa.Column("edges", sa.JSON(), nullable=False),
        sa.Column("is_confirmed", sa.Boolean(), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_attack_paths_project_id_projects",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_attack_paths"),
    )
    op.create_index(
        "ix_attack_paths_project_id", "attack_paths", ["project_id"], unique=False
    )

    op.create_table(
        "remediation_suggestions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("secure_code_example", sa.Text(), nullable=True),
        sa.Column("code_language", sa.String(length=50), nullable=True),
        sa.Column("verification_checklist", sa.JSON(), nullable=True),
        sa.Column("status", remediationstatus, nullable=False),
        sa.Column("ai_generated", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["security_findings.id"],
            name="fk_remediation_suggestions_finding_id_security_findings",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_remediation_suggestions"),
    )
    op.create_index(
        "ix_remediation_suggestions_finding_id",
        "remediation_suggestions",
        ["finding_id"],
        unique=False,
    )

    op.create_table(
        "security_reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("report_format", reportformat, nullable=False),
        sa.Column("file_path", sa.String(length=512), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("report_data", sa.JSON(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("scope_summary", sa.Text(), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_security_reports_project_id_projects",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_security_reports"),
    )
    op.create_index(
        "ix_security_reports_project_id",
        "security_reports",
        ["project_id"],
        unique=False,
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("action", auditaction, nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=True),
        sa.Column("resource_id", sa.String(length=36), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_audit_logs_user_id_users"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)
    op.create_index(
        "ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False
    )
    op.create_index(
        "ix_audit_logs_action_created",
        "audit_logs",
        ["action", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_logs_action_created", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_security_reports_project_id", table_name="security_reports")
    op.drop_table("security_reports")

    op.drop_index(
        "ix_remediation_suggestions_finding_id", table_name="remediation_suggestions"
    )
    op.drop_table("remediation_suggestions")

    op.drop_index("ix_attack_paths_project_id", table_name="attack_paths")
    op.drop_table("attack_paths")

    op.drop_index(
        "ix_agent_executions_project_status", table_name="agent_executions"
    )
    op.drop_index("ix_agent_executions_finding_id", table_name="agent_executions")
    op.drop_index("ix_agent_executions_project_id", table_name="agent_executions")
    op.drop_table("agent_executions")

    op.drop_index("ix_finding_evidence_finding_id", table_name="finding_evidence")
    op.drop_table("finding_evidence")

    op.drop_index("ix_findings_validation", table_name="security_findings")
    op.drop_index("ix_findings_project_severity", table_name="security_findings")
    op.drop_index("ix_security_findings_finding_hash", table_name="security_findings")
    op.drop_index("ix_security_findings_cve_id", table_name="security_findings")
    op.drop_index("ix_security_findings_scan_job_id", table_name="security_findings")
    op.drop_index("ix_security_findings_asset_id", table_name="security_findings")
    op.drop_index("ix_security_findings_project_id", table_name="security_findings")
    op.drop_table("security_findings")

    op.drop_index("ix_scan_jobs_project_id", table_name="scan_jobs")
    op.drop_table("scan_jobs")

    op.drop_index("ix_assets_project_status", table_name="assets")
    op.drop_index("ix_assets_hostname", table_name="assets")
    op.drop_index("ix_assets_project_id", table_name="assets")
    op.drop_table("assets")

    op.drop_index(
        "ix_authorized_scopes_project_active", table_name="authorized_scopes"
    )
    op.drop_index("ix_authorized_scopes_project_id", table_name="authorized_scopes")
    op.drop_table("authorized_scopes")

    op.drop_index("ix_projects_owner_id", table_name="projects")
    op.drop_table("projects")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

    bind = op.get_bind()
    for enum_type in reversed(ENUM_TYPES):
        enum_type.drop(bind, checkfirst=False)
