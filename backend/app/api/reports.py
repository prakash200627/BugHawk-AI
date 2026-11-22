"""
BugHawk AI 2.0 — Reports API
"""
import json
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_owned_project, require_writer
from app.database.session import get_db
from app.models import SecurityReport, Project, SecurityFinding, Asset, AuthorizedScope, ReportFormat, User
from app.schemas import ReportGenerateRequest, ReportResponse
from app.config import settings

router = APIRouter()


def _build_report_data(
    project: Project,
    db: Session,
    include_evidence: bool = True,
    include_remediation: bool = True,
) -> dict:
    """Build a report from rows already stored for the project."""
    from app.models import RemediationSuggestion

    findings = db.query(SecurityFinding).filter(SecurityFinding.project_id == project.id).all()
    assets = db.query(Asset).filter(Asset.project_id == project.id).all()
    scopes = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == project.id,
        AuthorizedScope.is_active.is_(True),
    ).all()
    suggestions_by_finding = {}
    if include_remediation and findings:
        finding_ids = [finding.id for finding in findings]
        stored = db.query(RemediationSuggestion).filter(
            RemediationSuggestion.finding_id.in_(finding_ids)
        ).all()
        for suggestion in stored:
            suggestions_by_finding.setdefault(suggestion.finding_id, []).append({
                "id": suggestion.id,
                "status": suggestion.status.value if hasattr(suggestion.status, "value") else suggestion.status,
                "recommendation": suggestion.recommendation,
            })

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.effective_severity.value if f.effective_severity else "info"
        sev_counts[key] = sev_counts.get(key, 0) + 1

    report_findings = []
    for f in findings:
        fd = {
            "id": f.id,
            "title": f.title,
            "severity": f.effective_severity.value if f.effective_severity else "unknown",
            "vulnerability_type": f.vulnerability_type,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "endpoint": f.endpoint,
            "description": f.description,
            "confidence": f.confidence.value if f.confidence else "unverified",
            "validation_status": f.validation_status.value if f.validation_status else "pending",
            "source_tool": f.source_tool,
            "is_demo": f.is_demo,
        }
        if include_remediation:
            fd["remediation"] = f.remediation
            fd["stored_remediation_suggestions"] = suggestions_by_finding.get(f.id, [])
        if include_evidence:
            fd["evidence"] = f.evidence
        report_findings.append(fd)
    analyzed = [f for f in findings if f.ai_explanation]

    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "BugHawk AI 2.0",
            "version": settings.app_version,
            "demo_mode": settings.is_demo,
        },
        "executive_summary": {
            "project_name": project.name,
            "assessment_period": project.created_at.isoformat(),
            "total_assets": len(assets),
            "total_findings": len(findings),
            "severity_distribution": sev_counts,
            "methodology": (
                "This report lists records stored for the project. "
                + (
                    f"{len(analyzed)} finding(s) already have analyst text saved on the record. "
                    "No new analysis was run while creating this report."
                    if analyzed
                    else "No scanner was executed and no AI analysis was performed while creating this report."
                )
            ),
            "limitations": (
                "Stored findings were not revalidated while creating this report."
                + (" The project is marked as demo data." if project.is_demo else "")
            ),
        },
        "scope": {
            "authorized_scopes": [s.scope_value for s in scopes],
            "assets_assessed": [{"hostname": a.hostname, "status": a.status.value} for a in assets],
        },
        "findings": report_findings,
    }


@router.post("/generate", response_model=ReportResponse, status_code=201)
def generate_report(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_writer),
):
    """Generate a security assessment report for an owned project."""
    if (payload.format or "").strip().lower() != "json":
        raise HTTPException(
            status_code=400,
            detail="Only JSON reports are available. PDF and HTML generation are not implemented.",
        )
    project = require_owned_project(payload.project_id, db, current_user)

    report_data = _build_report_data(
        project,
        db,
        include_evidence=payload.include_evidence,
        include_remediation=payload.include_remediation,
    )
    findings_count = len(report_data["findings"])

    report = SecurityReport(
        project_id=payload.project_id,
        title=payload.title or f"{project.name} — Security Assessment Report",
        report_format=ReportFormat.JSON,
        report_data=report_data,
        findings_count=findings_count,
        is_demo=project.is_demo,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("", response_model=List[ReportResponse])
def list_reports(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List reports for a project owned by the authenticated user."""
    require_owned_project(project_id, db, current_user)
    return db.query(SecurityReport).filter(
        SecurityReport.project_id == project_id
    ).order_by(SecurityReport.created_at.desc()).all()


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download a report from a project owned by the authenticated user."""
    report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    require_owned_project(report.project_id, db, current_user)
    if report.report_format != ReportFormat.JSON:
        raise HTTPException(
            status_code=400,
            detail="This report is not JSON. PDF and HTML downloads are not implemented.",
        )

    content = json.dumps(report.report_data, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="bughawk_report_{report_id[:8]}.json"'
        },
    )
