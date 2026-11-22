"""
BugHawk AI 2.0 — Scans API
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_owned_project, require_writer
from app.database.session import get_db
from app.models import ScanJob, AuthorizedScope, ScanStatus, User
from app.schemas import ScanCreate, ScanResponse
from app.core.scope_guard import ScopeDecision, ScopeGuardian, _is_ip_address
from app.scanners.subfinder import is_safe_domain
from app.workers.scan_worker import is_httpx_job, is_nuclei_job, is_semgrep_job, is_subfinder_job, is_zap_job

router = APIRouter()

ALLOWED_MODULES = {"subfinder", "httpx", "nuclei", "semgrep", "zap", "import"}


def _httpx_result(item: object) -> dict | None:
    if not isinstance(item, dict):
        return None
    host = item.get("hostname")
    url = item.get("url")
    if not isinstance(host, str) or not isinstance(url, str):
        return None
    if not url.startswith("https://") and not url.startswith("http://"):
        return None
    public = {"hostname": host, "url": url.split("?", 1)[0]}
    status_code = item.get("status_code")
    if isinstance(status_code, int):
        public["status_code"] = status_code
    for key in ("title", "webserver"):
        value = item.get(key)
        if isinstance(value, str) and value:
            public[key] = value
    technologies = item.get("technologies")
    if isinstance(technologies, list):
        names = [entry for entry in technologies if isinstance(entry, str) and entry][:20]
        if names:
            public["technologies"] = names
    return public


def scan_to_response(scan: ScanJob) -> ScanResponse:
    """Return the stored job. Summaries come from saved raw output only."""
    response = ScanResponse.model_validate(scan)
    raw = scan.raw_output if isinstance(scan.raw_output, dict) else None
    if not raw:
        return response
    if raw.get("module") == "subfinder":
        names = raw.get("hostnames") or []
        response.result_summary = {
            "module": "subfinder",
            "passive": True,
            "discovered": int(raw.get("discovered") or 0),
            "stored": int(raw.get("stored") or 0),
            "duplicates": int(raw.get("duplicates") or 0),
            "rejected_out_of_scope": int(raw.get("rejected_out_of_scope") or 0),
            "hostnames": [str(host) for host in names][:200],
        }
        return response
    if raw.get("module") == "httpx":
        results = [row for row in (_httpx_result(item) for item in (raw.get("results") or [])) if row]
        response.result_summary = {
            "module": "httpx",
            "service_discovery": True,
            "probed": int(raw.get("probed") or 0),
            "updated": int(raw.get("updated") or 0),
            "rejected_out_of_scope": int(raw.get("rejected_out_of_scope") or 0),
            "skipped_over_limit": int(raw.get("skipped_over_limit") or 0),
            "results": results[:100],
        }
        return response
    if raw.get("module") == "nuclei":
        public_results = []
        for item in raw.get("results") or []:
            if not isinstance(item, dict):
                continue
            template_id = item.get("template_id")
            url = item.get("url")
            severity = item.get("severity")
            classification = item.get("classification")
            if not all(isinstance(value, str) and value for value in (template_id, url, severity, classification)):
                continue
            if classification not in {"informational", "potential"}:
                continue
            if not url.startswith("https://") and not url.startswith("http://"):
                continue
            public_results.append({
                "template_id": template_id,
                "url": url.split("?", 1)[0],
                "severity": severity,
                "classification": classification,
            })
        response.result_summary = {
            "module": "nuclei",
            "vulnerability_detection": True,
            "template_set": "reviewed-header-checks",
            "coverage": "Reviewed header checks only. Exploit, fuzz, brute force, DoS, and out-of-band templates are not included.",
            "targets": int(raw.get("targets") or 0),
            "findings": int(raw.get("findings") or 0),
            "informational": int(raw.get("informational") or 0),
            "potential": int(raw.get("potential") or 0),
            "duplicates": int(raw.get("duplicates") or 0),
            "rejected_out_of_scope": int(raw.get("rejected_out_of_scope") or 0),
            "unverified": int(raw.get("unverified") or 0),
            "results": public_results[:100],
        }
        return response
    if raw.get("module") == "semgrep":
        public_results = []
        for item in raw.get("results") or []:
            if not isinstance(item, dict):
                continue
            rule_id = item.get("rule_id")
            path = item.get("path")
            line = item.get("line")
            severity = item.get("severity")
            if not isinstance(rule_id, str) or not isinstance(path, str) or not isinstance(line, int):
                continue
            if ".." in path or path.startswith("/") or "\\" in path:
                continue
            public_results.append({
                "rule_id": rule_id,
                "path": path,
                "line": line,
                "severity": severity if isinstance(severity, str) else "unknown",
                "classification": "static-source",
            })
        response.result_summary = {
            "module": "semgrep",
            "source_analysis": True,
            "prerequisite_missing": bool(scan.error_message and "no uploaded source archive" in scan.error_message),
            "findings": int(raw.get("findings") or 0),
            "results": public_results[:100],
        }
        return response
    if raw.get("module") == "zap":
        public_results = []
        for item in raw.get("results") or []:
            if not isinstance(item, dict):
                continue
            plugin_id = item.get("plugin_id")
            url = item.get("url")
            risk = item.get("risk")
            classification = item.get("classification")
            if not all(isinstance(value, str) and value for value in (plugin_id, url, risk, classification)):
                continue
            if not url.startswith("https://") and not url.startswith("http://"):
                continue
            public_results.append({
                "plugin_id": plugin_id,
                "url": url.split("?", 1)[0],
                "risk": risk,
                "classification": classification,
            })
        response.result_summary = {
            "module": "zap",
            "passive_baseline": True,
            "findings": int(raw.get("findings") or 0),
            "results": public_results[:100],
        }
    return response


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_writer),
):
    """
    Create a scan job.
    Target is validated against project scopes before the job is accepted.
    Only approved modules are allowed.
    """
    require_owned_project(payload.project_id, db, current_user)
    modules = [item.strip().lower() for item in payload.modules]
    invalid_modules = set(modules) - ALLOWED_MODULES
    if invalid_modules:
        raise HTTPException(
            status_code=400,
            detail="Unknown scan module. Allowed modules are subfinder, httpx, nuclei, semgrep, zap, and import.",
        )

    # Scope validation — mandatory
    scopes = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == payload.project_id,
        AuthorizedScope.is_active.is_(True),
    ).all()
    scope_strings = [s.scope_value for s in scopes]
    guardian = ScopeGuardian.from_scope_values(scope_strings)
    scope_result = guardian.validate(payload.target)

    if "subfinder" in modules and not is_subfinder_job(modules):
        raise HTTPException(
            status_code=400,
            detail="Subfinder must be the only module in the job. Other tools are not executed.",
        )
    if "httpx" in modules and not is_httpx_job(modules):
        raise HTTPException(
            status_code=400,
            detail="HTTPX must be the only module in the job. Other tools are not executed.",
        )
    if "nuclei" in modules and not is_nuclei_job(modules):
        raise HTTPException(
            status_code=400,
            detail="Nuclei must be the only module in the job. Other tools are not executed.",
        )
    if "semgrep" in modules and not is_semgrep_job(modules):
        raise HTTPException(
            status_code=400,
            detail="Semgrep must be the only module in the job. Other tools are not executed.",
        )
    if "zap" in modules and not is_zap_job(modules):
        raise HTTPException(
            status_code=400,
            detail="ZAP must be the only module in the job. Other tools are not executed.",
        )
    if is_subfinder_job(modules):
        if _is_ip_address(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail="Subfinder accepts a domain, not an IP address.")
        if scope_result.decision == ScopeDecision.INVALID or not is_safe_domain(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail="Target is not a valid domain.")
    if is_httpx_job(modules):
        raw_target = payload.target.strip()
        if "://" in raw_target or "/" in raw_target:
            raise HTTPException(
                status_code=400,
                detail="HTTPX selects stored assets by domain. It does not accept a URL.",
            )
        if _is_ip_address(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail="HTTPX selects stored assets by domain, not an IP address.")
        if scope_result.decision == ScopeDecision.INVALID or not is_safe_domain(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail="Target is not a valid domain.")
    if is_nuclei_job(modules):
        raw_target = payload.target.strip()
        if "://" in raw_target or "/" in raw_target:
            raise HTTPException(
                status_code=400,
                detail="Nuclei selects stored HTTPX results by domain. It does not accept a URL or a template.",
            )
        if _is_ip_address(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail="Nuclei selects stored HTTPX results by domain, not an IP address.")
        if scope_result.decision == ScopeDecision.INVALID or not is_safe_domain(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail="Target is not a valid domain.")
    if is_semgrep_job(modules) or is_zap_job(modules):
        raw_target = payload.target.strip()
        tool = "Semgrep" if is_semgrep_job(modules) else "ZAP"
        if "://" in raw_target or "/" in raw_target:
            raise HTTPException(status_code=400, detail=f"{tool} does not accept a URL.")
        if _is_ip_address(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail=f"{tool} selects an authorized domain, not an IP address.")
        if scope_result.decision == ScopeDecision.INVALID or not is_safe_domain(scope_result.normalized_host):
            raise HTTPException(status_code=400, detail="Target is not a valid domain.")
    if not scope_result.is_allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Target is not in authorized scope: {scope_result.reason}",
        )

    scan = ScanJob(
        project_id=payload.project_id,
        name=payload.name,
        target=payload.target,
        modules=modules,
        status=ScanStatus.PENDING,
        scope_validated=True,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan_to_response(scan)


@router.get("", response_model=List[ScanResponse])
def list_scans(
    project_id: str = Query(...),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List scan jobs for a project owned by the authenticated user."""
    require_owned_project(project_id, db, current_user)
    rows = db.query(ScanJob).filter(
        ScanJob.project_id == project_id
    ).order_by(ScanJob.created_at.desc()).offset(skip).limit(limit).all()
    return [scan_to_response(row) for row in rows]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a scan job owned through its project."""
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")
    require_owned_project(scan.project_id, db, current_user)
    return scan_to_response(scan)
