"""Phase 2 checks that do not open a database connection."""
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api.assets import import_assets, list_assets
from app.api.findings import import_findings, list_findings, resolve_scan_for_import
from app.api.remediation import update_remediation_status
from app.api.reports import _build_report_data, download_report, generate_report
from app.models import (
    Asset,
    AssetStatus,
    AssetType,
    AuthorizedScope,
    Project,
    RemediationSuggestion,
    ReportFormat,
    SecurityFinding,
    SecurityReport,
    Severity,
    User,
    ValidationStatus,
    ConfidenceLevel,
    ScanJob,
)
from app.schemas import (
    AssetImportItem,
    AssetImportRequest,
    FindingImportRequest,
    ReportGenerateRequest,
    RemediationStatusUpdate,
)


class Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return list(self.rows)

    def order_by(self, *args, **kwargs):
        return self

    def offset(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self


class DB:
    def __init__(self, rows):
        self.rows = rows
        self.added = []
        self.committed = False

    def query(self, model):
        return Query(self.rows.get(model, []))

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        return None


def user():
    return User(id="user-1", email="owner@example.com", hashed_password="hashed")


def owned_project(project_id="project-1"):
    return Project(
        id=project_id,
        owner_id="user-1",
        name="Owned",
        created_at=datetime.now(timezone.utc),
        is_demo=False,
    )


def test_asset_import_stores_migration_enum_name():
    database = DB({Project: [owned_project()], AuthorizedScope: [], Asset: []})
    payload = AssetImportRequest(
        project_id="project-1",
        assets=[AssetImportItem(hostname="app.example.com", asset_type="subdomain")],
    )
    import_assets(payload, database, user())
    assert database.committed
    assert database.added[0].asset_type is AssetType.SUBDOMAIN
    assert database.added[0].asset_type.name == "SUBDOMAIN"


def test_asset_import_rejects_unknown_type_without_writing():
    database = DB({Project: [owned_project()], AuthorizedScope: [], Asset: []})
    payload = AssetImportRequest(
        project_id="project-1",
        assets=[AssetImportItem(hostname="app.example.com", asset_type="not-a-type")],
    )
    with pytest.raises(HTTPException) as caught:
        import_assets(payload, database, user())
    assert caught.value.status_code == 400
    assert database.added == []
    assert database.committed is False


def test_finding_severity_filter_accepts_api_value():
    database = DB({Project: [owned_project()], SecurityFinding: []})
    rows = list_findings(
        project_id="project-1",
        severity="high",
        validation_status=None,
        source_tool=None,
        search=None,
        skip=0,
        limit=100,
        db=database,
        current_user=user(),
    )
    assert rows == []


def test_finding_severity_filter_rejects_unknown_value():
    database = DB({Project: [owned_project()], SecurityFinding: []})
    with pytest.raises(HTTPException) as caught:
        list_findings(
            project_id="project-1",
            severity="severe",
            validation_status=None,
            source_tool=None,
            search=None,
            skip=0,
            limit=100,
            db=database,
            current_user=user(),
        )
    assert caught.value.status_code == 400


def test_remediation_status_update_stores_enum_member():
    suggestion = RemediationSuggestion(id="rem-1", finding_id="finding-1", recommendation="Patch")
    finding = SecurityFinding(
        id="finding-1",
        project_id="project-1",
        title="Header",
        scanner_severity=Severity.LOW,
        effective_severity=Severity.LOW,
        validation_status=ValidationStatus.PENDING,
        confidence=ConfidenceLevel.UNVERIFIED,
    )
    database = DB({
        RemediationSuggestion: [suggestion],
        SecurityFinding: [finding],
        Project: [owned_project()],
    })
    updated = update_remediation_status(
        "rem-1",
        RemediationStatusUpdate(status="accepted"),
        database,
        user(),
    )
    assert updated.status.name == "ACCEPTED"
    assert database.committed


def test_remediation_status_update_rejects_unknown_status():
    suggestion = RemediationSuggestion(id="rem-1", finding_id="finding-1")
    finding = SecurityFinding(
        id="finding-1",
        project_id="project-1",
        title="Header",
        scanner_severity=Severity.LOW,
        effective_severity=Severity.LOW,
        validation_status=ValidationStatus.PENDING,
        confidence=ConfidenceLevel.UNVERIFIED,
    )
    database = DB({
        RemediationSuggestion: [suggestion],
        SecurityFinding: [finding],
        Project: [owned_project()],
    })
    with pytest.raises(HTTPException) as caught:
        update_remediation_status(
            "rem-1",
            RemediationStatusUpdate(status="ship-it"),
            database,
            user(),
        )
    assert caught.value.status_code == 400
    assert database.committed is False


def test_scan_reference_cases():
    owner = user()
    scan = ScanJob(id="scan-1", project_id="project-1", name="Scan", target="example.com", modules=["httpx"])
    database = DB({ScanJob: [scan], Project: [owned_project()]})
    assert resolve_scan_for_import(database, owner, "project-1", "scan-1") is scan

    missing = DB({ScanJob: [], Project: [owned_project()]})
    with pytest.raises(HTTPException) as missing_scan:
        resolve_scan_for_import(missing, owner, "project-1", "missing")
    assert missing_scan.value.status_code == 404

    other = Project(id="project-2", owner_id="user-2", name="Theirs", created_at=datetime.now(timezone.utc))
    foreign_scan = ScanJob(id="scan-2", project_id="project-2", name="Foreign", target="example.com", modules=["httpx"])
    foreign = DB({ScanJob: [foreign_scan], Project: [other]})
    with pytest.raises(HTTPException) as cross_user:
        resolve_scan_for_import(foreign, owner, "project-1", "scan-2")
    assert cross_user.value.status_code == 403

    other_project = owned_project("project-9")
    moved = ScanJob(id="scan-3", project_id="project-9", name="Other", target="example.com", modules=["httpx"])
    cross = DB({ScanJob: [moved], Project: [other_project]})
    with pytest.raises(HTTPException) as cross_project:
        resolve_scan_for_import(cross, owner, "project-1", "scan-3")
    assert cross_project.value.status_code == 403


def test_finding_import_does_not_write_when_scan_is_missing():
    database = DB({Project: [owned_project()], ScanJob: [], SecurityFinding: []})
    payload = FindingImportRequest(
        project_id="project-1",
        scan_job_id="missing",
        findings=[{"title": "Should not be stored", "severity": "low"}],
    )
    with pytest.raises(HTTPException) as caught:
        import_findings(payload, database, user())
    assert caught.value.status_code == 404
    assert database.added == []
    assert database.committed is False


def _finding():
    return SecurityFinding(
        id="finding-1",
        project_id="project-1",
        title="Missing header",
        scanner_severity=Severity.MEDIUM,
        effective_severity=Severity.MEDIUM,
        validation_status=ValidationStatus.PENDING,
        confidence=ConfidenceLevel.UNVERIFIED,
        remediation="Add the header",
        ai_explanation=None,
        is_demo=False,
        evidence={"header": "absent"},
    )


def test_json_report_does_not_claim_ai_and_honors_remediation_flag():
    project = owned_project()
    finding = _finding()
    database = DB({
        Project: [project],
        SecurityFinding: [finding],
        Asset: [Asset(id="asset-1", project_id="project-1", hostname="app.example.com", status=AssetStatus.UNKNOWN)],
        AuthorizedScope: [],
    })
    included = _build_report_data(project, database, include_remediation=True)
    assert "AI-assisted" not in included["executive_summary"]["methodology"]
    assert "no AI analysis" in included["executive_summary"]["methodology"]
    assert included["findings"][0]["remediation"] == "Add the header"

    excluded = _build_report_data(project, database, include_remediation=False)
    assert "remediation" not in excluded["findings"][0]


def test_pdf_report_is_rejected_and_not_stored():
    database = DB({})
    payload = ReportGenerateRequest(project_id="project-1", format="pdf")
    with pytest.raises(HTTPException) as caught:
        generate_report(payload, database, user())
    assert caught.value.status_code == 400
    assert "not implemented" in caught.value.detail
    assert database.added == []


def test_pdf_download_is_rejected():
    report = SecurityReport(
        id="report-1",
        project_id="project-1",
        title="Report",
        report_format=ReportFormat.PDF,
        report_data={"findings": []},
    )
    database = DB({SecurityReport: [report], Project: [owned_project()]})
    with pytest.raises(HTTPException) as caught:
        download_report("report-1", database, user())
    assert caught.value.status_code == 400


def test_asset_status_filter_rejects_unknown_value():
    database = DB({Project: [owned_project()], Asset: []})
    with pytest.raises(HTTPException) as caught:
        list_assets(
            project_id="project-1",
            status="asleep",
            search=None,
            skip=0,
            limit=100,
            db=database,
            current_user=user(),
        )
    assert caught.value.status_code == 400
