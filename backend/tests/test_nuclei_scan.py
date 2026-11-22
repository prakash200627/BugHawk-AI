"""Nuclei scope and execution tests. The process is mocked. No live scan."""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.database.session import get_db
from app.main import app
from app.models import (
    Asset,
    AssetStatus,
    AssetType,
    AuthorizedScope,
    ConfidenceLevel,
    Project,
    ScanJob,
    ScanStatus,
    Severity,
    User,
    UserRole,
    ValidationStatus,
)
from app.scanners.nuclei import (
    NucleiMatch,
    NucleiOutcome,
    NucleiTemplateError,
    parse_nuclei_line,
    review_templates,
    run_nuclei,
)
from app.workers import scan_worker
from app.workers.scan_worker import claim_supported_job, execute_nuclei_scan, fail_stale_running


def _user():
    return User(
        id="user-1",
        email="analyst@example.com",
        hashed_password="hashed",
        role=UserRole.ANALYST,
        is_active=True,
        is_demo=False,
        created_at=datetime.now(timezone.utc),
    )


def _scan(project_id="project-1", status=ScanStatus.RUNNING):
    return ScanJob(
        id="scan-nuclei",
        project_id=project_id,
        name="Headers",
        target="example.com",
        modules=["nuclei"],
        status=status,
        scope_validated=True,
        findings_count=0,
        is_demo=False,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
    )


def _asset(hostname="www.example.com", project_id="project-1", status_code=200):
    return Asset(
        id=f"asset-{project_id}-{hostname}",
        project_id=project_id,
        hostname=hostname,
        asset_type=AssetType.SUBDOMAIN,
        status=AssetStatus.LIVE if status_code is not None else AssetStatus.UNKNOWN,
        http_status_code=status_code,
        is_in_scope=True,
        is_demo=False,
    )


def _scopes(*values, project_id="project-1"):
    return [
        AuthorizedScope(id=f"scope-{index}", project_id=project_id, scope_value=value, is_active=True)
        for index, value in enumerate(values)
    ]


def _http(hostname="www.example.com", scheme="https", status_code=200):
    return {"hostname": hostname, "url": f"{scheme}://{hostname}", "status_code": status_code}


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_packaged_templates_pass_review():
    paths = review_templates()
    assert [path.name for path in paths] == [
        "bughawk-missing-content-type-options.yaml",
        "bughawk-missing-csp.yaml",
        "bughawk-missing-frame-options.yaml",
        "bughawk-missing-hsts.yaml",
        "bughawk-missing-referrer-policy.yaml",
    ]


def test_unsafe_template_directory_is_rejected_without_a_process(tmp_path, monkeypatch):
    (tmp_path / "bughawk-missing-hsts.yaml").write_text(
        "id: bughawk-missing-hsts\ninteractsh-url\nmethod: POST\n",
        encoding="utf-8",
    )
    with pytest.raises(NucleiTemplateError):
        review_templates(tmp_path)
    monkeypatch.setattr("app.scanners.nuclei.TEMPLATE_DIR", tmp_path)
    called = {}
    monkeypatch.setattr(
        "app.scanners.nuclei.subprocess.Popen",
        lambda *args, **kwargs: called.setdefault("ran", True),
    )
    outcome = run_nuclei(["https://www.example.com"], executable="nuclei")
    assert outcome.failed is True
    assert "ran" not in called


def test_parse_drops_malformed_redirects_unknown_templates_and_secrets():
    allowed = {"www.example.com"}
    good = parse_nuclei_line(json.dumps({
        "template-id": "bughawk-missing-hsts",
        "matched-at": "https://www.example.com/",
        "timestamp": "2026-11-22T00:00:00Z",
        "matcher-name": "header",
        "info": {"name": "Strict-Transport-Security header is absent", "severity": "info"},
        "response": "Set-Cookie: session=secret",
        "curl-command": "curl -H 'Authorization: Bearer secret'",
        "extracted-results": ["token=1"],
    }), allowed)
    assert good is not None
    assert good.severity == "info"
    assert good.detected_at == "2026-11-22T00:00:00Z"
    dumped = json.dumps(good.__dict__)
    assert "session" not in dumped
    assert "Bearer" not in dumped
    assert "response" not in good.__dict__
    secret_name = parse_nuclei_line(json.dumps({
        "template-id": "bughawk-missing-hsts",
        "matched-at": "https://www.example.com",
        "info": {"name": "Set-Cookie: session=abc", "severity": "info"},
    }), allowed)
    assert secret_name is not None
    assert secret_name.name == "bughawk-missing-hsts"
    assert parse_nuclei_line("not-json", allowed) is None
    assert parse_nuclei_line(json.dumps({
        "template-id": "cve-2024-exploit",
        "matched-at": "https://www.example.com",
        "info": {"severity": "critical"},
    }), allowed) is None
    assert parse_nuclei_line(json.dumps({
        "template-id": "bughawk-missing-hsts",
        "matched-at": "https://evil.test",
        "info": {"severity": "info"},
    }), allowed) is None
    assert parse_nuclei_line(json.dumps({
        "template-id": "bughawk-missing-hsts",
        "matched-at": "https://www.example.com",
        "info": {"severity": "apocalyptic"},
    }), allowed) is None


def test_run_nuclei_argument_list_is_fixed(monkeypatch):
    captured = {}

    class Proc:
        returncode = 0

        def __init__(self):
            import io
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")
            self.stdin = io.BytesIO()

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

        def kill(self):
            return None

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return Proc()

    monkeypatch.setattr("app.scanners.nuclei.subprocess.Popen", fake_popen)
    outcome = run_nuclei(["https://www.example.com", "https://www.example.com"], executable="nuclei", job_timeout_seconds=5)
    argv = captured["argv"]
    assert captured["kwargs"]["shell"] is False
    assert argv[0] == "nuclei"
    assert "-follow-redirects" not in argv
    assert "-fr" not in argv
    assert "-dast" not in argv
    assert "-fuzz" not in argv
    assert "-update-templates" not in argv
    assert "-no-interactsh" in argv
    assert "-omit-raw" in argv
    assert argv[argv.index("-severity") + 1] == "info,low"
    assert argv[argv.index("-templates") + 1].endswith("nuclei_templates\\safe") or argv[argv.index("-templates") + 1].endswith("nuclei_templates/safe")
    assert outcome.exit_code == 0
    assert outcome.matches == []


def test_run_nuclei_timeout(monkeypatch):
    import subprocess

    class Proc:
        returncode = None

        def __init__(self):
            import io
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")
            self.stdin = io.BytesIO()

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="nuclei", timeout=timeout)

        def poll(self):
            return None

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("app.scanners.nuclei.subprocess.Popen", lambda *args, **kwargs: Proc())
    outcome = run_nuclei(["https://www.example.com"], executable="nuclei", job_timeout_seconds=1)
    assert outcome.timed_out is True
    assert outcome.matches == []
    assert outcome.message == "Nuclei timed out."


def _execute(scan, scopes, assets, results, matches, **flags):
    seen = {}
    added = []

    def scopes_for(db, project_id):
        seen["scope_project"] = project_id
        return [row.scope_value for row in scopes if row.project_id == project_id]

    def assets_for(db, project_id):
        seen["asset_project"] = project_id
        return [asset for asset in assets if asset.project_id == project_id]

    def httpx_for(db, project_id):
        seen["httpx_project"] = project_id
        return [item for item in results if item.get("project_id", project_id) == project_id]

    def existing_asset(db, project_id, hostname):
        for asset in assets:
            if asset.project_id == project_id and asset.hostname == hostname:
                return asset
        return None

    def existing_finding(db, project_id, scan_id, template_id, endpoint):
        for row in added:
            if (
                row.project_id == project_id
                and row.scan_job_id == scan_id
                and row.source_template == template_id
                and row.endpoint == endpoint
            ):
                return row
        return None

    def runner(urls):
        seen["urls"] = list(urls)
        return NucleiOutcome(
            exit_code=flags.get("exit_code", 0),
            matches=[] if flags.get("timed_out") or flags.get("exit_code", 0) not in (0, None) else matches,
            timed_out=flags.get("timed_out", False),
            failed=flags.get("failed", False) or flags.get("timed_out", False) or flags.get("exit_code", 0) not in (0, None),
            message=flags.get("message", ""),
        )

    database = MagicMock()
    database.add.side_effect = added.append
    original = (
        scan_worker.load_scope_values,
        scan_worker.load_project_assets,
        scan_worker.load_httpx_results,
        scan_worker.existing_asset,
        scan_worker.existing_nuclei_finding,
    )
    scan_worker.load_scope_values = scopes_for
    scan_worker.load_project_assets = assets_for
    scan_worker.load_httpx_results = httpx_for
    scan_worker.existing_asset = existing_asset
    scan_worker.existing_nuclei_finding = existing_finding
    try:
        result = execute_nuclei_scan(database, scan, runner=runner)
    finally:
        (
            scan_worker.load_scope_values,
            scan_worker.load_project_assets,
            scan_worker.load_httpx_results,
            scan_worker.existing_asset,
            scan_worker.existing_nuclei_finding,
        ) = original
    return result, seen, added


def test_authorized_http_and_https_targets_create_unconfirmed_findings():
    asset = _asset()
    result, seen, added = _execute(
        _scan(),
        _scopes("*.example.com"),
        [asset],
        [_http(), _http(scheme="http")],
        [
            NucleiMatch("bughawk-missing-hsts", "HSTS absent", "info", "https://www.example.com/", "www.example.com", "2026-11-22T00:00:00Z"),
            NucleiMatch("bughawk-missing-frame-options", "Frame header absent", "low", "http://www.example.com/", "www.example.com"),
        ],
    )
    assert seen["urls"] == ["https://www.example.com", "http://www.example.com"]
    assert result.status == ScanStatus.COMPLETED
    assert result.findings_count == 2
    assert added[0].project_id == "project-1"
    assert added[0].scan_job_id == "scan-nuclei"
    assert added[0].validation_status == ValidationStatus.PENDING
    assert added[0].confidence == ConfidenceLevel.UNVERIFIED
    assert added[0].scanner_severity == Severity.INFO
    assert added[0].evidence["classification"] == "informational"
    assert added[0].evidence["confirmed"] is False
    assert added[0].evidence["detected_at"] == "2026-11-22T00:00:00Z"
    assert added[1].scanner_severity == Severity.LOW
    assert added[1].evidence["classification"] == "potential"
    assert added[1].needs_human_review is True
    assert result.raw_output["informational"] == 1
    assert result.raw_output["potential"] == 1


def test_out_of_scope_and_unverified_targets_are_not_scanned():
    verified = _asset()
    outside = _asset("evil.test")
    bare = _asset("api.example.com", status_code=None)
    result, seen, added = _execute(
        _scan(),
        _scopes("*.example.com"),
        [verified, outside, bare],
        [
            _http(),
            _http("evil.test"),
            {"hostname": "api.example.com", "url": "https://api.example.com"},
        ],
        [],
    )
    assert seen["urls"] == ["https://www.example.com"]
    assert result.status == ScanStatus.COMPLETED
    assert added == []
    assert result.raw_output["rejected_out_of_scope"] == 1
    assert result.raw_output["unverified"] == 1
    assert result.findings_count == 0

    empty, seen, added = _execute(_scan(), _scopes("*.example.com"), [verified], [], [])
    assert "urls" not in seen
    assert empty.status == ScanStatus.COMPLETED
    assert empty.findings_count == 0
    assert added == []


def test_duplicate_findings_and_nonzero_exit():
    asset = _asset()
    match = NucleiMatch("bughawk-missing-hsts", "HSTS absent", "info", "https://www.example.com/", "www.example.com")
    result, _seen, added = _execute(
        _scan(),
        _scopes("*.example.com"),
        [asset],
        [_http()],
        [match, match],
    )
    assert len(added) == 1
    assert result.raw_output["duplicates"] == 1

    failed, _seen, added = _execute(
        _scan(),
        _scopes("*.example.com"),
        [asset],
        [_http()],
        [match],
        exit_code=2,
        message="Nuclei exited with status 2.",
    )
    assert failed.status == ScanStatus.FAILED
    assert added == []

    timed, _seen, added = _execute(
        _scan(),
        _scopes("*.example.com"),
        [asset],
        [_http()],
        [match],
        timed_out=True,
        message="Nuclei timed out.",
    )
    assert timed.status == ScanStatus.FAILED
    assert timed.error_message == "Nuclei timed out."
    assert added == []


def test_project_isolation_uses_only_the_job_project():
    owned = _asset(project_id="project-a")
    foreign = _asset(project_id="project-b")
    result, seen, added = _execute(
        _scan(project_id="project-a"),
        _scopes("*.example.com", project_id="project-a"),
        [owned, foreign],
        [_http(), {**_http(), "project_id": "project-b", "hostname": "www.example.com"}],
        [NucleiMatch("bughawk-missing-hsts", "HSTS absent", "info", "https://www.example.com/", "www.example.com")],
    )
    assert seen["httpx_project"] == "project-a"
    assert seen["asset_project"] == "project-a"
    assert added[0].project_id == "project-a"
    assert added[0].asset_id == owned.id
    assert result.status == ScanStatus.COMPLETED


def test_worker_claims_nuclei_and_recovers_a_stale_job():
    nuclei_job = _scan(status=ScanStatus.PENDING)
    nuclei_job.started_at = None
    semgrep = _scan(status=ScanStatus.PENDING)
    semgrep.id = "scan-semgrep"
    semgrep.modules = ["semgrep"]
    database = MagicMock()
    database.query.return_value.filter.return_value.all.return_value = []
    database.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [
        nuclei_job, semgrep,
    ]
    database.query.return_value.filter.return_value.update.side_effect = [1, 0, 0]
    first = claim_supported_job(database)
    second = claim_supported_job(database)
    assert first.id == "scan-nuclei"
    assert first.status == ScanStatus.RUNNING
    assert semgrep.status == ScanStatus.PENDING
    assert second is None

    stale = _scan(status=ScanStatus.RUNNING)
    stale.started_at = datetime.now(timezone.utc) - timedelta(hours=1)
    holder = MagicMock()
    holder.query.return_value.filter.return_value.all.return_value = [stale]
    assert fail_stale_running(holder) == 1
    assert stale.status == ScanStatus.FAILED
    assert "Nuclei" in stale.error_message


def test_api_accepts_a_nuclei_domain_and_rejects_a_url_or_mix(client):
    user = _user()
    app.dependency_overrides[get_current_user] = lambda: user
    owned = Project(id="project-1", owner_id=user.id, name="Mine", is_demo=False)

    class DB:
        def __init__(self):
            self.added = []

        def query(self, model):
            query = MagicMock()
            if model is AuthorizedScope:
                query.filter.return_value.all.return_value = _scopes("*.example.com")
            elif model is Project:
                query.filter.return_value.first.return_value = owned
            else:
                query.filter.return_value.first.return_value = None
            return query

        def add(self, obj):
            self.added.append(obj)

        def commit(self):
            return None

        def refresh(self, obj):
            obj.id = obj.id or "scan-created"
            obj.created_at = datetime.now(timezone.utc)
            obj.started_at = None
            obj.completed_at = None
            obj.error_message = None
            obj.raw_output = None
            obj.findings_count = 0
            obj.is_demo = False
            obj.scope_validated = True

    database = DB()

    def override_db():
        yield database

    app.dependency_overrides[get_db] = override_db
    created = client.post("/api/scans", json={
        "project_id": "project-1",
        "name": "Headers",
        "target": "example.com",
        "modules": ["nuclei"],
        "templates": "/tmp/exploits",
        "nuclei_path": "/tmp/not-nuclei",
    })
    assert created.status_code == 201
    assert created.json()["status"] == "pending"
    assert database.added[0].modules == ["nuclei"]

    url = client.post("/api/scans", json={
        "project_id": "project-1",
        "name": "URL",
        "target": "https://example.com",
        "modules": ["nuclei"],
    })
    assert url.status_code == 400

    mixed = client.post("/api/scans", json={
        "project_id": "project-1",
        "name": "Mixed",
        "target": "example.com",
        "modules": ["nuclei", "httpx"],
    })
    assert mixed.status_code == 400
    assert len(database.added) == 1
