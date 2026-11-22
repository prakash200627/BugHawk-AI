"""Semgrep and ZAP tests. Processes and archives are local fixtures. No live target is contacted."""
import io
import json
import zipfile
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
    Project,
    ScanJob,
    ScanStatus,
    User,
    UserRole,
    ValidationStatus,
)
from app.scanners.semgrep import (
    SemgrepConfigError,
    SemgrepMatch,
    SemgrepOutcome,
    allocate_source_directory,
    extract_source_archive,
    parse_semgrep_output,
    release_source_directory,
    review_rules,
    run_semgrep,
)
from app.scanners.zap import ZapAlert, ZapOutcome, resolve_zap_executable, run_zap
from app.workers import scan_worker
from app.workers.scan_worker import claim_supported_job, execute_semgrep_scan, execute_zap_scan, run_once


def _user():
    return User(
        id="user-1", email="analyst@example.com", hashed_password="hashed", role=UserRole.ANALYST,
        is_active=True, is_demo=False, created_at=datetime.now(timezone.utc),
    )


def _scan(modules, project_id="project-1", status=ScanStatus.RUNNING):
    return ScanJob(
        id=f"scan-{modules[0]}", project_id=project_id, name="Job", target="example.com", modules=modules,
        status=status, scope_validated=True, findings_count=0, is_demo=False,
        created_at=datetime.now(timezone.utc), started_at=datetime.now(timezone.utc),
    )


def _asset(hostname="www.example.com", project_id="project-1", status_code=200):
    return Asset(
        id=f"asset-{project_id}-{hostname}", project_id=project_id, hostname=hostname,
        asset_type=AssetType.SUBDOMAIN, status=AssetStatus.LIVE, http_status_code=status_code,
        is_in_scope=True, is_demo=False,
    )


def _scopes(*values, project_id="project-1"):
    return [AuthorizedScope(id=f"scope-{i}", project_id=project_id, scope_value=value, is_active=True) for i, value in enumerate(values)]


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "def run(value):\n    return eval(value)\n")
        archive.writestr(".env", "PASSWORD=secret\n")
        archive.writestr("notes.md", "ignore\n")
    return buffer.getvalue()


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_reviewed_semgrep_rules_and_rejected_directory(tmp_path):
    assert len(review_rules()) == 3
    (tmp_path / "evil.yaml").write_text("rules:\n- id: rce\n", encoding="utf-8")
    with pytest.raises(Exception):
        review_rules(tmp_path)


def test_semgrep_refuses_an_arbitrary_directory_and_uses_fixed_arguments(monkeypatch):
    outcome = run_semgrep(__import__("pathlib").Path("."), executable="semgrep")
    assert outcome.failed is True
    assert "allocate" in outcome.message
    directory = allocate_source_directory()
    captured = {}

    class Proc:
        returncode = 0

        def __init__(self):
            import io as bio
            self.stdout = bio.BytesIO(b'{"results":[]}')
            self.stderr = bio.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

        def kill(self):
            self.returncode = -9

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["shell"] = kwargs["shell"]
        return Proc()

    monkeypatch.setattr("app.scanners.semgrep.subprocess.Popen", fake_popen)
    try:
        outcome = run_semgrep(directory, executable="semgrep", timeout_seconds=5)
    finally:
        release_source_directory(directory)
    assert captured["shell"] is False
    assert captured["argv"][0] == "semgrep"
    assert "--config" in captured["argv"]
    assert "r/" not in captured["argv"]
    assert outcome.exit_code == 0


def test_archive_escape_is_rejected_and_secrets_are_redacted():
    directory = allocate_source_directory()
    try:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../outside.py", "eval(1)\n")
        with pytest.raises(SemgrepConfigError):
            extract_source_archive(buffer.getvalue(), directory)
        stored = extract_source_archive(_zip(), directory)
        assert stored == 1
        assert (directory / ".env").exists() is False
    finally:
        release_source_directory(directory)
    matches, invalid = parse_semgrep_output(json.dumps({
        "results": [
            {"check_id": "bughawk-python-eval", "path": "app.py", "start": {"line": 2}, "extra": {"severity": "WARNING", "lines": "password=hunter2"}},
            {"check_id": "not-reviewed", "path": "app.py", "start": {"line": 1}, "extra": {"severity": "ERROR"}},
        ]
    }).encode(), directory)
    assert invalid == 1
    assert matches[0].evidence == "[redacted]"
    assert parse_semgrep_output(b"not-json", directory)[1] == 1


def test_semgrep_job_reports_the_missing_source_prerequisite():
    called = {}
    scan = _scan(["semgrep"])
    original = scan_worker.load_scope_values
    scan_worker.load_scope_values = lambda db, project_id: ["*.example.com"] if project_id == "project-1" else []
    try:
        result = execute_semgrep_scan(MagicMock(), scan, runner=lambda directory: called.setdefault("ran", True))
    finally:
        scan_worker.load_scope_values = original
    assert called == {}
    assert result.status == ScanStatus.FAILED
    assert "no uploaded source archive" in result.error_message
    assert result.findings_count == 0


def test_semgrep_persists_a_static_finding_once_and_isolates_the_project():
    scan = _scan(["semgrep"], project_id="project-a")
    added = []
    seen = {}

    def bundle(db, project_id):
        seen["project_id"] = project_id
        return _zip() if project_id == "project-a" else None

    def existing(db, project_id, scan_id, template_id, endpoint):
        return next((row for row in added if row.project_id == project_id and row.scan_job_id == scan_id and row.source_template == template_id and row.endpoint == endpoint), None)

    match = SemgrepMatch("bughawk-python-eval", "app.py", 2, "medium", "eval(value)")
    database = MagicMock()
    database.add.side_effect = added.append
    original = (scan_worker.load_scope_values, scan_worker.load_source_bundle, scan_worker.existing_nuclei_finding)
    scan_worker.load_scope_values = lambda db, project_id: ["*.example.com"] if project_id == "project-a" else []
    scan_worker.load_source_bundle = bundle
    scan_worker.existing_nuclei_finding = existing
    try:
        result = execute_semgrep_scan(
            database,
            scan,
            runner=lambda directory: SemgrepOutcome(exit_code=1, matches=[match, match]),
        )
    finally:
        scan_worker.load_scope_values, scan_worker.load_source_bundle, scan_worker.existing_nuclei_finding = original
    assert seen["project_id"] == "project-a"
    assert result.status == ScanStatus.COMPLETED
    assert len(added) == 1
    assert added[0].vulnerability_type == "static-analysis"
    assert added[0].evidence["source_kind"] == "static"
    assert added[0].evidence["confirmed"] is False
    assert added[0].validation_status == ValidationStatus.PENDING
    assert result.raw_output["duplicates"] == 1

    denied = _scan(["semgrep"], project_id="project-b")
    scan_worker.load_scope_values = lambda db, project_id: []
    try:
        failed = execute_semgrep_scan(MagicMock(), denied, runner=lambda directory: None)
    finally:
        scan_worker.load_scope_values = original[0]
    assert failed.status == ScanStatus.FAILED


def test_zap_binds_loopback_and_drops_out_of_scope_alerts(monkeypatch):
    assert resolve_zap_executable("zap.sh") == "zap.sh"
    with pytest.raises(Exception):
        resolve_zap_executable("bash")
    captured = {}

    class Proc:
        def poll(self):
            return 1

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 1

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["shell"] = kwargs["shell"]
        return Proc()

    monkeypatch.setattr("app.scanners.zap.subprocess.Popen", fake_popen)
    monkeypatch.setattr("app.scanners.zap._local_get", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("down")))
    failed = run_zap(["https://www.example.com"], executable="zap.sh", job_timeout_seconds=1)
    assert captured["shell"] is False
    assert captured["argv"][captured["argv"].index("-host") + 1] == "127.0.0.1"
    assert "-daemon" in captured["argv"]
    assert failed.failed is True

    routes = []

    def transport(route):
        routes.append(route)
        if "alerts" in route:
            return {"alerts": [
                {"pluginId": "10020", "alert": "Header", "risk": "Medium", "confidence": "Low", "url": "https://www.example.com/path", "evidence": "Set-Cookie: session=secret"},
                {"pluginId": "10021", "alert": "Other", "risk": "High", "confidence": "High", "url": "https://evil.test/", "evidence": "x"},
                {"risk": "apocalyptic", "url": "https://www.example.com/"},
            ]}
        return {"version": "2.16.0"}

    outcome = run_zap(["https://www.example.com"], executable="zap.sh", transport=transport, job_timeout_seconds=2)
    scope_at = next(index for index, route in enumerate(routes) if "setScanOnlyInScope" in route)
    access_at = next(index for index, route in enumerate(routes) if "accessUrl" in route)
    assert scope_at < access_at
    assert all("spider" not in route and "ascan" not in route for route in routes)
    assert [alert.plugin_id for alert in outcome.alerts] == ["10020"]
    assert outcome.alerts[0].evidence == "[redacted]"
    assert outcome.alerts[0].hostname == "www.example.com"


def test_zap_worker_stores_potential_findings_and_discards_failures():
    asset = _asset()
    added = []
    seen = {}

    def scopes(db, project_id):
        seen["scope_project"] = project_id
        return ["*.example.com"] if project_id == "project-1" else []

    def assets(db, project_id):
        seen["asset_project"] = project_id
        return [asset] if project_id == asset.project_id else []

    def httpx(db, project_id):
        seen["httpx_project"] = project_id
        if project_id != "project-1":
            return []
        return [
            {"hostname": "www.example.com", "url": "https://www.example.com", "status_code": 200},
            {"hostname": "evil.test", "url": "https://evil.test", "status_code": 200},
            {"hostname": "api.example.com", "url": "https://api.example.com"},
        ]

    def existing(db, project_id, scan_id, template_id, endpoint):
        return next((row for row in added if row.scan_job_id == scan_id and row.source_template == template_id and row.endpoint == endpoint), None)

    alert = ZapAlert("10020", "Header", "medium", "Low", "https://www.example.com/", "www.example.com", "missing")

    def runner(urls):
        seen["urls"] = list(urls)
        return ZapOutcome(exit_code=0, alerts=[alert, alert])

    database = MagicMock()
    database.add.side_effect = added.append
    original = (
        scan_worker.load_scope_values,
        scan_worker.load_project_assets,
        scan_worker.load_httpx_results,
        scan_worker.existing_asset,
        scan_worker.existing_nuclei_finding,
    )
    scan_worker.load_scope_values = scopes
    scan_worker.load_project_assets = assets
    scan_worker.load_httpx_results = httpx
    scan_worker.existing_asset = lambda db, project_id, hostname: asset if project_id == "project-1" and hostname == "www.example.com" else None
    scan_worker.existing_nuclei_finding = existing
    try:
        result = execute_zap_scan(database, _scan(["zap"]), runner=runner)
        timed = execute_zap_scan(
            MagicMock(),
            _scan(["zap"]),
            runner=lambda urls: ZapOutcome(exit_code=None, timed_out=True, failed=True, message="ZAP timed out."),
        )
    finally:
        (
            scan_worker.load_scope_values,
            scan_worker.load_project_assets,
            scan_worker.load_httpx_results,
            scan_worker.existing_asset,
            scan_worker.existing_nuclei_finding,
        ) = original
    assert seen["urls"] == ["https://www.example.com"]
    assert seen["httpx_project"] == "project-1"
    assert result.status == ScanStatus.COMPLETED
    assert len(added) == 1
    assert added[0].vulnerability_type == "web-baseline"
    assert added[0].evidence["confirmed"] is False
    assert added[0].evidence["classification"] == "potential"
    assert added[0].validation_status == ValidationStatus.PENDING
    assert result.raw_output["duplicates"] == 1
    assert timed.status == ScanStatus.FAILED
    assert timed.findings_count == 0


def test_claim_is_exclusive_and_unsupported_jobs_fail():
    zap_job = _scan(["zap"], status=ScanStatus.PENDING)
    zap_job.started_at = None
    other = _scan(["import"], status=ScanStatus.PENDING)
    other.id = "scan-import"
    other.started_at = None
    database = MagicMock()
    database.query.return_value.filter.return_value.all.return_value = []
    database.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [zap_job, other]
    database.query.return_value.filter.return_value.update.side_effect = [1, 0, 0]
    first = claim_supported_job(database)
    second = claim_supported_job(database)
    assert first.id == "scan-zap"
    assert first.status == ScanStatus.RUNNING
    assert second is None
    assert other.status == ScanStatus.PENDING

    stale = _scan(["import"], status=ScanStatus.RUNNING)
    stale.started_at = datetime.now(timezone.utc) - timedelta(hours=1)
    holder = MagicMock()
    holder.query.return_value.filter.return_value.all.return_value = [stale]
    from app.workers.scan_worker import fail_stale_running
    assert fail_stale_running(holder) == 1
    assert stale.status == ScanStatus.FAILED

    pending = _scan(["import"], status=ScanStatus.PENDING)
    pending.started_at = None
    database.query.return_value.filter.return_value.update.side_effect = [1]
    database.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [pending]
    assert run_once(database) is True
    assert pending.status == ScanStatus.FAILED
    assert "import" in pending.error_message


def test_api_accepts_separate_semgrep_and_zap_jobs(client):
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
            return query

        def add(self, obj):
            self.added.append(obj)

        def commit(self):
            return None

        def refresh(self, obj):
            obj.id = "scan-created"
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
        "project_id": "project-1", "name": "Code", "target": "example.com", "modules": ["semgrep"],
        "rules": "/tmp/custom", "semgrep_path": "/tmp/not-semgrep",
    })
    assert created.status_code == 201
    zap = client.post("/api/scans", json={
        "project_id": "project-1", "name": "Baseline", "target": "example.com", "modules": ["zap"],
    })
    assert zap.status_code == 201
    mixed = client.post("/api/scans", json={
        "project_id": "project-1", "name": "Mixed", "target": "example.com", "modules": ["zap", "semgrep"],
    })
    url = client.post("/api/scans", json={
        "project_id": "project-1", "name": "URL", "target": "https://example.com", "modules": ["zap"],
    })
    assert mixed.status_code == 400
    assert url.status_code == 400
    assert [row.modules for row in database.added] == [["semgrep"], ["zap"]]
