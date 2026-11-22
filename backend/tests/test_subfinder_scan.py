"""Subfinder scope and execution tests. Subprocess is mocked. No live lookup."""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.database.session import get_db
from app.main import app
from app.models import Asset, AuthorizedScope, ScanJob, ScanStatus, User, UserRole
from app.scanners.subfinder import (
    SubfinderOutcome,
    is_safe_domain,
    parse_subfinder_hosts,
    resolve_subfinder_executable,
    run_subfinder,
    sanitize_tool_text,
)
from app.workers.scan_worker import (
    claim_subfinder_job,
    execute_subfinder_scan,
    fail_stale_running,
    is_subfinder_job,
    load_scope_values,
    mark_running,
)


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


def _scan(target="example.com", project_id="project-1", status=ScanStatus.RUNNING):
    return ScanJob(
        id="scan-1",
        project_id=project_id,
        name="Passive",
        target=target,
        modules=["subfinder"],
        status=status,
        scope_validated=True,
        findings_count=0,
        is_demo=False,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _scopes(*values, project_id="project-1"):
    return [
        AuthorizedScope(id=f"scope-{index}", project_id=project_id, scope_value=value, is_active=True)
        for index, value in enumerate(values)
    ]


def test_parse_deduplicates_and_drops_junk():
    raw = b"WWW.Example.com\nwww.example.com.\n*.example.com\n203.0.113.10\nnot a host\n-example.com\napi.example.com\n"
    assert parse_subfinder_hosts(raw) == ["www.example.com", "api.example.com"]


def test_executable_must_be_subfinder():
    assert resolve_subfinder_executable("subfinder") == "subfinder"
    assert resolve_subfinder_executable("/usr/local/bin/subfinder") == "/usr/local/bin/subfinder"
    with pytest.raises(Exception):
        resolve_subfinder_executable("bash")
    with pytest.raises(Exception):
        resolve_subfinder_executable("subfinder;id")


def test_sanitize_removes_connection_urls():
    text = sanitize_tool_text(b"dial postgresql://user:secret@db.internal/app failed")
    assert "secret" not in text
    assert "db.internal" not in text


def test_run_subfinder_uses_an_argument_list(monkeypatch):
    captured = {}

    class Proc:
        returncode = 0
        stdout = None
        stderr = None

        def __init__(self):
            import io
            self.stdout = io.BytesIO(b"www.example.com\nwww.example.com\n")
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

        def kill(self):
            self.returncode = -9

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return Proc()

    monkeypatch.setattr("app.scanners.subfinder.subprocess.Popen", fake_popen)
    outcome = run_subfinder("example.com", executable="subfinder", timeout_seconds=5, max_output_bytes=1000)
    assert captured["kwargs"]["shell"] is False
    assert captured["argv"] == ["subfinder", "-silent", "-d", "example.com"]
    assert outcome.exit_code == 0
    assert outcome.hosts == ["www.example.com"]
    assert is_safe_domain("-example.com") is False


def test_run_subfinder_timeout(monkeypatch):
    import subprocess

    class Proc:
        returncode = None
        stdout = None
        stderr = None

        def __init__(self):
            import io
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="subfinder", timeout=timeout)

        def poll(self):
            return None

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("app.scanners.subfinder.subprocess.Popen", lambda *args, **kwargs: Proc())
    outcome = run_subfinder("example.com", executable="subfinder", timeout_seconds=1)
    assert outcome.timed_out is True
    assert outcome.hosts == []
    assert outcome.message == "Subfinder timed out."


def _execute(scan, scopes, hosts, exit_code=0, timed_out=False, failed=False, message="", assets=None):
    database = MagicMock()
    database.query.return_value.filter.return_value.first.side_effect = list(assets or [])
    added = []
    database.add.side_effect = added.append
    monkey_scopes = scopes

    def runner(domain):
        runner.domain = domain
        return SubfinderOutcome(
            exit_code=exit_code,
            hosts=hosts,
            timed_out=timed_out,
            failed=failed or timed_out or exit_code not in (0, None) and exit_code != 0,
            message=message,
        )

    runner.domain = None
    import app.workers.scan_worker as worker
    original = worker.load_scope_values
    worker.load_scope_values = lambda db, project_id: [row.scope_value for row in monkey_scopes if row.project_id == project_id]
    original_existing = worker.existing_asset
    existing_rows = {asset.hostname: asset for asset in (assets or [])}

    def existing(db, project_id, hostname):
        return existing_rows.get(hostname)

    worker.existing_asset = existing
    try:
        result = execute_subfinder_scan(database, scan, runner=runner)
    finally:
        worker.load_scope_values = original
        worker.existing_asset = original_existing
    return result, added, runner.domain, database


def test_authorized_domain_is_executed_and_stored():
    scan = _scan()
    result, added, domain, database = _execute(
        scan,
        _scopes("*.example.com"),
        ["www.example.com", "example.com"],
    )
    assert domain == "example.com"
    assert result.status == ScanStatus.COMPLETED
    assert result.completed_at is not None
    assert [asset.hostname for asset in added] == ["www.example.com", "example.com"]
    assert all(asset.project_id == "project-1" and asset.discovery_source == "subfinder" for asset in added)
    assert result.raw_output["stored"] == 2
    assert result.findings_count == 0
    database.commit.assert_called()


def test_duplicate_and_out_of_scope_results_are_not_inserted():
    scan = _scan()
    existing = Asset(project_id="project-1", hostname="www.example.com", asset_type="subdomain")
    result, added, domain, _database = _execute(
        scan,
        _scopes("*.example.com"),
        ["www.example.com", "api.example.com", "evil.test", "notexample.com"],
        assets=[existing],
    )
    assert domain == "example.com"
    assert [asset.hostname for asset in added] == ["api.example.com"]
    assert result.status == ScanStatus.COMPLETED
    assert result.raw_output["duplicates"] == 1
    assert result.raw_output["rejected_out_of_scope"] == 2
    assert "evil.test" not in result.raw_output["hostnames"]


def test_empty_results_complete_without_assets():
    scan = _scan()
    result, added, _domain, _database = _execute(scan, _scopes("*.example.com"), [])
    assert result.status == ScanStatus.COMPLETED
    assert added == []
    assert result.raw_output["stored"] == 0
    assert result.error_message is None


def test_timeout_and_nonzero_exit_fail_without_storage():
    scan = _scan()
    timed, added, domain, _database = _execute(
        scan, _scopes("*.example.com"), ["www.example.com"], timed_out=True, message="Subfinder timed out."
    )
    assert domain == "example.com"
    assert timed.status == ScanStatus.FAILED
    assert timed.error_message == "Subfinder timed out."
    assert added == []

    scan = _scan()
    failed, added, domain, _database = _execute(
        scan,
        _scopes("*.example.com"),
        ["www.example.com"],
        exit_code=2,
        message="Subfinder exited with status 2.",
    )
    assert failed.status == ScanStatus.FAILED
    assert added == []
    assert "www.example.com" not in (failed.raw_output or {}).get("hostnames", [])


def test_worker_revalidates_and_rejects_revoked_or_foreign_scope():
    scan = _scan(target="example.com", project_id="project-a")
    result, added, domain, _database = _execute(scan, _scopes("*.example.com", project_id="project-b"), ["www.example.com"])
    assert domain is None
    assert result.status == ScanStatus.FAILED
    assert added == []

    called = {}

    def scopes(db, project_id):
        called["project_id"] = project_id
        return ["*.example.com"] if project_id == "project-a" else []

    import app.workers.scan_worker as worker
    original = worker.load_scope_values
    worker.load_scope_values = scopes
    worker.existing_asset = lambda db, project_id, hostname: None
    try:
        scan = _scan(project_id="project-a")
        execute_subfinder_scan(MagicMock(), scan, runner=lambda domain: SubfinderOutcome(exit_code=0, hosts=["www.example.com"]))
    finally:
        worker.load_scope_values = original
    assert called["project_id"] == "project-a"


def test_status_claim_and_stale_running():
    pending = _scan(status=ScanStatus.PENDING)
    pending.started_at = None
    other = _scan(status=ScanStatus.PENDING)
    other.id = "scan-2"
    other.modules = ["httpx"]
    database = MagicMock()
    database.query.return_value.filter.return_value.all.return_value = []
    database.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [other, pending]
    database.query.return_value.filter.return_value.update.return_value = 1
    claimed = claim_subfinder_job(database)
    assert claimed.id == "scan-1"
    assert claimed.status == ScanStatus.RUNNING
    assert claimed.started_at is not None
    assert is_subfinder_job(["httpx"]) is False

    database.query.return_value.filter.return_value.update.return_value = 0
    assert mark_running(database, pending) is False

    stale = _scan(status=ScanStatus.RUNNING)
    stale.started_at = datetime.now(timezone.utc) - timedelta(hours=1)
    holder = MagicMock()
    holder.query.return_value.filter.return_value.all.return_value = [stale]
    assert fail_stale_running(holder) == 1
    assert stale.status == ScanStatus.FAILED


def test_api_rejects_out_of_scope_invalid_and_mixed_modules(client):
    from app.models import Project

    user = _user()
    app.dependency_overrides[get_current_user] = lambda: user
    owned = Project(id="project-1", owner_id=user.id, name="Mine", is_demo=False)

    class DB:
        def __init__(self, scopes):
            self.scopes = scopes
            self.added = []

        def query(self, model):
            query = MagicMock()
            if model is AuthorizedScope:
                query.filter.return_value.all.return_value = self.scopes
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

    database = DB(_scopes("*.example.com"))

    def override_db():
        yield database

    app.dependency_overrides[get_db] = override_db

    denied = client.post("/api/scans", json={
        "project_id": "project-1", "name": "Nope", "target": "other.test", "modules": ["subfinder"],
    })
    assert denied.status_code == 403
    assert database.added == []

    invalid = client.post("/api/scans", json={
        "project_id": "project-1", "name": "Bad", "target": "not a domain", "modules": ["subfinder"],
    })
    assert invalid.status_code == 400

    address = client.post("/api/scans", json={
        "project_id": "project-1", "name": "IP", "target": "203.0.113.10", "modules": ["subfinder"],
    })
    assert address.status_code == 400
    assert "IP" in address.json()["detail"]

    mixed = client.post("/api/scans", json={
        "project_id": "project-1", "name": "Mixed", "target": "example.com", "modules": ["subfinder", "httpx"],
    })
    assert mixed.status_code == 400

    created = client.post("/api/scans", json={
        "project_id": "project-1", "name": "Passive", "target": "https://Example.com/path", "modules": ["subfinder"],
    })
    assert created.status_code == 201
    assert created.json()["status"] == "pending"
    assert created.json()["modules"] == ["subfinder"]
    assert database.added[0].status == ScanStatus.PENDING


def test_load_scope_values_uses_the_job_project():
    rows = _scopes("*.example.com", project_id="project-9")
    database = MagicMock()
    database.query.return_value.filter.return_value.all.return_value = rows
    assert load_scope_values(database, "project-9") == ["*.example.com"]
