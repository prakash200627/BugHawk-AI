"""httpx scope and execution tests. The process is mocked. No live probe."""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.api.scans import scan_to_response
from app.database.session import get_db
from app.main import app
from app.models import Asset, AssetStatus, AssetType, AuthorizedScope, Project, ScanJob, ScanStatus, User, UserRole
from app.scanners.httpx import (
    HttpxOutcome,
    HttpxProbe,
    parse_httpx_line,
    parse_httpx_output,
    resolve_httpx_executable,
    run_httpx,
)
from app.workers import scan_worker
from app.workers.scan_worker import (
    claim_supported_job,
    execute_httpx_scan,
    fail_stale_running,
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


def _scan(project_id="project-1", target="example.com", status=ScanStatus.RUNNING):
    return ScanJob(
        id="scan-httpx",
        project_id=project_id,
        name="HTTP",
        target=target,
        modules=["httpx"],
        status=status,
        scope_validated=True,
        findings_count=0,
        is_demo=False,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
    )


def _asset(hostname, project_id="project-1"):
    return Asset(
        id=f"asset-{hostname}",
        project_id=project_id,
        hostname=hostname,
        asset_type=AssetType.SUBDOMAIN,
        status=AssetStatus.UNKNOWN,
        is_in_scope=True,
        is_demo=False,
    )


def _scopes(*values, project_id="project-1"):
    return [
        AuthorizedScope(id=f"scope-{index}", project_id=project_id, scope_value=value, is_active=True)
        for index, value in enumerate(values)
    ]


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_executable_must_be_httpx():
    assert resolve_httpx_executable("httpx") == "httpx"
    assert resolve_httpx_executable(r"C:\tools\httpx.exe") == r"C:\tools\httpx.exe"
    with pytest.raises(Exception):
        resolve_httpx_executable("curl")
    with pytest.raises(Exception):
        resolve_httpx_executable("httpx && whoami")


def test_parse_http_and_https_only_when_fields_exist():
    allowed = {"www.example.com"}
    https = parse_httpx_line(
        json.dumps({
            "url": "https://www.example.com",
            "status_code": 200,
            "title": "Example",
            "webserver": "nginx",
            "tech": ["Nginx"],
            "body": "secret page",
            "a": ["10.1.2.3"],
        }),
        allowed,
    )
    http = parse_httpx_line(json.dumps({"url": "http://www.example.com", "status_code": 301}), allowed)
    bare = parse_httpx_line(json.dumps({"url": "https://www.example.com"}), allowed)
    assert https is not None and http is not None and bare is not None
    assert https.status_code == 200
    assert https.title == "Example"
    assert https.webserver == "nginx"
    assert https.technologies == ["Nginx"]
    assert http.status_code == 301
    assert http.title is None
    assert http.webserver is None
    assert http.technologies == []
    assert bare.status_code is None
    assert bare.title is None
    assert "body" not in https.__dict__
    assert "10.1.2.3" not in json.dumps(https.__dict__)


def test_redirect_and_invalid_lines_are_dropped():
    raw = "\n".join([
        "not-json",
        json.dumps({"url": "https://www.example.com", "location": "https://evil.test/", "status_code": 302}),
        json.dumps({"url": "https://www.example.com:8443", "status_code": 200}),
        json.dumps({"url": "https://evil.test", "status_code": 200}),
        json.dumps({"url": "https://www.example.com", "status_code": 200, "title": "ok"}),
        json.dumps({"url": "https://www.example.com", "status_code": 200, "title": "ok"}),
    ]).encode()
    probes, invalid = parse_httpx_output(raw, {"www.example.com"})
    assert [probe.url for probe in probes] == ["https://www.example.com"]
    assert probes[0].title == "ok"
    assert invalid == 4


def test_run_httpx_uses_a_fixed_argument_list(monkeypatch):
    captured = {}

    class Proc:
        returncode = 0

        def __init__(self):
            import io
            self.stdout = io.BytesIO(b'{"url":"https://www.example.com","status_code":200}\n')
            self.stderr = io.BytesIO(b"")
            self.stdin = io.BytesIO()

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

        def kill(self):
            self.returncode = -9

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        captured["stdin"] = kwargs["stdin"]
        return Proc()

    monkeypatch.setattr("app.scanners.httpx.subprocess.Popen", fake_popen)
    outcome = run_httpx(["www.example.com", "www.example.com"], executable="httpx", job_timeout_seconds=5)
    assert captured["kwargs"]["shell"] is False
    assert captured["argv"][0] == "httpx"
    assert "-follow-redirects" not in captured["argv"]
    assert captured["argv"][captured["argv"].index("-ports") + 1] == "80,443"
    assert "-threads" in captured["argv"]
    assert outcome.exit_code == 0
    assert [probe.url for probe in outcome.probes] == ["https://www.example.com"]


def test_run_httpx_timeout(monkeypatch):
    import subprocess

    class Proc:
        returncode = None

        def __init__(self):
            import io
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")
            self.stdin = io.BytesIO()

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="httpx", timeout=timeout)

        def poll(self):
            return None

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("app.scanners.httpx.subprocess.Popen", lambda *args, **kwargs: Proc())
    outcome = run_httpx(["www.example.com"], executable="httpx", job_timeout_seconds=1)
    assert outcome.timed_out is True
    assert outcome.probes == []
    assert outcome.message == "httpx timed out."


def _execute(scan, scopes, assets, probes, **flags):
    seen = {}

    def scopes_for(db, project_id):
        seen["scope_project"] = project_id
        return [row.scope_value for row in scopes if row.project_id == project_id]

    def assets_for(db, project_id):
        seen["asset_project"] = project_id
        return [asset for asset in assets if asset.project_id == project_id]

    def existing(db, project_id, hostname):
        matches = [
            asset for asset in assets
            if asset.project_id == project_id and asset.hostname == hostname
        ]
        return matches[0] if matches else None

    def runner(hosts):
        seen["hosts"] = list(hosts)
        return flags.get("outcome") or HttpxOutcome(
            exit_code=flags.get("exit_code", 0),
            probes=probes,
            invalid_lines=flags.get("invalid_lines", 0),
            timed_out=flags.get("timed_out", False),
            failed=flags.get("failed", False) or flags.get("timed_out", False),
            message=flags.get("message", ""),
        )

    original = (
        scan_worker.load_scope_values,
        scan_worker.load_project_assets,
        scan_worker.existing_asset,
    )
    scan_worker.load_scope_values = scopes_for
    scan_worker.load_project_assets = assets_for
    scan_worker.existing_asset = existing
    try:
        result = execute_httpx_scan(MagicMock(), scan, runner=runner)
    finally:
        scan_worker.load_scope_values, scan_worker.load_project_assets, scan_worker.existing_asset = original
    return result, seen


def test_authorized_assets_are_probed_for_http_and_https():
    asset = _asset("www.example.com")
    result, seen = _execute(
        _scan(),
        _scopes("*.example.com"),
        [asset],
        [
            HttpxProbe("www.example.com", "https://www.example.com", 200, "Example", "nginx", ["Nginx"]),
            HttpxProbe("www.example.com", "http://www.example.com", 200),
        ],
    )
    assert seen["hosts"] == ["www.example.com"]
    assert seen["asset_project"] == "project-1"
    assert result.status == ScanStatus.COMPLETED
    assert asset.http_status_code == 200
    assert asset.title == "Example"
    assert asset.technologies == ["Nginx"]
    assert asset.status == AssetStatus.LIVE
    urls = [row["url"] for row in result.raw_output["results"]]
    assert urls == ["https://www.example.com", "http://www.example.com"]
    assert result.raw_output["results"][1].get("title") is None
    assert result.raw_output["results"][1].get("webserver") is None
    assert result.findings_count == 0


def test_out_of_scope_asset_is_not_probed():
    inside = _asset("www.example.com")
    outside = _asset("evil.test")
    result, seen = _execute(
        _scan(),
        _scopes("*.example.com"),
        [inside, outside],
        [HttpxProbe("www.example.com", "https://www.example.com", 204)],
    )
    assert seen["hosts"] == ["www.example.com"]
    assert outside.status == AssetStatus.UNKNOWN
    assert result.raw_output["rejected_out_of_scope"] == 1
    assert result.status == ScanStatus.COMPLETED


def test_duplicate_assets_are_probed_once_and_updated_in_place():
    first = _asset("www.example.com")
    second = _asset("www.example.com")
    second.id = "asset-copy"
    result, seen = _execute(
        _scan(),
        _scopes("*.example.com"),
        [first, second],
        [HttpxProbe("www.example.com", "https://www.example.com", 200, "Once")],
    )
    assert seen["hosts"] == ["www.example.com"]
    assert result.raw_output["updated"] == 1
    assert first.title == "Once"
    assert second.title is None


def test_timeout_does_not_update_assets():
    asset = _asset("www.example.com")
    result, seen = _execute(
        _scan(),
        _scopes("*.example.com"),
        [asset],
        [HttpxProbe("www.example.com", "https://www.example.com", 200, "Nope")],
        timed_out=True,
        message="httpx timed out.",
    )
    assert seen["hosts"] == ["www.example.com"]
    assert result.status == ScanStatus.FAILED
    assert result.error_message == "httpx timed out."
    assert asset.title is None
    assert asset.http_status_code is None
    assert result.raw_output["results"] == []


def test_project_isolation_loads_only_the_job_project():
    owned = _asset("www.example.com", project_id="project-a")
    foreign = _asset("www.example.com", project_id="project-b")
    foreign.title = "other project"
    result, seen = _execute(
        _scan(project_id="project-a"),
        _scopes("*.example.com", project_id="project-a"),
        [owned, foreign],
        [HttpxProbe("www.example.com", "https://www.example.com", 200, "Mine")],
    )
    assert seen["scope_project"] == "project-a"
    assert seen["asset_project"] == "project-a"
    assert owned.title == "Mine"
    assert foreign.title == "other project"
    assert result.status == ScanStatus.COMPLETED

    empty, seen = _execute(
        _scan(project_id="project-a", target="example.com"),
        _scopes("*.other.test", project_id="project-b"),
        [owned],
        [],
    )
    assert empty.status == ScanStatus.FAILED
    assert "hosts" not in seen


def test_httpx_claim_skips_unsupported_modules_and_is_exclusive():
    httpx_job = _scan(status=ScanStatus.PENDING)
    httpx_job.started_at = None
    nuclei = _scan(status=ScanStatus.PENDING)
    nuclei.id = "scan-semgrep"
    nuclei.modules = ["semgrep"]
    database = MagicMock()
    database.query.return_value.filter.return_value.all.return_value = []
    database.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [
        httpx_job, nuclei,
    ]
    database.query.return_value.filter.return_value.update.side_effect = [1, 0, 0]
    first = claim_supported_job(database)
    second = claim_supported_job(database)
    assert first.id == "scan-httpx"
    assert first.status == ScanStatus.RUNNING
    assert nuclei.status == ScanStatus.PENDING
    assert second is None


def test_interrupted_httpx_job_is_failed_and_a_fresh_job_is_left_running():
    stale = _scan(status=ScanStatus.RUNNING)
    stale.started_at = datetime.now(timezone.utc) - timedelta(hours=1)
    fresh = _scan(status=ScanStatus.RUNNING)
    fresh.id = "scan-fresh"
    fresh.started_at = datetime.now(timezone.utc)
    database = MagicMock()
    database.query.return_value.filter.return_value.all.return_value = [stale, fresh]
    assert fail_stale_running(database) == 1
    assert stale.status == ScanStatus.FAILED
    assert "httpx" in stale.error_message
    assert fresh.status == ScanStatus.RUNNING


def test_summary_omits_fields_httpx_did_not_return_and_response_bodies():
    scan = _scan(status=ScanStatus.COMPLETED)
    scan.raw_output = {
        "module": "httpx",
        "probed": 1,
        "updated": 1,
        "rejected_out_of_scope": 0,
        "results": [{
            "hostname": "www.example.com",
            "url": "https://www.example.com",
            "status_code": 200,
            "body": "secret",
            "a": ["10.0.0.8"],
        }],
    }
    summary = scan_to_response(scan).result_summary
    assert summary["results"] == [{
        "hostname": "www.example.com",
        "url": "https://www.example.com",
        "status_code": 200,
    }]


def test_api_accepts_httpx_domain_and_rejects_a_url(client):
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
        "name": "Services",
        "target": "example.com",
        "modules": ["httpx"],
        "httpx_path": "/tmp/not-httpx",
    })
    assert created.status_code == 201
    assert created.json()["status"] == "pending"
    assert created.json()["modules"] == ["httpx"]
    assert database.added[0].status == ScanStatus.PENDING

    url = client.post("/api/scans", json={
        "project_id": "project-1",
        "name": "URL",
        "target": "https://example.com/admin",
        "modules": ["httpx"],
    })
    assert url.status_code == 400

    mixed = client.post("/api/scans", json={
        "project_id": "project-1",
        "name": "Mixed",
        "target": "example.com",
        "modules": ["httpx", "nuclei"],
    })
    assert mixed.status_code == 400
    assert len(database.added) == 1
