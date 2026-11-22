"""Role, token, and login-limit checks that do not open a database."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_current_user, require_writer
from app.config import settings
from app.core.login_rate_limit import login_rate_limiter
from app.core.logging import redact_connection_urls
from app.core.security import create_access_token
from app.database.session import get_db
from app.main import app
from app.models import Project, User, UserRole


def _user(role, user_id="user-1", email="person@example.com"):
    return User(
        id=user_id,
        email=email,
        hashed_password="hashed",
        role=role,
        is_active=True,
        is_demo=False,
        full_name=None,
        created_at=datetime.now(timezone.utc),
    )


def _db_returning(value):
    def override():
        database = MagicMock()
        database.query.return_value.filter.return_value.first.return_value = value
        database.query.return_value.filter.return_value.all.return_value = []
        yield database

    return override


@pytest.fixture
def client():
    app.dependency_overrides.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def jwt_secret():
    previous = settings.jwt_secret_key
    settings.jwt_secret_key = "test-only-jwt-secret-value-32b"
    yield
    settings.jwt_secret_key = previous


@pytest.fixture
def tight_login_limit():
    previous = (
        login_rate_limiter.email_limit,
        login_rate_limiter.ip_limit,
        login_rate_limiter.window_seconds,
    )
    login_rate_limiter.email_limit = 3
    login_rate_limiter.ip_limit = 50
    login_rate_limiter.window_seconds = 600
    login_rate_limiter.reset()
    yield login_rate_limiter
    login_rate_limiter.email_limit, login_rate_limiter.ip_limit, login_rate_limiter.window_seconds = previous
    login_rate_limiter.reset()


def _as(user):
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = _db_returning(None)


WRITE_CALLS = [
    ("post", "/api/projects", {"json": {"name": "Owned"}}),
    ("patch", "/api/projects/project-1", {"json": {"name": "Renamed"}}),
    ("post", "/api/scopes", {"params": {"project_id": "project-1"}, "json": {"scope_value": "example.com"}}),
    ("delete", "/api/scopes/scope-1", {}),
    ("post", "/api/assets/import", {"json": {"project_id": "project-1", "assets": [{"hostname": "example.com"}]}}),
    ("post", "/api/scans", {"json": {"project_id": "project-1", "name": "Scan", "target": "example.com", "modules": ["httpx"]}}),
    ("post", "/api/findings/import", {"json": {"project_id": "project-1", "findings": [{"title": "Finding", "severity": "low"}]}}),
    ("post", "/api/reports/generate", {"json": {"project_id": "project-1", "format": "json"}}),
    ("patch", "/api/remediation/rem-1/status", {"json": {"status": "accepted"}}),
    ("post", "/api/agents/chat", {"json": {"project_id": "project-1", "messages": [{"role": "user", "content": "hello"}]}}),
    ("post", "/api/agents/analyze/finding-1", {"json": {"project_id": "project-1"}}),
]


@pytest.mark.parametrize("method,path,kwargs", WRITE_CALLS)
def test_viewer_cannot_write(client, method, path, kwargs):
    _as(_user(UserRole.VIEWER))
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 403
    assert response.json()["detail"] == "Viewers have read-only access"


def test_viewer_can_read_profile_and_validate_scope(client):
    viewer = _user(UserRole.VIEWER)
    _as(viewer)
    profile = client.get("/api/auth/me")
    assert profile.status_code == 200
    assert profile.json()["role"] == "viewer"

    owned = Project(id="project-1", owner_id=viewer.id, name="Mine")
    app.dependency_overrides[get_db] = _db_returning(owned)
    checked = client.post("/api/scopes/validate", json={"project_id": "project-1", "target": "example.com"})
    assert checked.status_code == 200
    assert checked.json()["is_allowed"] is False


def test_analyst_and_admin_pass_the_write_gate_without_bypassing_ownership(client):
    for role in (UserRole.ANALYST, UserRole.ADMIN):
        user = _user(role, user_id=f"id-{role.value}", email=f"{role.value}@example.com")
        _as(user)
        missing = client.delete("/api/scopes/missing-scope")
        assert missing.status_code == 404

        other = Project(id="project-b", owner_id="someone-else", name="Other")
        app.dependency_overrides[get_db] = _db_returning(other)
        denied = client.get("/api/projects/project-b")
        assert denied.status_code == 403
        assert denied.json()["detail"] == "You do not have access to this project"


def test_unknown_role_cannot_write():
    user = _user(UserRole.ANALYST)
    user.role = None
    with pytest.raises(Exception) as caught:
        require_writer(current_user=user)
    assert getattr(caught.value, "status_code", None) == 403


def test_missing_invalid_and_expired_tokens(client, jwt_secret):
    missing = client.get("/api/auth/me")
    assert missing.status_code == 401

    invalid = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-token"})
    assert invalid.status_code == 401
    assert "not-a-token" not in invalid.text

    viewer = _user(UserRole.VIEWER)
    app.dependency_overrides[get_db] = _db_returning(viewer)
    expired = create_access_token(viewer.id, expires_delta=timedelta(seconds=-30))
    rejected = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert rejected.status_code == 401
    assert expired not in rejected.text


def test_token_role_claim_does_not_grant_admin(client, jwt_secret):
    viewer = _user(UserRole.VIEWER)
    app.dependency_overrides[get_db] = _db_returning(viewer)
    token = create_access_token(viewer.id, {"role": "admin"})
    response = client.post(
        "/api/projects",
        json={"name": "Should not be created"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Viewers have read-only access"
    assert "admin" not in response.text


def test_login_rate_limit_is_per_email_and_does_not_echo_the_password(client, tight_login_limit, jwt_secret, monkeypatch):
    secret = "RateLimitDummyPassword"
    app.dependency_overrides[get_db] = _db_returning(None)
    for _ in range(3):
        failed = client.post("/api/auth/login", json={"email": "one@example.com", "password": secret})
        assert failed.status_code == 401
        assert secret not in failed.text

    blocked = client.post("/api/auth/login", json={"email": "one@example.com", "password": secret})
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "Too many login attempts. Try again later."
    assert blocked.headers["retry-after"]
    assert secret not in blocked.text
    assert "set-cookie" not in {name.lower() for name in blocked.headers}

    other = client.post("/api/auth/login", json={"email": "two@example.com", "password": secret})
    assert other.status_code == 401

    monkeypatch.setattr("app.api.auth.verify_password", lambda plain, hashed: plain == secret)
    analyst = _user(UserRole.ANALYST, email="two@example.com")
    app.dependency_overrides[get_db] = _db_returning(analyst)
    allowed = client.post("/api/auth/login", json={"email": "two@example.com", "password": secret})
    assert allowed.status_code == 200
    assert allowed.json()["token_type"] == "bearer"
    assert "set-cookie" not in {name.lower() for name in allowed.headers}
    assert secret not in allowed.text


def test_login_limit_expires(tight_login_limit):
    import time

    login_rate_limiter.record_failure("old@example.com", "127.0.0.1")
    login_rate_limiter.record_failure("old@example.com", "127.0.0.1")
    login_rate_limiter.record_failure("old@example.com", "127.0.0.1")
    login_rate_limiter._email_failures["old@example.com"] = [time.monotonic() - 1000]
    login_rate_limiter.enforce("old@example.com", "127.0.0.1")


def test_connection_urls_are_redacted_and_alembic_ini_has_no_database_url():
    secret = "postgresql://bughawk_user:super-secret@db.internal:5432/bughawk"
    redacted = redact_connection_urls(f"connect failed: {secret}")
    assert "super-secret" not in redacted
    assert "db.internal" not in redacted
    assert "postgresql://redacted" in redacted

    ini = (Path(__file__).resolve().parents[1] / "alembic.ini").read_text(encoding="utf-8")
    assert "postgresql://" not in ini
    assert "localhost" not in ini
    assert "driver://" in ini
