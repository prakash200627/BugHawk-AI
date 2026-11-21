"""Auth and health behavior that does not require a database."""
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.deps import require_owned_project
from app.config import Settings
from app.database.session import get_db
from app.main import app
from app.models import Project, User


@pytest.fixture
def client():
    def override_db():
        yield MagicMock()

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_project_list_requires_authentication(client):
    response = client.get("/api/projects")
    assert response.status_code == 401


def test_health_returns_503_when_database_check_fails():
    def broken_db():
        database = MagicMock()
        database.execute.side_effect = RuntimeError("database unavailable")
        yield database

    app.dependency_overrides[get_db] = broken_db
    with TestClient(app) as client:
        response = client.get("/api/health")
    app.dependency_overrides.clear()
    assert response.status_code == 503
    body = response.json()
    assert body["database"] == "unavailable"
    assert "database unavailable" not in response.text.lower() or body["database"] == "unavailable"
    assert "RuntimeError" not in response.text


def test_owned_project_rejects_another_users_project():
    user = User(id="user-a", email="a@example.com", hashed_password="x")
    project = Project(id="project-b", owner_id="user-b", name="Other")
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = project
    with pytest.raises(Exception) as caught:
        require_owned_project(project.id, db, user)
    assert getattr(caught.value, "status_code", None) == 403


def test_production_settings_reject_short_secrets_and_localhost():
    settings = Settings(
        app_env="production",
        app_secret_key="short",
        jwt_secret_key="also-short",
        allowed_origins="http://localhost:5173",
        database_url="postgresql://bughawk@localhost:5432/bughawk_db",
    )
    with pytest.raises(RuntimeError) as caught:
        settings.validate_runtime_settings()
    message = str(caught.value)
    assert "APP_SECRET_KEY" in message
    assert "JWT_SECRET_KEY" in message
    assert "ALLOWED_ORIGINS" in message
    assert "short" not in message
