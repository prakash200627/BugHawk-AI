"""Authentication and project-ownership dependencies."""
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database.session import get_db
from app.models import Project, SecurityFinding, User, UserRole

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Require a valid bearer token for an active user."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or not credentials.credentials:
        raise unauthorized
    payload = decode_access_token(credentials.credentials)
    if payload.get("type") != "access":
        raise unauthorized
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_writer(current_user: User = Depends(get_current_user)) -> User:
    """Allow analyst and admin writes. Viewers and unknown roles cannot change records.

    The role is read from the user row. A role claim inside the token is ignored.
    Admin does not bypass project ownership checks.
    """
    if current_user.role not in (UserRole.ADMIN, UserRole.ANALYST):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Viewers have read-only access",
        )
    return current_user


def require_owned_project(project_id: str, db: Session, user: User) -> Project:
    """Return the project when it belongs to the authenticated user."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this project",
        )
    return project


def require_owned_finding(finding_id: str, db: Session, user: User) -> SecurityFinding:
    """Return the finding when its project belongs to the authenticated user."""
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    require_owned_project(finding.project_id, db, user)
    return finding
