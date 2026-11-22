"""
BugHawk AI 2.0 — Scopes API
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_owned_project, require_writer
from app.database.session import get_db
from app.models import AuthorizedScope, User
from app.schemas import ScopeCreate, ScopeResponse, ScopeValidateRequest, ScopeValidateResponse
from app.core.scope_guard import ScopeGuardian

router = APIRouter()


def _get_project_scopes(project_id: str, db: Session) -> List[str]:
    scopes = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == project_id,
        AuthorizedScope.is_active.is_(True)
    ).all()
    return [s.scope_value for s in scopes]


@router.post("", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
def add_scope(
    project_id: str,
    payload: ScopeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_writer),
):
    """Add an authorized scope to a project owned by the authenticated user."""
    require_owned_project(project_id, db, current_user)

    # Determine if wildcard
    is_wildcard = payload.scope_value.startswith("*.")

    scope = AuthorizedScope(
        project_id=project_id,
        scope_value=payload.scope_value,
        is_wildcard=is_wildcard,
        notes=payload.notes,
        authorized_by=payload.authorized_by,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)
    return scope


@router.get("", response_model=List[ScopeResponse])
def list_scopes(
    project_id: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List authorized scopes for a project owned by the authenticated user."""
    require_owned_project(project_id, db, current_user)
    return db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == project_id,
        AuthorizedScope.is_active.is_(True),
    ).all()


@router.post("/validate", response_model=ScopeValidateResponse)
def validate_target(
    payload: ScopeValidateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Validate whether a target is within authorized scope.
    Uses the deterministic Scope Guardian — no LLM involved.
    """
    require_owned_project(payload.project_id, db, current_user)
    scope_strings = _get_project_scopes(payload.project_id, db)
    guardian = ScopeGuardian.from_scope_values(scope_strings)
    result = guardian.validate(payload.target)

    return ScopeValidateResponse(
        target=payload.target,
        normalized_host=result.normalized_host,
        decision=result.decision.value,
        matched_rule=result.matched_rule,
        reason=result.reason,
        is_allowed=result.is_allowed,
    )


@router.delete("/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(
    scope_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_writer),
):
    """Deactivate a scope rule on a project owned by the authenticated user."""
    scope = db.query(AuthorizedScope).filter(AuthorizedScope.id == scope_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    require_owned_project(scope.project_id, db, current_user)
    scope.is_active = False
    db.commit()
