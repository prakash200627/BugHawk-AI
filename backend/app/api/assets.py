"""
BugHawk AI 2.0 — Assets API
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.api.deps import get_current_user, require_owned_project
from app.database.session import get_db
from app.models import Asset, AuthorizedScope, User
from app.schemas import AssetCreate, AssetResponse, AssetImportRequest, MessageResponse
from app.core.scope_guard import ScopeGuardian

router = APIRouter()


def _validate_asset_scope(hostname: str, project_id: str, db: Session) -> bool:
    """Check asset hostname against project scopes."""
    scopes = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == project_id,
        AuthorizedScope.is_active == True
    ).all()
    scope_strings = [s.scope_value for s in scopes]
    guardian = ScopeGuardian(scope_strings)
    return guardian.validate(hostname).is_allowed


@router.get("", response_model=List[AssetResponse])
def list_assets(
    project_id: str = Query(...),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List assets for a project owned by the authenticated user."""
    require_owned_project(project_id, db, current_user)
    q = db.query(Asset).filter(Asset.project_id == project_id)
    if status:
        q = q.filter(Asset.status == status)
    if search:
        q = q.filter(Asset.hostname.ilike(f"%{search}%"))
    return q.offset(skip).limit(limit).all()


@router.post("/import", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def import_assets(
    payload: AssetImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Import a batch of assets for a project.
    Each asset is validated against authorized scopes before import.
    Out-of-scope assets are stored with is_in_scope=False and NOT processed further.
    """
    require_owned_project(payload.project_id, db, current_user)
    imported = 0
    skipped = 0
    out_of_scope = 0

    # Load project scopes once
    from app.models import AuthorizedScope
    scopes = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == payload.project_id,
        AuthorizedScope.is_active == True,
    ).all()
    scope_strings = [s.scope_value for s in scopes]
    guardian = ScopeGuardian(scope_strings)

    for item in payload.assets:
        # Check for existing asset
        existing = db.query(Asset).filter(
            Asset.project_id == payload.project_id,
            Asset.hostname == item.hostname.lower().strip(),
        ).first()

        if existing:
            skipped += 1
            continue

        # Scope validation
        scope_result = guardian.validate(item.hostname)
        is_in_scope = scope_result.is_allowed

        if not is_in_scope:
            out_of_scope += 1

        asset = Asset(
            project_id=payload.project_id,
            hostname=item.hostname.lower().strip(),
            asset_type=item.asset_type or "subdomain",
            ip_addresses=item.ip_addresses,
            technologies=item.technologies,
            http_status_code=item.http_status_code,
            title=item.title,
            discovery_source=item.discovery_source or "import",
            is_in_scope=is_in_scope,
        )
        db.add(asset)
        imported += 1

    db.commit()
    return MessageResponse(
        message=f"Import complete. Imported: {imported}, Skipped (duplicate): {skipped}, Out-of-scope: {out_of_scope}",
        success=True,
    )
