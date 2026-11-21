"""
BugHawk AI 2.0 — Projects API
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.api.deps import get_current_user, require_owned_project
from app.database.session import get_db
from app.models import Project, SecurityFinding, Asset, Severity, User
from app.schemas import ProjectCreate, ProjectUpdate, ProjectResponse

router = APIRouter()


def _enrich_project(db: Session, project: Project) -> ProjectResponse:
    """Add computed counts to a project."""
    asset_count = db.query(func.count(Asset.id)).filter(Asset.project_id == project.id).scalar() or 0
    finding_count = db.query(func.count(SecurityFinding.id)).filter(SecurityFinding.project_id == project.id).scalar() or 0
    critical_count = db.query(func.count(SecurityFinding.id)).filter(
        SecurityFinding.project_id == project.id,
        SecurityFinding.effective_severity == Severity.CRITICAL
    ).scalar() or 0

    resp = ProjectResponse.model_validate(project)
    resp.asset_count = asset_count
    resp.finding_count = finding_count
    resp.critical_count = critical_count
    return resp


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a project owned by the authenticated user."""
    project = Project(
        owner_id=current_user.id,
        name=payload.name,
        description=payload.description,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return _enrich_project(db, project)


@router.get("", response_model=List[ProjectResponse])
def list_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List projects owned by the authenticated user."""
    projects = db.query(Project).filter(
        Project.owner_id == current_user.id,
        Project.is_active == True,
    ).offset(skip).limit(limit).all()
    return [_enrich_project(db, p) for p in projects]


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a project owned by the authenticated user."""
    project = require_owned_project(project_id, db, current_user)
    return _enrich_project(db, project)


@router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a project owned by the authenticated user."""
    project = require_owned_project(project_id, db, current_user)
    if project.is_demo:
        raise HTTPException(status_code=403, detail="Cannot modify demo project")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(project, field, value)
    db.commit()
    db.refresh(project)
    return _enrich_project(db, project)
