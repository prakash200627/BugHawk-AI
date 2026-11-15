"""
BugHawk AI 2.0 — Projects API
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.session import get_db
from app.models import Project, SecurityFinding, Asset, Severity
from app.schemas import ProjectCreate, ProjectUpdate, ProjectResponse, PaginatedResponse
from app.config import settings

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
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new security assessment project."""
    project = Project(
        owner_id="demo-user-id",  # Auth milestone will replace this
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
):
    """List all projects."""
    projects = db.query(Project).filter(Project.is_active == True).offset(skip).limit(limit).all()
    return [_enrich_project(db, p) for p in projects]


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_db)):
    """Get a single project by ID."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return _enrich_project(db, project)


@router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: str, payload: ProjectUpdate, db: Session = Depends(get_db)):
    """Update project details."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.is_demo:
        raise HTTPException(status_code=403, detail="Cannot modify demo project")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(project, field, value)
    db.commit()
    db.refresh(project)
    return _enrich_project(db, project)
