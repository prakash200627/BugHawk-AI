"""
BugHawk AI 2.0 — Health Check Endpoint
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database.session import get_db
from app.config import settings
from app.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    """
    Platform health check.
    Returns application version, environment, database connectivity, and demo mode status.
    """
    # Check database connectivity
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return HealthResponse(
        status="ok",
        version=settings.app_version,
        environment=settings.app_env,
        database=db_status,
        demo_mode=settings.is_demo,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
