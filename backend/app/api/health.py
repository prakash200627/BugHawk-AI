"""
BugHawk AI 2.0 — Health Check Endpoint
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database.session import get_db
from app.config import settings
from app.core.logging import get_logger
from app.schemas import HealthResponse

logger = get_logger("health")

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    """
    Platform health check.
    Returns application version, environment, database connectivity, and demo mode status.
    """
    # Check database connectivity
    body = {
        "version": settings.app_version,
        "environment": settings.app_env,
        "demo_mode": settings.is_demo,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        logger.exception("database health check failed")
        return JSONResponse(
            status_code=503,
            content={**body, "status": "unavailable", "database": "unavailable"},
        )

    return HealthResponse(
        status="ok",
        database="connected",
        **body,
    )
