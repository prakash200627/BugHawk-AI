"""
BugHawk AI 2.0 — FastAPI Main Application
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.api import agents, assets, auth, findings, health, projects, remediation, reports, scans, scopes
from app.config import settings
from app.core.logging import configure_logging, get_logger, redact_connection_urls

# Import all models so Alembic sees them
import app.models  # noqa: F401

# Configure logging first
configure_logging()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    settings.validate_runtime_settings()
    logger.info(
        "BugHawk AI 2.0 starting",
        version=settings.app_version,
        environment=settings.app_env,
        demo_mode=settings.is_demo,
        llm_provider=settings.llm_provider,
    )
    yield
    logger.info("BugHawk AI 2.0 shutting down")


app = FastAPI(
    title="BugHawk AI 2.0 API",
    description=(
        "AI-powered cybersecurity intelligence platform. "
        "Transforms authorized security assessment results into actionable security intelligence."
    ),
    version=settings.app_version,
    docs_url=None if settings.is_production else "/api/docs",
    redoc_url=None if settings.is_production else "/api/redoc",
    openapi_url=None if settings.is_production else "/api/openapi.json",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

def _public_validation_errors(exc: RequestValidationError) -> list:
    """Field messages only. Drop values that may be passwords or tokens."""
    public = []
    for error in exc.errors():
        public.append({
            "type": error.get("type"),
            "loc": error.get("loc"),
            "msg": error.get("msg"),
        })
    return public


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation error",
            "detail": _public_validation_errors(exc),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        raise exc
    logger.error(
        "Unhandled exception",
        path=request.url.path,
        error_type=type(exc).__name__,
        detail=redact_connection_urls(str(exc)),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error", "detail": "An unexpected error occurred."},
    )

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(health.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(projects.router, prefix="/api/projects", tags=["Projects"])
app.include_router(scopes.router, prefix="/api/scopes", tags=["Scopes"])
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(agents.router, prefix="/api/agents", tags=["AI Agents"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(remediation.router, prefix="/api/remediation", tags=["Remediation"])


@app.get("/", include_in_schema=False)
def root():
    return {
        "platform": "BugHawk AI 2.0",
        "version": settings.app_version,
        "docs": None if settings.is_production else "/api/docs",
        "health": "/api/health",
    }
