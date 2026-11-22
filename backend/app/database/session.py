"""
BugHawk AI 2.0 — Database Session Management
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
from app.config import settings

# Synchronous engine (used by Alembic and sync endpoints)
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=2,
    max_overflow=2,
    echo=settings.app_debug,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: provides a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
