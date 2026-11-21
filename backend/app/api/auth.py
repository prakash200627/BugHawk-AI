"""Login for a pre-provisioned user. Public registration is not available."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.core.security import create_access_token, verify_password
from app.database.session import get_db
from app.models import User
from app.schemas import LoginRequest, TokenResponse, UserResponse

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate an existing user and return a JWT access token."""
    if not settings.jwt_secret_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured",
        )
    user = (
        db.query(User)
        .filter(func.lower(User.email) == str(payload.email).lower())
        .first()
    )
    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(user.id, {"role": user.role.value})
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.jwt_access_token_expire_minutes * 60,
        user_id=user.id,
        email=user.email,
        role=user.role.value,
    )


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user."""
    return current_user
