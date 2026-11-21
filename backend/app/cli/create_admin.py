"""Create the first administrator from an interactive shell.

Prerequisites:
- The initial migration has already been applied with ``alembic upgrade head``.
- ``DATABASE_URL`` is present in the environment. This command does not print it.
- The shell is interactive. A password argument is not accepted.

From the backend directory, or from the Render service shell:

    python -m app.cli.create_admin

The command refuses to replace an existing account. It is not called during startup
and it does not add a public registration or bootstrap endpoint.
"""
import argparse
import getpass
import sys

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

from app.core.security import hash_password
from app.database.session import SessionLocal
from app.models import User, UserRole

_email_adapter = TypeAdapter(EmailStr)
_MIN_PASSWORD_LENGTH = 10
_MAX_PASSWORD_BYTES = 72


def _prompt_email(supplied: str | None) -> str:
    raw = supplied if supplied is not None else input("Email: ")
    try:
        return str(_email_adapter.validate_python(raw.strip()))
    except ValidationError:
        raise ValueError("Enter a valid email address.")


def _prompt_password() -> str:
    if not sys.stdin.isatty():
        raise ValueError("Refusing to read a password from a non-interactive shell.")
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise ValueError("Passwords do not match.")
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters.")
    if len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        raise ValueError("Password is too long for the password hasher.")
    return password


def create_initial_admin(email: str, password: str) -> str:
    """Insert one administrator. Return the new user id."""
    db = SessionLocal()
    try:
        existing = (
            db.query(User)
            .filter(func.lower(User.email) == email.lower())
            .first()
        )
        if existing is not None:
            raise ValueError("An account with that email already exists. It was not changed.")
        user = User(
            email=email,
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
            is_demo=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id
    except SQLAlchemyError:
        db.rollback()
        raise
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create the initial BugHawk administrator. Password is prompted, not accepted as an argument."
    )
    parser.add_argument("--email", help="Administrator email. Prompted when omitted.")
    args = parser.parse_args(argv)
    try:
        email = _prompt_email(args.email)
        password = _prompt_password()
        user_id = create_initial_admin(email, password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except SQLAlchemyError:
        print(
            "Could not create the administrator. Apply the database migration first.",
            file=sys.stderr,
        )
        return 1
    print(f"Created administrator {user_id} for {email}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
