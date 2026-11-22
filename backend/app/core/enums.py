"""Map API strings onto the enum members stored by the published migration.

The migration persists member names (for example SUBDOMAIN and PENDING).
Clients may send those names or the lowercase values (subdomain, pending).
"""
from enum import Enum
from typing import Type, TypeVar

from fastapi import HTTPException

Member = TypeVar("Member", bound=Enum)


def require_enum(enum_cls: Type[Member], raw: str) -> Member:
    """Return the enum member for an API value, or raise HTTP 400."""
    text = (raw or "").strip()
    lowered = text.lower()
    for member in enum_cls:
        value = getattr(member, "value", "")
        if lowered == str(value).lower() or lowered == member.name.lower():
            return member
    allowed = ", ".join(str(member.value) for member in enum_cls)
    raise HTTPException(
        status_code=400,
        detail=f"Invalid value. Expected one of: {allowed}",
    )
