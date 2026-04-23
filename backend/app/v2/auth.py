from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select

from app.v2.db import APIKeyRecord, session_maker


ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass(slots=True)
class AuthContext:
    key_id: str
    role: str
    name: str


def authorize(required_role: str = "viewer"):
    async def dependency(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> AuthContext:
        context = await validate_api_key_role(x_api_key, required_role)
        if context is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")
        return context

    return dependency


ViewerAccess = Depends(authorize("viewer"))
AnalystAccess = Depends(authorize("analyst"))


async def validate_api_key_role(api_key: str | None, required_role: str = "viewer") -> AuthContext | None:
    if not api_key:
        return None
    async with session_maker() as session:
        record = await session.scalar(
            select(APIKeyRecord).where(
                APIKeyRecord.api_key == api_key,
                APIKeyRecord.is_active.is_(True),
            )
        )
    if not record:
        return None
    if ROLE_RANK[record.role] < ROLE_RANK[required_role]:
        return None
    return AuthContext(key_id=record.id, role=record.role, name=record.name)
