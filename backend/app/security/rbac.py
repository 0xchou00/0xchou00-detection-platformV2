from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status

from app.storage.sqlite import APIKeyRecord, SQLiteStorage


ROLE_RANKS = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
}


@dataclass(slots=True)
class AuthContext:
    key_id: str
    name: str
    role: str


def authorize(required_role: str = "viewer"):
    def dependency(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> AuthContext:
        if not x_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-API-Key header.",
            )

        storage = SQLiteStorage()
        record = storage.validate_api_key(x_api_key)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive API key.",
            )

        if ROLE_RANKS[record.role] < ROLE_RANKS[required_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{required_role}' or higher.",
            )

        return AuthContext(key_id=record.key_id, name=record.name, role=record.role)

    return dependency


ViewerAccess = Depends(authorize("viewer"))
AnalystAccess = Depends(authorize("analyst"))
AdminAccess = Depends(authorize("admin"))
