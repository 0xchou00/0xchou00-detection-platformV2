from __future__ import annotations

from fastapi import APIRouter

from app.security.rbac import ViewerAccess
from app.services.integrity import IntegrityService


router = APIRouter(prefix="/integrity", tags=["integrity"])


@router.get("/verify", dependencies=[ViewerAccess])
def verify_integrity():
    return IntegrityService().verify()
