from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import select

from app.v2.config import settings
from app.v2.db import APIKeyRecord, AgentCredentialRecord, session_maker


ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass(slots=True)
class AuthContext:
    key_id: str
    role: str
    name: str


@dataclass(slots=True)
class AgentAuthContext:
    credential_id: str
    agent_id: str
    name: str
    key_version: int
    rate_limit_per_window: int


def authorize(required_role: str = "viewer"):
    async def dependency(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> AuthContext:
        context = await validate_api_key_role(x_api_key, required_role)
        if context is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")
        return context

    return dependency


ViewerAccess = Depends(authorize("viewer"))
AnalystAccess = Depends(authorize("analyst"))
AdminAccess = Depends(authorize("admin"))


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


async def validate_agent_ingest_request(
    *,
    request: Request,
    body: bytes,
    state_client: Redis,
) -> AgentAuthContext:
    agent_id = request.headers.get("X-Agent-Id")
    agent_key = request.headers.get("X-Agent-Key")
    signature = request.headers.get("X-Signature")
    nonce = request.headers.get("X-Nonce")
    timestamp_header = request.headers.get("X-Timestamp")
    version_header = request.headers.get("X-Key-Version")

    if settings.require_tls_for_ingest and _request_scheme(request) != "https":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="TLS is required for ingest.")

    if not all([agent_id, agent_key, signature, nonce, timestamp_header]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing ingest authentication headers.")

    try:
        timestamp = int(timestamp_header)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid timestamp header.") from exc

    now = int(datetime.now(timezone.utc).timestamp())
    if abs(now - timestamp) > settings.allowed_clock_skew_seconds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ingest request timestamp is outside the accepted replay window.")

    async with session_maker() as session:
        credential = await session.scalar(
            select(AgentCredentialRecord).where(
                AgentCredentialRecord.agent_id == agent_id,
                AgentCredentialRecord.api_key == agent_key,
                AgentCredentialRecord.is_active.is_(True),
            )
        )
        if credential is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or inactive agent credential.")

        if version_header:
            try:
                supplied_version = int(version_header)
            except ValueError as exc:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid key version header.") from exc
            if supplied_version != credential.key_version:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent key version mismatch.")

        _verify_signature(
            secret=credential.signing_secret,
            body=body,
            agent_id=agent_id,
            nonce=nonce,
            timestamp=timestamp,
            key_version=credential.key_version,
            signature=signature,
        )

        replay_key = f"siem:auth:nonce:{agent_id}:{nonce}"
        if not await state_client.set(replay_key, "1", ex=settings.replay_window_seconds, nx=True):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected for ingest nonce.")

        rate_key = f"siem:ratelimit:{agent_id}:{now // max(settings.rate_limit_window_seconds, 1)}"
        count = int(await state_client.incr(rate_key))
        await state_client.expire(rate_key, settings.rate_limit_window_seconds)
        limit = credential.rate_limit_per_window or settings.default_agent_rate_limit
        if count > limit:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Agent rate limit exceeded.")

        credential.last_used_at = datetime.now(timezone.utc)
        await session.commit()
        return AgentAuthContext(
            credential_id=credential.id,
            agent_id=credential.agent_id,
            name=credential.name,
            key_version=credential.key_version,
            rate_limit_per_window=limit,
        )


def build_hmac_signature(
    *,
    secret: str,
    body: bytes,
    agent_id: str,
    nonce: str,
    timestamp: int,
    key_version: int,
) -> str:
    material = _signature_material(
        body=body,
        agent_id=agent_id,
        nonce=nonce,
        timestamp=timestamp,
        key_version=key_version,
    )
    return hmac.new(secret.encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_agent_secret() -> str:
    return secrets.token_urlsafe(32)


def generate_agent_api_key() -> str:
    return secrets.token_urlsafe(24)


def _verify_signature(
    *,
    secret: str,
    body: bytes,
    agent_id: str,
    nonce: str,
    timestamp: int,
    key_version: int,
    signature: str,
) -> None:
    expected = build_hmac_signature(
        secret=secret,
        body=body,
        agent_id=agent_id,
        nonce=nonce,
        timestamp=timestamp,
        key_version=key_version,
    )
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ingest request signature.")


def _signature_material(
    *,
    body: bytes,
    agent_id: str,
    nonce: str,
    timestamp: int,
    key_version: int,
) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([agent_id, str(timestamp), nonce, str(key_version), body_hash])


def _request_scheme(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-Proto")
    if forwarded:
        return forwarded.split(",")[0].strip().lower()
    return request.url.scheme.lower()
