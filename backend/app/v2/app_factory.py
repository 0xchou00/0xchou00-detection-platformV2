from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.v2.api import router
from app.v2.config import settings
from app.v2.db import initialize_database


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.service_name,
        version="2.0.0",
        description="Real-time detection platform with Redis Streams + PostgreSQL + WebSocket SOC feed.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )
    app.include_router(router)

    @app.on_event("startup")
    async def startup() -> None:
        await initialize_database()

    return app

