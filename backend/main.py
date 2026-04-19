import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.storage.sqlite import SQLiteStorage


def _allowed_origins() -> list[str]:
    raw = os.getenv(
        "SIEM_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app() -> FastAPI:
    app = FastAPI(
        title="0xchou00 — Lightweight Security Detection Tool",
        version="0.4.0-beta",
        description="Local logs, normalized events, bounded detections, and correlated alerts.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def startup() -> None:
        SQLiteStorage().initialize()

    app.include_router(router)
    return app


app = create_app()
