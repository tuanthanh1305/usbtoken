"""Khởi tạo ứng dụng FastAPI cho daemon vn-esign.

Chạy dev:  python -m service.main   (bind 127.0.0.1:8787)
Hoặc:      uvicorn service.main:app --host 127.0.0.1 --port 8787

Vì lý do bảo mật, daemon CHỈ bind loopback (127.0.0.1).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core import __version__
from service.api.routes import router

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8787",
    "http://127.0.0.1:8787",
]


def create_app() -> FastAPI:
    """Factory tạo app FastAPI đã gắn router và CORS (giới hạn localhost)."""
    app = FastAPI(
        title="vn-esign-suite service",
        version=__version__,
        summary="Daemon ký số & kiểm tra chữ ký số trên USB token (Việt Nam).",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


app = create_app()


def main() -> None:
    """Điểm vào CLI: chạy uvicorn bind loopback."""
    import uvicorn

    uvicorn.run("service.main:app", host=DEFAULT_HOST, port=DEFAULT_PORT, log_level="info")


if __name__ == "__main__":
    main()
