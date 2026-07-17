"""Daemon vn-esign — FastAPI + uvicorn, BIND CHỈ 127.0.0.1.

Đây là điểm vào chính của "phần mềm ký số + phần mềm kiểm tra chữ ký số".

BẢO MẬT (bắt buộc — xem ``service/security.py``):
    * CHỈ bind loopback 127.0.0.1 (KHÔNG 0.0.0.0).
    * Kiểm Host header (chống DNS rebinding) + Origin whitelist + CORS.
    * Rate-limit ``/login``; PIN chỉ trong RAM, TTL ngắn, zeroize.
    * KHÔNG endpoint nào trả private key; PIN đi MỘT CHIỀU vào token.
    * Log xoay vòng, che PIN, không log DER đầy đủ.
    * ⭐ TUYỆT ĐỐI không tự tải/chạy installer bên thứ ba — chỉ phát hiện & hướng
      dẫn. Ra mạng chỉ cho đồng bộ kho tin cậy (rootca.gov.vn) và CRL/OCSP/TSA.

Chạy dev (3 OS): ``python -m service.app`` hoặc ``scripts/run_dev.*``.
Swagger: ``http://127.0.0.1:<port>/docs``.
"""

from __future__ import annotations

import contextlib

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core import __version__
from core.platform import get_adapter
from service.api.gateway import router as gateway_router
from service.api.routes import router as api_router
from service.deps import ServiceDeps, build_default_deps
from service.runtime import (
    configure_logging,
    find_free_port,
    remove_state_file,
    write_state_file,
)
from service.security import (
    HostHeaderMiddleware,
    OriginCheckMiddleware,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


def create_app(deps: ServiceDeps | None = None) -> FastAPI:
    """Factory: dựng app đã gắn middleware bảo mật + router (loopback-only).

    ``deps`` tiêm được để test; mặc định dựng bộ phụ thuộc thật.
    """
    resolved = deps or build_default_deps(get_adapter())

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        try:
            yield
        finally:
            resolved.close()  # zeroize mọi phiên PIN + đóng bridge helper

    app = FastAPI(
        title="vn-esign-suite service",
        version=__version__,
        summary="Daemon ký số & kiểm tra chữ ký số trên USB token (Việt Nam) — loopback only.",
        lifespan=lifespan,
    )
    app.state.deps = resolved

    # Thứ tự thêm ngược với thứ tự chạy: Host chạy TRƯỚC, rồi Origin, rồi CORS.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.add_middleware(OriginCheckMiddleware, allowed_origins=resolved.allowed_origins)
    app.add_middleware(HostHeaderMiddleware, allowed_hosts=resolved.allowed_hosts)

    app.include_router(gateway_router)   # /health /diagnose /tokens /login ... /events
    app.include_router(api_router)       # /api/* (tương thích ngược)
    return app


app = create_app()


def run(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Chạy daemon: bind loopback, tự dò cổng trống, ghi file trạng thái."""
    import uvicorn

    adapter = get_adapter()
    configure_logging(adapter.log_dir())
    actual_port = find_free_port(port, host)
    write_state_file(adapter.config_dir(), host=host, port=actual_port, version=__version__)
    try:
        uvicorn.run(app, host=host, port=actual_port, log_level="info")
    finally:
        remove_state_file(adapter.config_dir())


if __name__ == "__main__":
    run()


__all__ = ["create_app", "app", "run", "DEFAULT_HOST", "DEFAULT_PORT"]
