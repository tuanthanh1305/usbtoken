"""Phòng thủ tầng HTTP cho daemon loopback.

Mối đe doạ chính với một daemon nghe trên máy người dùng: TRANG WEB ĐỘC HẠI trong
trình duyệt gọi tới ``http://127.0.0.1`` (CSRF/DNS-rebinding) để dò token hoặc
lừa ký. Ba lớp chặn:

    1. :class:`HostHeaderMiddleware` — chỉ nhận Host = 127.0.0.1/localhost/::1
       (chống DNS rebinding: tên miền kẻ tấn công trỏ về 127.0.0.1 vẫn bị loại vì
       Host header mang tên miền đó).
    2. :class:`OriginCheckMiddleware` — nếu có Origin (request từ trình duyệt),
       phải nằm trong whitelist; nếu không -> 403.
    3. :class:`RateLimiter` — hãm brute-force PIN ở ``/login`` (khoá theo token).

Kết hợp với CORS whitelist ở tầng app. WebSocket không đi qua middleware HTTP nên
được kiểm thủ công bằng :func:`connection_allowed`.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
DEFAULT_ALLOWED_ORIGINS: tuple[str, ...] = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8787",
    "http://127.0.0.1:8787",
)


def host_only(value: str) -> str:
    """Tách phần host (bỏ cổng) từ Host header, xử lý cả IPv6 ``[::1]:port``."""
    v = value.strip()
    if not v:
        return ""
    if v.startswith("["):  # IPv6 có ngoặc: [::1] hoặc [::1]:8787
        end = v.find("]")
        return v[1:end] if end != -1 else v
    if v.count(":") == 1:  # host:port
        return v.rsplit(":", 1)[0]
    return v  # host thuần hoặc IPv6 không ngoặc (giữ nguyên)


def connection_allowed(
    headers: object, allowed_hosts: Iterable[str], allowed_origins: Iterable[str]
) -> bool:
    """Kiểm Host + Origin cho một kết nối (dùng cho WebSocket, không qua middleware).

    ``headers`` là bất kỳ mapping nào có ``.get`` (vd. ``starlette.Headers``).
    """
    get = headers.get  # type: ignore[attr-defined]
    host = host_only(get("host", "") or "").lower()
    if host not in set(allowed_hosts):
        return False
    origin = get("origin")
    return not (origin is not None and origin not in set(allowed_origins))


class HostHeaderMiddleware(BaseHTTPMiddleware):
    """Chỉ chấp nhận Host loopback (chống DNS rebinding)."""

    def __init__(self, app, allowed_hosts: Iterable[str] = DEFAULT_ALLOWED_HOSTS) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._allowed = {h.lower() for h in allowed_hosts}

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        host = host_only(request.headers.get("host", "")).lower()
        if host not in self._allowed:
            return JSONResponse(
                status_code=403,
                content={"detail": "Host header không hợp lệ — daemon chỉ phục vụ "
                                   "loopback (chống DNS rebinding)."},
            )
        return await call_next(request)


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Nếu request mang Origin (từ trình duyệt), Origin phải thuộc whitelist."""

    def __init__(self, app, allowed_origins: Iterable[str] = DEFAULT_ALLOWED_ORIGINS) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._allowed = set(allowed_origins)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        origin = request.headers.get("origin")
        if origin is not None and origin not in self._allowed:
            return JSONResponse(
                status_code=403,
                content={"detail": f"Origin không được phép: {origin}."},
            )
        return await call_next(request)


class RateLimiter:
    """Giới hạn tần suất theo khoá (cửa sổ trượt) — hãm brute-force PIN."""

    def __init__(
        self, *, max_attempts: int = 5, window: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_attempts
        self._window = window
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        """True nếu còn lượt; đồng thời GHI NHẬN một lượt nếu cho phép."""
        now = self._clock()
        with self._lock:
            self._evict_stale(now)  # dọn key hết hạn -> dict không phình vô hạn
            hits = [t for t in self._hits.get(key, []) if now - t < self._window]
            if len(hits) >= self._max:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True

    def _evict_stale(self, now: float) -> None:
        """Xoá các key mà mọi mốc thời gian đã ra khỏi cửa sổ (giữ dict gọn)."""
        stale = [k for k, ts in self._hits.items() if all(now - t >= self._window for t in ts)]
        for k in stale:
            del self._hits[k]

    def reset(self, key: str) -> None:
        """Xoá bộ đếm cho ``key`` (gọi sau khi đăng nhập THÀNH CÔNG)."""
        with self._lock:
            self._hits.pop(key, None)


__all__ = [
    "DEFAULT_ALLOWED_HOSTS",
    "DEFAULT_ALLOWED_ORIGINS",
    "host_only",
    "connection_allowed",
    "HostHeaderMiddleware",
    "OriginCheckMiddleware",
    "RateLimiter",
]
