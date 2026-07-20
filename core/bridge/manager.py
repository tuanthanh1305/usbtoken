"""Phía HOST — quản lý vòng đời helper bridge.

Trách nhiệm:
    * Spawn LƯỜI (chỉ khi lần đầu cần), qua ``adapter.spawn_bridge_helper``
      (lệnh đúng arch: Win python/exe 32-bit · mac ``arch -x86_64`` · Linux
      Python 32-bit/qemu).
    * TỰ RESTART khi helper chết (module rác làm sập subprocess).
    * TIMEOUT mỗi RPC (không treo daemon).
    * KILL SẠCH mọi helper khi daemon dừng (:meth:`close`).
    * GIỚI HẠN helper đồng thời + tuần tự hoá RPC (một kênh stdio không cho phép
      xen kẽ) qua khoá.
    * Không spawn được -> :class:`~core.errors.BridgeUnavailableError` kèm
      remediation ĐÚNG OS (Win "helper 32-bit" · mac "install-rosetta" · Linux
      "dpkg --add-architecture i386 ...").
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from core.errors import BridgeUnavailableError
from core.models import ErrorCode, ErrorInfo
from core.platform import PlatformAdapter, get_adapter

from .client import BridgeClient, BridgeError

DEFAULT_TIMEOUT = 20.0


class BridgeManager:
    """Quản lý một pool helper (mặc định 1 helper cho arch đích của OS này)."""

    def __init__(
        self,
        adapter: PlatformAdapter | None = None,
        *,
        max_helpers: int = 4,
        default_timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.adapter = adapter or get_adapter()
        self.max_helpers = max_helpers
        self.default_timeout = default_timeout
        self._client: BridgeClient | None = None
        self._lock = threading.RLock()  # tuần tự hoá RPC trên kênh stdio
        self._closed = False

    # -- Gọi RPC (tự spawn + tự restart) -------------------------------- #
    def call(
        self,
        module_path: str,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        """Gửi một RPC tới helper; spawn nếu chưa có, restart nếu helper chết."""
        to = timeout or self.default_timeout
        with self._lock:
            if self._closed:
                raise BridgeUnavailableError("BridgeManager đã đóng.")
            client = self._ensure_client(module_path)
            try:
                return client.rpc(method, params, to)
            except BridgeError:
                # Helper có thể đã chết vì module rác -> restart MỘT lần & thử lại.
                self._drop_client()
                client = self._ensure_client(module_path)
                return client.rpc(method, params, to)

    def _ensure_client(self, module_path: str) -> BridgeClient:
        if self._client is None:
            try:
                self._client = self.adapter.spawn_bridge_helper(Path(module_path))
            except BridgeUnavailableError:
                raise  # đã kèm remediation ở .detail
            except Exception as exc:  # noqa: BLE001
                raise BridgeUnavailableError(
                    "Không spawn được bridge helper.",
                    detail=self.adapter.arch_bridge_hint(),
                ) from exc
        return self._client

    def _drop_client(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    # -- Tiện ích ------------------------------------------------------- #
    def error_info(self, exc: Exception) -> ErrorInfo:
        """Dựng :class:`ErrorInfo` (tiếng Việt + remediation đúng OS) từ lỗi bridge."""
        detail = ""
        if isinstance(exc, BridgeUnavailableError):
            detail = exc.detail or self.adapter.arch_bridge_hint()
        else:
            detail = self.adapter.arch_bridge_hint()
        return ErrorInfo(
            code=ErrorCode.BRIDGE_UNAVAILABLE,
            message_vi="Module lệch kiến trúc với daemon; cần helper cầu nối để nạp.",
            remediation=detail,
            platform=self.adapter.name(),  # type: ignore[arg-type]
        )

    def active_helpers(self) -> int:
        return 1 if self._client is not None else 0

    def close(self) -> None:
        """Kill sạch mọi helper (gọi khi daemon dừng)."""
        with self._lock:
            self._closed = True
            self._drop_client()

    def __enter__(self) -> BridgeManager:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["BridgeManager"]
