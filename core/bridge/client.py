"""Phía CLIENT của bridge — engine host dùng để gọi sang helper khác-arch.

Một luồng đọc nền đẩy phản hồi vào hàng đợi, cho phép áp timeout từng lời gọi
mà không treo vô hạn.
"""

from __future__ import annotations

import queue
import subprocess
import threading
import time
from typing import Any

from .protocol import (
    M_ENUMERATE,
    M_GET_INFO,
    M_PING,
    M_READ_CERTS,
    M_SHUTDOWN,
    M_SIGN,
    M_VALIDATE,
    decode,
    encode,
    make_request,
)


class BridgeError(RuntimeError):
    """Lỗi giao tiếp/thực thi phía bridge helper."""


class BridgeTimeout(BridgeError):
    """Helper không phản hồi trong thời gian cho phép."""


class BridgeClient:
    """Quản lý một tiến trình helper và giao tiếp JSON-RPC qua stdio."""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        name: str = "",
    ) -> None:
        self.command = command
        self.name = name or (command[0] if command else "bridge")
        self._id = 0
        self._closed = False
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue()

        try:
            self._proc = subprocess.Popen(  # noqa: S603 - lệnh do adapter dựng
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                cwd=cwd,
                env=env,
            )
        except (FileNotFoundError, OSError) as exc:
            raise BridgeError(
                f"Không khởi chạy được helper ({' '.join(command)}): {exc}"
            ) from exc

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            msg = decode(line)
            if msg is not None:
                self._queue.put(msg)
        self._queue.put(None)  # sentinel EOF

    def _rpc(self, method: str, params: dict[str, Any] | None, timeout: float) -> Any:
        if self._closed:
            raise BridgeError("BridgeClient đã đóng")
        self._id += 1
        rid = self._id
        assert self._proc.stdin is not None
        try:
            self._proc.stdin.write(encode(make_request(rid, method, params)))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise BridgeError(f"Không gửi được yêu cầu tới helper: {exc}") from exc

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeTimeout(f"Helper không phản hồi method {method!r}")
            try:
                msg = self._queue.get(timeout=remaining)
            except queue.Empty:
                raise BridgeTimeout(f"Helper không phản hồi method {method!r}") from None
            if msg is None:
                raise BridgeError("Helper đã đóng kết nối (EOF)")
            if msg.get("id") != rid:
                continue
            if "error" in msg:
                raise BridgeError(str(msg["error"].get("message", "lỗi helper")))
            return msg.get("result")

    def rpc(self, method: str, params: dict[str, Any] | None = None, timeout: float = 15.0) -> Any:
        """Gọi RPC tổng quát (dùng bởi BridgeManager)."""
        return self._rpc(method, params, timeout)

    def ping(self, timeout: float = 5.0) -> dict[str, Any]:
        """Kiểm tra helper sống + lấy arch/bits/pykcs11 của nó."""
        return self._rpc(M_PING, {}, timeout)

    def validate_module(self, module_path: str, timeout: float = 15.0) -> dict[str, Any]:
        """Xác thực module bằng C_GetInfo (trả dict như core.pkcs11_ops.get_info)."""
        result = self._rpc(M_VALIDATE, {"module_path": module_path}, timeout)
        return dict(result) if isinstance(result, dict) else {"ok": False, "error": "kết quả lạ"}

    def get_info(self, module_path: str, timeout: float = 15.0) -> dict[str, Any]:
        result = self._rpc(M_GET_INFO, {"module_path": module_path}, timeout)
        return dict(result) if isinstance(result, dict) else {"ok": False, "error": "kết quả lạ"}

    def enumerate_tokens(self, module_path: str, timeout: float = 15.0) -> list[dict[str, Any]]:
        result = self._rpc(M_ENUMERATE, {"module_path": module_path}, timeout)
        return list(result) if isinstance(result, list) else []

    def read_certs(
        self, module_path: str, slot_id: int, pin: str | None = None, timeout: float = 20.0
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"module_path": module_path, "slot_id": slot_id}
        if pin is not None:
            params["pin"] = pin  # ⚠️ nhạy cảm — không log ở bất kỳ đâu
        result = self._rpc(M_READ_CERTS, params, timeout)
        return list(result) if isinstance(result, list) else []

    def sign(
        self,
        module_path: str,
        slot_id: int,
        key_id: str,
        mechanism: str,
        data_b64: str,
        pin: str | None = None,
        timeout: float = 20.0,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "module_path": module_path, "slot_id": slot_id, "key_id": key_id,
            "mechanism": mechanism, "data_b64": data_b64,
        }
        if pin is not None:
            params["pin"] = pin  # ⚠️ nhạy cảm
        result = self._rpc(M_SIGN, params, timeout)
        return dict(result) if isinstance(result, dict) else {}

    def close(self) -> None:
        """Đóng helper: gửi shutdown, đóng ống, terminate rồi kill nếu cần."""
        if self._closed:
            return
        self._closed = True
        try:
            self._rpc(M_SHUTDOWN, {}, timeout=2.0)
        except BridgeError:
            pass
        for closer in (self._close_stdin, self._terminate, self._kill):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass

    def _close_stdin(self) -> None:
        if self._proc.stdin is not None:
            self._proc.stdin.close()

    def _terminate(self) -> None:
        self._proc.terminate()
        self._proc.wait(timeout=3)

    def _kill(self) -> None:
        if self._proc.poll() is None:
            self._proc.kill()

    def __enter__(self) -> BridgeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["BridgeClient", "BridgeError", "BridgeTimeout"]
