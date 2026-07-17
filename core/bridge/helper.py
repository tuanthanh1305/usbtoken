"""Phía HELPER (tiến trình con) — chạy được 3 chế độ từ CÙNG một file code.

    Windows : đóng gói .exe 32-bit (PyInstaller + Python 32-bit).
    macOS   : ``arch -x86_64 <python_x86_64> -m core.bridge.helper`` (Rosetta 2).
    Linux   : Python 32-bit (nếu có multilib i386) — chạy module .so 32-bit.

Helper nạp module PKCS#11 (đúng arch của nó) và thực thi thao tác qua
``core.pkcs11_ops`` — CÙNG mã với tuyến in-process, nên kết quả GIỐNG HỆT.

Mọi ngoại lệ được gói thành phản hồi lỗi (không làm sập helper). ⚠️ Thông báo
lỗi/log KHÔNG chứa PIN (ops không đưa pin ra ngoài).
"""

from __future__ import annotations

import importlib.util
import os
import platform
import sys
from typing import Any, TextIO

from .protocol import (
    M_CLOSE,
    M_ENUMERATE,
    M_GET_INFO,
    M_PING,
    M_READ_CERTS,
    M_SHUTDOWN,
    M_SIGN,
    M_VALIDATE,
    SHUTDOWN,
    decode,
    encode,
    make_error,
    make_result,
)


def _env_info() -> dict[str, Any]:
    return {
        "machine": platform.machine(),
        "bits": 64 if sys.maxsize > 2**32 else 32,
        "pykcs11": importlib.util.find_spec("PyKCS11") is not None,
        "pid": os.getpid(),
    }


def _dispatch(method: str, params: dict[str, Any]) -> Any:
    """Định tuyến một lời gọi RPC tới ``core.pkcs11_ops``."""
    if method == M_PING:
        return {"pong": True, **_env_info()}
    if method == M_SHUTDOWN:
        return SHUTDOWN
    if method == M_CLOSE:
        # Phiên module không giữ trạng thái lâu dài -> đóng là no-op an toàn.
        return {"closed": True}

    # Các thao tác nạp module -> import lười ops (CÙNG mã với in-process).
    from core import pkcs11_ops as ops

    # Trả THẲNG kết quả của ops (không bọc thêm) để shape GIỐNG HỆT tuyến
    # in-process — tầng router map sang model như nhau bất kể tuyến.
    mp = params.get("module_path", "")
    if method == M_VALIDATE:
        # Tầng 4 discovery: probe_module trả kèm token_slots (tối ưu p11-kit).
        from core.pkcs11_probe import probe_module

        return probe_module(mp)
    if method == M_GET_INFO:
        return ops.get_info(mp)
    if method == M_ENUMERATE:
        return ops.enumerate_tokens(mp)
    if method == M_READ_CERTS:
        return ops.read_certs(mp, int(params["slot_id"]), params.get("pin"))
    if method == M_SIGN:
        return ops.sign(
            mp,
            int(params["slot_id"]),
            str(params.get("key_id", "")),
            str(params["mechanism"]),
            str(params["data_b64"]),
            params.get("pin"),
        )
    raise ValueError(f"Phương thức RPC không hỗ trợ: {method!r}")


def serve(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Vòng lặp server: đọc request JSON (stdin) -> ghi response (stdout)."""
    inp = stdin or sys.stdin
    out = stdout or sys.stdout
    for line in inp:
        req = decode(line)
        if req is None:
            continue
        rid = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}
        try:
            result = _dispatch(method, params)
            if result is SHUTDOWN:
                out.write(encode(make_result(rid, {"bye": True})))
                out.flush()
                return
            out.write(encode(make_result(rid, result)))
        except Exception as exc:  # noqa: BLE001 - gói lỗi, KHÔNG kèm pin
            out.write(encode(make_error(rid, "helper_error", str(exc))))
        out.flush()


def main(argv: list[str] | None = None) -> int:
    _ = argv
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
