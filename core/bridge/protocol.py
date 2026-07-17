"""Giao thức JSON-RPC DÙNG CHUNG cho helper & host (Windows + macOS + Linux).

Định dạng: mỗi thông điệp là MỘT dòng JSON, kết bằng "\\n". Dữ liệu nhị phân
(chứng thư DER, dữ liệu ký, chữ ký) truyền dưới dạng base64.

Các phương thức RPC (dùng chung cho mọi tuyến):
    ping                                       — kiểm tra helper + arch/bits
    get_info(module_path)                      — C_GetInfo
    enumerate_tokens(module_path)              — liệt kê token
    read_certs(module_path, slot_id, pin?)     — đọc chứng thư
    sign(module_path, slot_id, key_id, mechanism, data_b64, pin?)
    close(module_path?)                        — đóng phiên module
    shutdown                                   — dừng helper

⚠️ AN TOÀN PIN: trường ``pin`` là NHẠY CẢM — :data:`SENSITIVE_FIELDS`. Dùng
:func:`redact_params_for_log` trước khi ghi log/thông báo BẤT KỲ. Không nơi nào
được log params thô của ``read_certs`` / ``sign``.
"""

from __future__ import annotations

import base64
import json
from typing import Any

SHUTDOWN = object()

# Tên phương thức (hằng để tránh gõ nhầm chuỗi).
M_PING = "ping"
M_GET_INFO = "get_info"
M_ENUMERATE = "enumerate_tokens"
M_READ_CERTS = "read_certs"
M_READ_CERTIFICATES = "read_certificates"  # bản đầy đủ (kèm key matching)
M_SIGN = "sign"
M_CLOSE = "close"
M_SHUTDOWN = "shutdown"
M_VALIDATE = "validate"  # tương thích Tầng 4 discovery (C_GetInfo)

# Trường nhạy cảm — PHẢI loại khỏi mọi log.
SENSITIVE_FIELDS = frozenset({"pin"})


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str) -> bytes:
    return base64.b64decode(text)


def encode(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False) + "\n"


def decode(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def make_request(rid: int, method: str, params: dict[str, Any] | None) -> dict[str, Any]:
    return {"id": rid, "method": method, "params": params or {}}


def make_result(rid: Any, result: Any) -> dict[str, Any]:
    return {"id": rid, "result": result}


def make_error(rid: Any, code: str, message: str) -> dict[str, Any]:
    return {"id": rid, "error": {"code": code, "message": message}}


def redact_params_for_log(params: dict[str, Any] | None) -> dict[str, Any]:
    """Trả bản sao params đã CHE trường nhạy cảm (pin) để an toàn khi log."""
    if not params:
        return {}
    return {
        k: ("***" if k in SENSITIVE_FIELDS else v)
        for k, v in params.items()
    }


__all__ = [
    "SHUTDOWN",
    "SENSITIVE_FIELDS",
    "M_PING", "M_GET_INFO", "M_ENUMERATE", "M_READ_CERTS", "M_READ_CERTIFICATES",
    "M_SIGN", "M_CLOSE", "M_SHUTDOWN", "M_VALIDATE",
    "b64encode", "b64decode",
    "encode", "decode", "make_request", "make_result", "make_error",
    "redact_params_for_log",
]
