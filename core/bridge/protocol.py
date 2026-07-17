"""Khung giao thức JSON-RPC dùng chung cho helper & client.

Định dạng: MỖI thông điệp là một đối tượng JSON nằm trên MỘT dòng, kết bằng
"\\n". Request: ``{"id", "method", "params"}``. Response: ``{"id", "result"}``
hoặc ``{"id", "error": {"code", "message"}}``.

Giữ tối thiểu phụ thuộc (chỉ thư viện chuẩn) để helper chạy được trong tiến
trình khác-arch (32-bit / Rosetta / qemu) mà không kéo theo pydantic/FastAPI.
"""

from __future__ import annotations

import json
from typing import Any

# Đánh dấu nội bộ để helper biết cần thoát vòng lặp sau khi trả lời.
SHUTDOWN = object()


def encode(obj: dict[str, Any]) -> str:
    """Serialize một thông điệp thành một dòng JSON (kèm "\\n")."""
    return json.dumps(obj, ensure_ascii=False) + "\n"


def decode(line: str) -> dict[str, Any] | None:
    """Parse một dòng thành dict; trả None nếu dòng rỗng/không hợp lệ."""
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


__all__ = [
    "SHUTDOWN",
    "encode",
    "decode",
    "make_request",
    "make_result",
    "make_error",
]
