"""Cầu nối khác kiến trúc (arch bridge) — DÙNG CHUNG cho Windows & macOS (và Linux).

Middleware CA Việt Nam rất hay lệch kiến trúc:
    * Windows: nhiều bản chỉ 32-bit (SysWOW64) — Python 64-bit LoadLibrary lỗi 193.
    * macOS: hầu như không hãng nào build arm64 ("have 'x86_64', need 'arm64e'").
    * Linux: fptca_v4.so nghi ELF32 ở /usr/lib.

Khi lệch arch, ta spawn helper CÙNG ARCH với module và giao tiếp JSON-RPC. Cùng
một bộ code (``protocol`` + ``helper`` + ``client`` + ``manager``) chạy trên cả
ba OS; tầng ``router`` cho phép gọi THỐNG NHẤT (in-process hoặc bridge trả model
GIỐNG HỆT).
"""

from __future__ import annotations

from .client import BridgeClient, BridgeError, BridgeTimeout
from .helper import serve
from .manager import BridgeManager
from .router import ModuleSession

__all__ = [
    "BridgeClient",
    "BridgeError",
    "BridgeTimeout",
    "BridgeManager",
    "ModuleSession",
    "serve",
]
