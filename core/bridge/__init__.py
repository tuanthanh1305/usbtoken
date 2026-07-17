"""Cầu nối khác kiến trúc (arch bridge) — DÙNG CHUNG cho Windows 32-bit & macOS
Rosetta (và Linux qemu/box64).

Khi module PKCS#11 lệch arch với tiến trình host, ta spawn một helper CÙNG ARCH
với module và giao tiếp qua JSON-RPC (một JSON mỗi dòng, qua stdio). Cùng một bộ
code (``protocol`` + ``helper`` + ``client``) chạy trên cả ba OS; chỉ *lệnh khởi
chạy* helper là khác nhau (do adapter dựng).
"""

from __future__ import annotations

from .client import BridgeClient, BridgeError, BridgeTimeout
from .helper import serve

__all__ = ["BridgeClient", "BridgeError", "BridgeTimeout", "serve"]
