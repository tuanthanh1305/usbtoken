"""Daemon FastAPI localhost — cầu nối web UI với ``core``.

Không chứa tri thức OS (chỉ gọi ``core``, vốn đã cô lập OS). Chỉ bind 127.0.0.1.
"""

from __future__ import annotations

from .main import create_app

__all__ = ["create_app"]
