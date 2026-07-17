"""Kết nối Cổng eSign (Cổng kết nối dịch vụ chứng thực chữ ký số công cộng).

Căn cứ Điều 44 NĐ 23/2025 và Điều 7/8 TT 15/2025: phần mềm ký số phải kết nối
được Cổng eSign theo Hướng dẫn kỹ thuật của Bộ KH&CN.

⛔ CHƯA HIỆN THỰC — CHỜ HƯỚNG DẪN KỸ THUẬT. Chỉ có KHUNG TRỪU TƯỢNG + hạ tầng
truyền tải gia cố; :func:`make_gateway` trả :class:`NullEsignGateway` (từ chối)
cho tới khi ``data/compliance/esign_gateway_spec.yaml`` được điền.
"""

from __future__ import annotations

from .gateway import (
    EsignGateway,
    GatewayResponse,
    HealthStatus,
    HttpEsignGateway,
    HttpResponse,
    HttpxTransport,
    NullEsignGateway,
    Transport,
    TransportError,
    make_gateway,
)
from .spec import EsignGatewaySpec, OperationSpec, load_spec

__all__ = [
    "EsignGateway",
    "NullEsignGateway",
    "HttpEsignGateway",
    "GatewayResponse",
    "HealthStatus",
    "Transport",
    "HttpxTransport",
    "HttpResponse",
    "TransportError",
    "make_gateway",
    "EsignGatewaySpec",
    "OperationSpec",
    "load_spec",
]
