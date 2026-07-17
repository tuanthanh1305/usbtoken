"""Kết nối Cổng eSign (Cổng kết nối dịch vụ chứng thực chữ ký số công cộng).

Điều 5/6 TT 15/2025 yêu cầu phần mềm kết nối Cổng eSign để: cập nhật danh sách
chứng thư tin cậy (NEAC + CA công cộng + danh sách nước ngoài), gắn dấu thời
gian (TSA) khi luật yêu cầu, và tra cứu trạng thái.
"""

from __future__ import annotations

from .gateway import ESignGatewayClient, ESignGatewayConfig

__all__ = ["ESignGatewayClient", "ESignGatewayConfig"]
