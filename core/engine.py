"""Facade nghiệp vụ OS-agnostic — điểm vào thống nhất cho service/tools.

KHÔNG rẽ nhánh theo hệ điều hành: mọi khác biệt OS đi qua ``get_adapter()``.
Ở giai đoạn này cung cấp: thông tin nền tảng, phát hiện module (Track A/B),
trạng thái kho neo tin cậy. Logic đọc token thuộc giai đoạn sau.
"""

from __future__ import annotations

import sys

from core.discovery import discover_modules
from core.models import ModuleCandidate, PlatformInfo
from core.platform import PlatformAdapter, get_adapter
from core.trust.anchors import TrustAnchorStore


def get_platform_info(adapter: PlatformAdapter | None = None) -> PlatformInfo:
    """Tổng hợp :class:`PlatformInfo` từ adapter hiện hành."""
    ad = adapter or get_adapter()
    arch = ad.host_arch()
    pcsc_ready, remediation = ad.pcsc_backend_ready()
    return PlatformInfo(
        name=ad.name(),
        bits=arch["bits"],
        machine=arch["machine"],
        rosetta=arch["rosetta"],
        python_version=sys.version.split()[0],
        pcsc_ready=pcsc_ready,
        pcsc_remediation=remediation,
        config_dir=str(ad.config_dir()),
        log_dir=str(ad.log_dir()),
        service_install_hint=ad.service_install_hint(),
    )


def list_modules(adapter: PlatformAdapter | None = None) -> list[ModuleCandidate]:
    """Phát hiện module PKCS#11 (Track A theo chip + Track B CA rebrand)."""
    return discover_modules(adapter)


def trust_store_summary() -> dict[str, int]:
    """Tóm tắt kho neo tin cậy (số chứng thư, số neo gốc)."""
    store = TrustAnchorStore()
    return {
        "total_certificates": len(store.certificates),
        "trust_anchors": len(store.anchors()),
    }


__all__ = ["get_platform_info", "list_modules", "trust_store_summary"]
