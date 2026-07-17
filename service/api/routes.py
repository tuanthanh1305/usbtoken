"""Endpoint REST của daemon (chỉ gọi ``core`` — không rẽ nhánh theo OS).

Giai đoạn này: thông tin nền tảng, phát hiện module (Track A/B), trạng thái kho
tin cậy, tình trạng tuân thủ Phụ lục, và KIỂM TRA HIỆU LỰC chứng thư (bằng
chain building). Chưa có thao tác đọc token/ký (giai đoạn sau).
"""

from __future__ import annotations

import base64

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core import __version__
from core.engine import get_platform_info, list_modules, trust_store_summary
from core.models import ModuleCandidate, PlatformInfo, ValidationResult
from core.trust.policy import CompliancePolicy
from core.trust.validator import CertificateValidator, ValidatorConfig

router = APIRouter(prefix="/api", tags=["vn-esign"])


@router.get("/health", summary="Kiểm tra daemon còn sống")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/platform", response_model=PlatformInfo, summary="Thông tin nền tảng")
def platform_info() -> PlatformInfo:
    return get_platform_info()


@router.get("/modules", response_model=list[ModuleCandidate], summary="Phát hiện module (Track A/B)")
def modules() -> list[ModuleCandidate]:
    """Danh sách module PKCS#11: Track A (theo chip) + Track B (CA rebrand)."""
    return list_modules()


@router.get("/trust/status", summary="Trạng thái kho tin cậy + tuân thủ Phụ lục")
def trust_status() -> dict[str, object]:
    """Tóm tắt kho neo tin cậy và tình trạng điền Phụ lục I/II."""
    policy = CompliancePolicy().status()
    return {
        "trust_store": trust_store_summary(),
        "appendix_i_filled": policy.appendix_i_filled,
        "appendix_ii_filled": policy.appendix_ii_filled,
        "fully_configured": policy.fully_configured,
    }


class ValidateRequest(BaseModel):
    """Yêu cầu kiểm tra hiệu lực một chứng thư (DER mã hoá base64)."""

    certificate_b64: str = Field(..., description="Chứng thư DER, mã hoá base64.")
    allow_network: bool = Field(default=False, description="Cho phép tải CRL/OCSP.")


@router.post("/validate", response_model=ValidationResult, summary="Kiểm tra hiệu lực chứng thư")
def validate(req: ValidateRequest) -> ValidationResult:
    """Kiểm tra hiệu lực qua ĐƯỜNG DẪN TIN CẬY (chain building), trả bằng chứng.

    Nhận diện CA bằng mật mã (KHÔNG regex). Nếu chưa điền Phụ lục I/II hoặc kho
    tin cậy rỗng, kết quả phản ánh đúng trạng thái fail-safe.
    """
    der = base64.b64decode(req.certificate_b64)
    config = ValidatorConfig(allow_network=req.allow_network)
    return CertificateValidator(config=config).validate(der)


__all__ = ["router"]
