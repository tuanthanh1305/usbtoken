"""Data model chung (pydantic v2) — ngôn ngữ chung của core/service/web.

Bố cục theo BA TRỤC ĐỘC LẬP:
    * TRỤC 1 (MODULE): :class:`ModuleCandidate` — file ta nạp, track A/B.
    * TRỤC 2 (CHIP):   :class:`TokenInfo.manufacturer_id` — chip THẬT trong token
      (đọc qua ``C_GetTokenInfo``, giai đoạn sau).
    * TRỤC 3 (CA):     :class:`CAInfo` — bên phát hành chứng thư, xác định bằng
      CHAIN BUILDING (``core/trust``), TUYỆT ĐỐI KHÔNG bằng regex trên Issuer.

:class:`ValidationResult` là BẰNG CHỨNG PHÁP LÝ (Điều 5/6 TT 15/2025): phải lưu
được đường dẫn tin cậy, trạng thái thu hồi và ảnh chụp CRL tại thời điểm ký.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    """Base dùng chung: cấm field lạ, enum giữ nguyên (không ép giá trị)."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# --------------------------------------------------------------------------- #
# Nền tảng (TRỤC 1)                                                            #
# --------------------------------------------------------------------------- #
class PlatformInfo(_Base):
    """Ảnh chụp môi trường thực thi (do tầng platform cung cấp)."""

    name: Literal["windows", "macos", "linux"]
    bits: Literal[64, 32]
    machine: Literal["arm64", "x86_64"]
    rosetta: bool = Field(default=False, description="Đang chạy dưới Rosetta 2 (macOS).")
    python_version: str
    pcsc_ready: bool
    pcsc_remediation: str = ""
    config_dir: str = ""
    log_dir: str = ""
    service_install_hint: str = ""


# --------------------------------------------------------------------------- #
# Module PKCS#11 (TRỤC 1)                                                      #
# --------------------------------------------------------------------------- #
class ModuleTrack(str, Enum):
    """Nhánh phát hiện module.

    * ``A`` — theo CHIP (tên file middleware của nhà sản xuất chip).
    * ``B`` — CA REBRAND (module do một CA phát hành riêng, vd. fptca_v4.so).
    """

    A_CHIP = "A"
    B_CA_REBRAND = "B"


class ModuleCandidate(_Base):
    """Một ứng viên module PKCS#11.

    ``chip_hint`` chỉ là GỢI Ý suy từ tên file — KHÔNG có giá trị pháp lý và
    KHÔNG thay cho TRỤC 2 (chip thật, đọc qua ``C_GetTokenInfo``) hay TRỤC 3
    (CA, xác định bằng chain building).
    """

    path: str = Field(..., description="Đường dẫn tuyệt đối tới module.")
    track: ModuleTrack = Field(..., description="Nhánh phát hiện: A (chip) | B (CA rebrand).")
    chip_hint: str = Field(
        default="", description="Gợi ý chip/nhà cung cấp từ tên file (KHÔNG chuẩn xác)."
    )
    source: str = Field(
        default="search_path",
        description="Nguồn: system | user_config | vendor_intel | glob_probe.",
    )
    tier: int = Field(
        default=0, ge=0, le=4, description="Tầng phát hiện (1..4); 0 nếu chưa rõ."
    )
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Độ tin cậy phát hiện [0..1]."
    )
    confidence_label: str = Field(
        default="", description="Nhãn: confirmed | documented | hypothesis."
    )
    arch: str = Field(default="unknown", description="Kiến trúc native của file.")
    validated: bool = Field(
        default=False,
        description="Đã xác thực (arch hợp lệ; Tầng 4: C_GetInfo cryptokiVersion hợp lệ).",
    )
    needs_arch_bridge: bool = Field(
        default=False, description="Lệch arch với host? (ĐÁNH CỜ, KHÔNG loại bỏ)."
    )
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Token & khoá (TRỤC 2)                                                        #
# --------------------------------------------------------------------------- #
class PinState(_Base):
    """Trạng thái PIN của token (giải mã từ CK_TOKEN_INFO.flags)."""

    login_required: bool = True
    count_low: bool = False
    final_try: bool = False
    locked: bool = False
    protected_auth_path: bool = False


class TokenInfo(_Base):
    """Thông tin một USB token (một slot PKCS#11 có token cắm vào).

    ``manufacturer_id`` là CHIP THẬT (TRỤC 2) — đọc từ ``C_GetTokenInfo`` —
    KHÔNG suy từ tên module (TRỤC 1) và KHÔNG dính tới CA (TRỤC 3).
    """

    module_path: str = Field(default="", description="Module PKCS#11 đã dùng để thấy token.")
    slot_id: int = Field(..., description="Định danh slot PKCS#11.")
    label: str = ""
    # ⭐ TRỤC 2 — CHIP THẬT: đọc từ C_GetTokenInfo, ĐỘC LẬP với tên module.
    manufacturer_id: str = Field(
        default="", description="Chip THẬT (CK_TOKEN_INFO.manufacturerID)."
    )
    model: str = Field(default="", description="Model chip THẬT (CK_TOKEN_INFO.model).")
    serial: str = ""
    flags: int = Field(default=0, description="Bitmask CK_TOKEN_INFO.flags thô.")
    pin_state: PinState = Field(default_factory=PinState)
    # -- Metadata TRỤC 1 (từ ModuleCandidate) — GỢI Ý, khác chip thật ở trên -- #
    track: str = Field(default="", description="Nhánh module: A (chip) | B (CA rebrand).")
    chip_hint: str = Field(
        default="", description="Gợi ý từ tên module (KHÔNG phải chip thật)."
    )
    source: str = Field(default="", description="Nguồn phát hiện module.")
    arch: str = Field(default="unknown", description="Kiến trúc native của module.")
    via_bridge: bool = Field(
        default=False, description="Token được liệt kê QUA bridge (module lệch arch)."
    )


class KeyInfo(_Base):
    """Một đối tượng khoá trên token."""

    label: str = ""
    id_hex: str = ""
    key_type: str = Field(default="", description="RSA | EC | ...")
    key_class: Literal["private", "public", "secret", "unknown"] = "unknown"
    bits: int | None = None
    usable_for_signing: bool = False


# --------------------------------------------------------------------------- #
# Chứng thư (TRỤC 3)                                                           #
# --------------------------------------------------------------------------- #
class CertInfo(_Base):
    """Chứng thư số X.509 (đọc từ token hoặc kho fallback)."""

    subject: str = ""
    issuer: str = ""
    serial_hex: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    fingerprint_sha256: str = Field(default="", description="Vân tay SHA-256 (hex) của DER.")
    der_b64: str = Field(default="", description="Chứng thư DER mã hoá base64.")
    key_id_hex: str = ""
    key_usage: list[str] = Field(default_factory=list)
    extended_key_usage: list[str] = Field(default_factory=list)


class CAInfo(_Base):
    """Kết quả nhận diện CA — TỪ CHAIN BUILDING, KHÔNG từ regex.

    Chỉ điền khi đã dựng được đường dẫn tin cậy tới một neo tin cậy (Vietnam
    National Root CA do NEAC phát hành).
    """

    ca_name: str = Field(default="", description="Tên CA (lấy từ chứng thư CA phát hành).")
    ca_cert_subject: str = Field(default="", description="Subject DN của chứng thư CA.")
    chain_verified: bool = Field(
        default=False, description="Đã xác thực chuỗi bằng mật mã tới neo tin cậy chưa."
    )
    trust_anchor: str = Field(
        default="", description="Subject DN của neo tin cậy gốc (NEAC Root)."
    )


# --------------------------------------------------------------------------- #
# Kết quả kiểm tra hiệu lực — BẰNG CHỨNG PHÁP LÝ                               #
# --------------------------------------------------------------------------- #
class RevocationStatus(str, Enum):
    """Trạng thái thu hồi của chứng thư."""

    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    UNCHECKED = "unchecked"  # chưa kiểm (offline / thiếu cấu hình)


class ValidationStatusCode(str, Enum):
    """Kết luận tổng thể của việc kiểm tra hiệu lực chứng thư."""

    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REVOKED = "revoked"
    UNTRUSTED = "untrusted"  # không dựng được đường dẫn tới neo tin cậy
    POLICY_NOT_CONFIGURED = "policy_not_configured"  # chưa điền Phụ lục I/II
    ERROR = "error"


class TrustPathNode(_Base):
    """Một mắt xích trong đường dẫn tin cậy (để lưu làm bằng chứng)."""

    subject: str
    issuer: str
    serial_hex: str
    is_trust_anchor: bool = False
    fingerprint_sha256: str = ""


class ValidationResult(_Base):
    """Kết quả kiểm tra hiệu lực — PHẢI LƯU ĐƯỢC (bằng chứng pháp lý).

    Theo Điều 5/6 TT 15/2025: lưu chứng thư đã ký + CRL tại thời điểm ký + kết
    quả kiểm tra trạng thái, và kiểm qua ĐƯỜNG DẪN TIN CẬY tới chứng thư gốc.
    """

    status: ValidationStatusCode
    checked_at: datetime = Field(..., description="Thời điểm kiểm tra (UTC).")
    subject: str = ""
    trust_path: list[TrustPathNode] = Field(default_factory=list)
    revocation_status: RevocationStatus = RevocationStatus.UNCHECKED
    crl_snapshot_ref: str = Field(
        default="", description="Tham chiếu ảnh chụp CRL tại thời điểm kiểm (đường dẫn/hash)."
    )
    ocsp_snapshot_ref: str = ""
    reasons_vi: list[str] = Field(
        default_factory=list, description="Lý do/diễn giải BẰNG TIẾNG VIỆT."
    )


# --------------------------------------------------------------------------- #
# Lỗi — thông báo & remediation theo OS                                        #
# --------------------------------------------------------------------------- #
class ErrorCode(str, Enum):
    """Mã lỗi ổn định để service/web phân nhánh."""

    UNSUPPORTED_PLATFORM = "unsupported_platform"
    PCSC_NOT_READY = "pcsc_not_ready"
    NO_MODULE_FOUND = "no_module_found"
    ARCH_MISMATCH = "arch_mismatch"
    BRIDGE_UNAVAILABLE = "bridge_unavailable"
    TOKEN_NOT_PRESENT = "token_not_present"
    LOGIN_REQUIRED = "login_required"
    TRUST_STORE_EMPTY = "trust_store_empty"
    CHAIN_BUILD_FAILED = "chain_build_failed"
    POLICY_NOT_CONFIGURED = "policy_not_configured"
    ESIGN_GATEWAY_ERROR = "esign_gateway_error"
    INTERNAL_ERROR = "internal_error"


class ErrorInfo(_Base):
    """Lỗi có cấu trúc: thông báo TIẾNG VIỆT + gợi ý khắc phục theo OS."""

    code: ErrorCode
    message_vi: str = Field(..., description="Thông báo BẰNG TIẾNG VIỆT.")
    remediation: str = Field(default="", description="Gợi ý khắc phục theo OS hiện tại.")
    platform: Literal["windows", "macos", "linux", "unknown"] = "unknown"
    detail: str = ""


__all__ = [
    "PlatformInfo",
    "ModuleTrack",
    "ModuleCandidate",
    "PinState",
    "TokenInfo",
    "KeyInfo",
    "CertInfo",
    "CAInfo",
    "RevocationStatus",
    "ValidationStatusCode",
    "TrustPathNode",
    "ValidationResult",
    "ErrorCode",
    "ErrorInfo",
]
