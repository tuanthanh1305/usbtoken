"""Ngoại lệ có mã lỗi ổn định (ánh xạ sang :class:`core.models.ErrorInfo`)."""

from __future__ import annotations

from core.models import ErrorCode


class VNeSignError(Exception):
    """Lỗi gốc của hệ thống, mang :class:`ErrorCode` + chi tiết.

    ``message`` là thông báo TIẾNG VIỆT (yêu cầu pháp lý: thông báo kết quả
    bằng tiếng Việt).
    """

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(self, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class UnsupportedPlatformError(VNeSignError):
    code = ErrorCode.UNSUPPORTED_PLATFORM


class PCSCNotReadyError(VNeSignError):
    code = ErrorCode.PCSC_NOT_READY


class NoModuleFoundError(VNeSignError):
    code = ErrorCode.NO_MODULE_FOUND


class ArchMismatchError(VNeSignError):
    code = ErrorCode.ARCH_MISMATCH


class BridgeUnavailableError(VNeSignError):
    code = ErrorCode.BRIDGE_UNAVAILABLE


class TrustStoreEmptyError(VNeSignError):
    code = ErrorCode.TRUST_STORE_EMPTY


class ChainBuildError(VNeSignError):
    code = ErrorCode.CHAIN_BUILD_FAILED


class SigningNotAllowedError(VNeSignError):
    """Chứng thư KHÔNG hợp lệ -> KHÔNG được phép ký (Điều 5 TT 15/2025).

    Mang theo :class:`ValidationResult` để tầng trên hiển thị lý do tiếng Việt.
    """

    code = ErrorCode.VALIDATION_FAILED

    def __init__(self, message: str, *, detail: str = "", result: object = None) -> None:
        super().__init__(message, detail=detail)
        self.result = result


class PolicyNotConfiguredError(VNeSignError):
    """Chưa điền Phụ lục I/II của TT 15/2025 -> không được phép kiểm tra/ký."""

    code = ErrorCode.POLICY_NOT_CONFIGURED


class ESignGatewayError(VNeSignError):
    code = ErrorCode.ESIGN_GATEWAY_ERROR


__all__ = [
    "VNeSignError",
    "UnsupportedPlatformError",
    "PCSCNotReadyError",
    "NoModuleFoundError",
    "ArchMismatchError",
    "BridgeUnavailableError",
    "TrustStoreEmptyError",
    "ChainBuildError",
    "SigningNotAllowedError",
    "PolicyNotConfiguredError",
    "ESignGatewayError",
]
