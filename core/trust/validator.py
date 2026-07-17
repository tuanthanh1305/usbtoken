"""Kiểm tra hiệu lực chứng thư -> :class:`ValidationResult` (BẰNG CHỨNG PHÁP LÝ).

Ghép các mảnh: chain building (TRỤC 3) + kiểm hiệu lực thời gian + thu hồi
(CRL/OCSP) + chính sách Phụ lục I/II. Kết quả PHẢI lưu được (đường dẫn tin cậy,
trạng thái thu hồi, ảnh chụp CRL) — phục vụ đối chiếu khi kiểm toán (TT 19/2025).

FAIL-SAFE: nếu chưa điền Phụ lục I/II, KHÔNG bao giờ tuyên bố "hợp lệ" — trả
``POLICY_NOT_CONFIGURED`` để tránh kết luận sai về pháp lý.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from core.models import (
    RevocationStatus,
    ValidationResult,
    ValidationStatusCode,
)
from core.platform import get_adapter
from .anchors import TrustAnchorStore, load_certificate
from .chain import ChainBuilder
from .policy import CompliancePolicy
from .revocation import RevocationChecker


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CertificateValidator:
    """Điều phối kiểm tra hiệu lực một chứng thư người ký (leaf)."""

    def __init__(
        self,
        store: TrustAnchorStore | None = None,
        policy: CompliancePolicy | None = None,
        revocation: RevocationChecker | None = None,
    ) -> None:
        self.store = store or TrustAnchorStore()
        self.policy = policy or CompliancePolicy()
        self.revocation = revocation or RevocationChecker()
        self.builder = ChainBuilder(self.store)

    def validate(
        self,
        leaf_der: bytes,
        *,
        at: datetime | None = None,
        allow_network: bool = False,
    ) -> ValidationResult:
        """Kiểm tra hiệu lực; trả kết quả có cấu trúc (lý do bằng tiếng Việt)."""
        checked_at = at or _utcnow()
        reasons: list[str] = []

        leaf = load_certificate(leaf_der)
        if leaf is None:
            return ValidationResult(
                status=ValidationStatusCode.ERROR,
                checked_at=checked_at,
                reasons_vi=["Không đọc được chứng thư (định dạng DER/PEM không hợp lệ)."],
            )

        subject = leaf.subject.rfc4514_string()

        # 1) Dựng đường dẫn tin cậy (nhận diện CA bằng mật mã, KHÔNG regex).
        chain = self.builder.build(leaf)
        reasons.extend(chain.reasons_vi)
        trust_path = chain.nodes(self.store)

        # 2) Hiệu lực theo thời gian.
        not_before = leaf.not_valid_before_utc
        not_after = leaf.not_valid_after_utc
        time_status: ValidationStatusCode | None = None
        if checked_at < not_before:
            time_status = ValidationStatusCode.NOT_YET_VALID
            reasons.append(f"Chứng thư chưa có hiệu lực (hiệu lực từ {not_before.isoformat()}).")
        elif checked_at > not_after:
            time_status = ValidationStatusCode.EXPIRED
            reasons.append(f"Chứng thư đã hết hạn (hết hạn {not_after.isoformat()}).")

        # 3) Kiểm thu hồi (leaf so với CA phát hành trực tiếp).
        issuer_cert = chain.path[1] if len(chain.path) >= 2 else None
        rev = self.revocation.check(leaf, issuer_cert, allow_network=allow_network)
        reasons.extend(rev.reasons_vi)

        # 4) Chính sách Phụ lục I/II (fail-safe nếu chưa điền).
        policy_ok = self.policy.is_configured
        if not policy_ok:
            reasons.append(
                "Chưa điền/duyệt Phụ lục I & II (TT 15/2025) — không thể kết luận "
                "HỢP LỆ theo đúng tiêu chuẩn; xem data/compliance/."
            )

        status = self._decide_status(
            time_status=time_status,
            chain_verified=chain.verified,
            store_empty=self.store.is_empty,
            revocation_status=rev.status,
            policy_ok=policy_ok,
        )

        return ValidationResult(
            status=status,
            checked_at=checked_at,
            subject=subject,
            trust_path=trust_path,
            revocation_status=rev.status,
            crl_snapshot_ref=rev.crl_sha256,
            reasons_vi=reasons,
        )

    @staticmethod
    def _decide_status(
        *,
        time_status: ValidationStatusCode | None,
        chain_verified: bool,
        store_empty: bool,
        revocation_status: RevocationStatus,
        policy_ok: bool,
    ) -> ValidationStatusCode:
        """Quyết định kết luận cuối theo thứ tự ưu tiên (fail-safe)."""
        if time_status is not None:
            return time_status
        if revocation_status is RevocationStatus.REVOKED:
            return ValidationStatusCode.REVOKED
        if store_empty or not chain_verified:
            return ValidationStatusCode.UNTRUSTED
        if not policy_ok:
            # Chuỗi tin cậy OK nhưng chưa đủ căn cứ Phụ lục -> không tuyên VALID.
            return ValidationStatusCode.POLICY_NOT_CONFIGURED
        return ValidationStatusCode.VALID


def persist_validation(
    result: ValidationResult, *, crl_der: bytes | None = None
) -> Path:
    """Lưu :class:`ValidationResult` (+ ảnh chụp CRL) vào thư mục log của OS.

    Trả về đường dẫn file JSON đã ghi. Đây là BẰNG CHỨNG để đối chiếu kiểm toán.
    Thời gian trong tên file lấy từ ``result.checked_at`` (không tự sinh mới).
    """
    log_dir = get_adapter().log_dir() / "validations"
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = result.checked_at.strftime("%Y%m%dT%H%M%S%z") or "unknown"
    base = log_dir / f"validation_{stamp}_{abs(hash(result.subject)) % 10_000:04d}"

    json_path = base.with_suffix(".json")
    json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    if crl_der:
        base.with_suffix(".crl").write_bytes(crl_der)
    return json_path


__all__ = ["CertificateValidator", "persist_validation"]
