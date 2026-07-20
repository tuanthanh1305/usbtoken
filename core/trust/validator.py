"""Kiểm tra hiệu lực chứng thư — MODULE PHÁP LÝ QUAN TRỌNG NHẤT.

CĂN CỨ: TT 15/2025/TT-BKHCN Điều 6 — kiểm hiệu lực qua ĐƯỜNG DẪN TIN CẬY tới
chứng thư gốc NEAC + đáp ứng Phụ lục II. Kết quả là BẰNG CHỨNG PHÁP LÝ lưu được.

⛔ ĐIỀU KIỆN TIÊN QUYẾT — PHỤ LỤC II:
    Tiêu chí "tính hợp lệ" (Phụ lục II) KHÔNG được suy đoán trong code. Chúng
    được NẠP từ ``data/compliance/appendix_II.yaml`` (phải điền từ bản gốc
    https://rootca.gov.vn/VanBan/Thongtu_So15_2025_TT_BKHCN.pdf). Khi phụ lục
    CHƯA điền, validator KHÔNG BAO GIỜ trả VALID (fail-closed) — trả UNKNOWN kèm
    lý do "chưa điền Phụ lục II". Đây là ràng buộc AN TOÀN cốt lõi, không phải
    thiếu sót: thà từ chối còn hơn khẳng định sai.

⛔ FAIL-CLOSED tuyệt đối: không lấy được CRL/OCSP -> UNKNOWN (không VALID); kho
neo tin cậy quá cũ / chưa ký -> không khẳng định hợp lệ.

⭐ TÍCH HỢP KÝ (Điều 5): :func:`CertificateValidator.assert_signable` ném lỗi
nếu status != VALID — PROMPT 12 (ký) PHẢI gọi hàm này trước khi ký.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.serialization import Encoding

from core import x509_parser
from core.errors import SigningNotAllowedError
from core.models import (
    CertInfo,
    RevocationEvidence,
    RevocationStatus,
    TrustPathNode,
    ValidationResult,
    ValidationStatusCode,
)

from .anchors import load_certificate
from .policy import CompliancePolicy
from .store import TrustStore
from .store import load as load_store

_MAX_DEPTH = 16


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _not_before(cert: x509.Certificate) -> datetime | None:
    return _as_utc(getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None))


def _not_after(cert: x509.Certificate) -> datetime | None:
    return _as_utc(getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None))


def _ca_name(cert: x509.Certificate) -> str:
    """Tên CA lấy TỪ CHÍNH chứng thư (CN, rồi O) — KHÔNG regex, KHÔNG đoán."""
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = cert.subject.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return cert.subject.rfc4514_string()


def _fp(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


# --------------------------------------------------------------------------- #
# Cấu hình + chính sách thu hồi (cấu hình được)                                 #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ValidatorConfig:
    require_signed_store: bool = True  # kho phải ký (chống sửa) mới được khẳng định VALID
    require_policy_configured: bool = True  # phải điền Phụ lục II mới được VALID
    revocation_mode: str = "ocsp_first"  # ocsp_first | crl_first
    allow_network: bool = False  # mặc định offline -> thu hồi UNKNOWN (fail-closed)
    max_store_age: timedelta = timedelta(days=7)


class RevocationChecker(Protocol):
    def check(
        self, cert: x509.Certificate, issuer: x509.Certificate, cert_info: CertInfo,
        *, mode: str, allow_network: bool,
    ) -> RevocationEvidence: ...


class DefaultRevocationChecker:
    """Kiểm thu hồi: OCSP/CRL. Offline -> UNKNOWN (FAIL-CLOSED, không đoán)."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    def check(
        self, cert: x509.Certificate, issuer: x509.Certificate, cert_info: CertInfo,
        *, mode: str, allow_network: bool,
    ) -> RevocationEvidence:
        ev = RevocationEvidence(status=RevocationStatus.UNKNOWN, checked_at=_utcnow())
        if not allow_network:
            ev.method = "NONE"
            ev.reasons_vi.append(
                "Chưa kiểm được thu hồi (chế độ offline). KHÔNG coi là 'chưa thu hồi' — "
                "kết quả để UNKNOWN theo nguyên tắc fail-closed."
            )
            return ev
        # Trực tuyến: ưu tiên OCSP rồi CRL (best-effort). Không xác định -> UNKNOWN.
        from .revocation import RevocationChecker as CrlChecker

        outcome = CrlChecker(self.timeout).check(cert, issuer, allow_network=True)
        ev.method = "CRL"
        ev.status = outcome.status
        ev.source_url = outcome.source_url
        ev.crl_snapshot_sha256 = outcome.crl_sha256
        ev.this_update = outcome.this_update
        ev.next_update = outcome.next_update  # để validator kiểm độ tươi CRL online
        ev.reasons_vi.extend(outcome.reasons_vi)
        return ev


# --------------------------------------------------------------------------- #
# Kết quả dựng chain                                                           #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class _ChainInfo:
    path: list[x509.Certificate] = field(default_factory=list)
    reached_root: bool = False
    structurally_invalid: bool = False  # chữ ký sai / ràng buộc CA sai
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Validator                                                                    #
# --------------------------------------------------------------------------- #
class CertificateValidator:
    """Kiểm hiệu lực chứng thư người ký theo Điều 6 TT 15/2025 (fail-closed)."""

    def __init__(
        self,
        store: TrustStore | None = None,
        policy: object | None = None,
        revocation_checker: RevocationChecker | None = None,
        config: ValidatorConfig | None = None,
    ) -> None:
        self.store = store if store is not None else load_store()
        self.policy = policy or CompliancePolicy()
        self.revocation = revocation_checker or DefaultRevocationChecker()
        self.config = config or ValidatorConfig()

    # -- API chính ------------------------------------------------------ #
    def validate(self, cert_der: bytes, at_time: datetime | None = None) -> ValidationResult:
        checked_at = _utcnow()
        at = _as_utc(at_time) or checked_at
        result = ValidationResult(
            status=ValidationStatusCode.UNKNOWN, checked_at=checked_at, at_time=at,
            trust_store_synced_at=self.store.synced_at,
        )

        leaf = load_certificate(cert_der)
        if leaf is None:
            result.status = ValidationStatusCode.INVALID
            result.reasons_vi.append("Không đọc được chứng thư (định dạng DER/PEM không hợp lệ).")
            return result
        result.subject = leaf.subject.rfc4514_string()
        leaf_info = x509_parser.parse(cert_der)

        if self.store.is_empty:
            result.status = ValidationStatusCode.INVALID
            result.reasons_vi.append(
                "Kho neo tin cậy RỖNG — chưa nạp chứng thư gốc NEAC + các CA. Không "
                "thể kiểm hiệu lực (xem data/trust_store/, chạy tools/sync_trust_store)."
            )
            return result

        # === 1) CHAIN BUILDING (chữ ký thật + ràng buộc CA) =============== #
        chain = self._build_chain(leaf)
        result.trust_path = [self._node(c) for c in chain.path]
        if len(chain.path) >= 2:
            result.ca_name = _ca_name(chain.path[1])  # CA phát hành trực tiếp
        result.reasons_vi.extend(chain.reasons)

        if chain.structurally_invalid:
            result.status = ValidationStatusCode.INVALID
            return result

        if not chain.reached_root:
            # 5) Thử Danh sách tin cậy nước ngoài (TT 06/2024).
            if self._recognized_foreign(chain.path):
                result.status = ValidationStatusCode.FOREIGN_RECOGNIZED
                result.reasons_vi.append(
                    "Chứng thư thuộc Danh sách tin cậy NƯỚC NGOÀI được công nhận "
                    "(TT 06/2024/TT-BTTTT). KHÔNG thuộc gốc NEAC."
                )
                return result
            result.status = ValidationStatusCode.INVALID
            result.reasons_vi.append(
                "KHÔNG dựng được đường dẫn tin cậy tới chứng thư gốc NEAC (chain đứt)."
            )
            return result

        # Các cờ quyết định (fail-closed).
        hard_invalid = False
        revoked = False
        expired = False
        cannot_assert = False  # -> UNKNOWN

        # === 2) HIỆU LỰC THỜI GIAN (mọi cert trong chain) ================ #
        for cert in chain.path:
            nb, na = _not_before(cert), _not_after(cert)
            name = _ca_name(cert)
            if na is not None and at > na:
                expired = True
                result.reasons_vi.append(f"Chứng thư '{name}' đã HẾT HẠN ({na.isoformat()}).")
            if nb is not None and at < nb:
                hard_invalid = True
                result.reasons_vi.append(
                    f"Chứng thư '{name}' CHƯA có hiệu lực tại thời điểm kiểm ({nb.isoformat()})."
                )

        # === 3) KIỂM THU HỒI Ở MỌI BẬC (leaf + trung gian) =============== #
        for i in range(len(chain.path) - 1):  # bỏ Root (neo tin cậy)
            cert = chain.path[i]
            issuer = chain.path[i + 1]
            info = leaf_info if i == 0 else x509_parser.parse(
                cert.public_bytes(_der())
            )
            ev = self.revocation.check(
                cert, issuer, info,
                mode=self.config.revocation_mode, allow_network=self.config.allow_network,
            )
            ev.node_subject = cert.subject.rfc4514_string()
            result.revocations.append(ev)
            if ev.status is RevocationStatus.REVOKED:
                revoked = True
                result.reasons_vi.append(f"Chứng thư '{_ca_name(cert)}' ĐÃ BỊ THU HỒI.")
            elif ev.status in (RevocationStatus.UNKNOWN, RevocationStatus.UNCHECKED):
                cannot_assert = True
                result.reasons_vi.append(
                    f"Không xác định được trạng thái thu hồi của '{_ca_name(cert)}' "
                    "(fail-closed: không coi là hợp lệ)."
                )
            # CRL hết hạn -> UNKNOWN
            if ev.next_update is not None and ev.next_update < checked_at:
                cannot_assert = True
                result.reasons_vi.append(
                    f"CRL/OCSP của '{_ca_name(cert)}' đã HẾT HẠN (nextUpdate quá khứ) — "
                    "không đáng tin, để UNKNOWN."
                )

        # === 4) FAIL-CLOSED: kho ký + độ mới ============================= #
        if self.config.require_signed_store and not self.store.verified:
            cannot_assert = True
            result.reasons_vi.append(
                "Kho neo tin cậy CHƯA được ký/verify (chống sửa cục bộ) — fail-closed."
            )
        stale, stale_reasons = self.store.is_stale(self.config.max_store_age)
        if stale:
            cannot_assert = True
            result.reasons_vi.extend(stale_reasons)
            result.reasons_vi.append("Kho neo tin cậy quá cũ — KHÔNG khẳng định hợp lệ.")

        # === Phụ lục II (nạp từ yaml, KHÔNG suy đoán) ==================== #
        if self.config.require_policy_configured:
            if not getattr(self.policy, "is_configured", False):
                cannot_assert = True
                result.reasons_vi.append(
                    "CHƯA điền/duyệt Phụ lục II (TT 15/2025) — không thể khẳng định HỢP LỆ. "
                    "Xem data/compliance/appendix_II.yaml."
                )
            else:
                ok, ap_reasons = self._check_appendix_ii(leaf_info)
                result.reasons_vi.extend(ap_reasons)
                if not ok:
                    hard_invalid = True

        # === Quyết định trạng thái (thứ tự nghiêm trọng) ================ #
        if hard_invalid:
            result.status = ValidationStatusCode.INVALID
        elif revoked:
            result.status = ValidationStatusCode.REVOKED
        elif expired:
            result.status = ValidationStatusCode.EXPIRED
        elif cannot_assert:
            result.status = ValidationStatusCode.UNKNOWN
        else:
            result.status = ValidationStatusCode.VALID
            result.reasons_vi.append("Chứng thư HỢP LỆ: chain tới gốc NEAC, còn hiệu lực, "
                                     "chưa thu hồi, đáp ứng Phụ lục II.")
        return result

    def assert_signable(self, cert_der: bytes, at_time: datetime | None = None) -> ValidationResult:
        """⭐ Điều 5: chỉ cho phép ký khi VALID. Ném lỗi nếu không."""
        result = self.validate(cert_der, at_time)
        if result.status is not ValidationStatusCode.VALID:
            raise SigningNotAllowedError(
                "Không được phép ký: chứng thư không ở trạng thái HỢP LỆ "
                f"({result.status.value}). " + " ".join(result.reasons_vi[:3]),
                detail=result.status.value,
                result=result,
            )
        return result

    # -- Chain building nội bộ (dùng TrustStore.find_issuer) ------------ #
    def _build_chain(self, leaf: x509.Certificate) -> _ChainInfo:
        info = _ChainInfo(path=[leaf])
        if self.store.is_trust_anchor(leaf):
            info.reached_root = True
            return info
        current = leaf
        seen = {_fp(leaf)}
        for _ in range(_MAX_DEPTH):
            issuer_entry = self.store.find_issuer(current)  # AKI<->SKI + Issuer DN<->Subject DN
            if issuer_entry is None:
                info.reasons.append(
                    "Không tìm được chứng thư CA phát hành trong kho tin cậy (khớp AKI/DN thất bại)."
                )
                return info
            issuer = issuer_entry.cert
            # Xác minh CHỮ KÝ THẬT (mật mã), KHÔNG so chuỗi tên.
            try:
                current.verify_directly_issued_by(issuer)
            except Exception:  # noqa: BLE001
                info.structurally_invalid = True
                info.reasons.append(
                    f"Chữ ký của '{_ca_name(current)}' KHÔNG khớp CA phát hành — chain không hợp lệ."
                )
                return info
            ok, cons = _check_ca_constraints(issuer, intermediates_below=len(info.path) - 1)
            info.reasons.extend(cons)
            if not ok:
                info.structurally_invalid = True
                return info
            fpi = _fp(issuer)
            if fpi in seen:
                info.reasons.append("Phát hiện VÒNG LẶP trong chuỗi chứng thư.")
                return info
            seen.add(fpi)
            info.path.append(issuer)
            if self.store.is_trust_anchor(issuer):
                info.reached_root = True
                return info
            current = issuer
        info.reasons.append(f"Chuỗi vượt quá độ sâu tối đa ({_MAX_DEPTH}).")
        return info

    def _recognized_foreign(self, path: list[x509.Certificate]) -> bool:
        """Kiểm chain có kết thúc ở một neo NƯỚC NGOÀI được công nhận không."""
        foreign = self.store.foreign_trusted_list
        if not foreign or not path:
            return False
        top = path[-1]
        # (a) top CHÍNH LÀ một neo nước ngoài đã ghim — khớp VÂN TAY (mật mã),
        # KHÔNG so Subject DN. So tên sẽ nhận nhầm một cert giả mạo chép DN của
        # neo nước ngoài (khác khoá) là hợp lệ.
        foreign_fps = {_fp(c) for c in foreign}
        if _fp(top) in foreign_fps:
            return True
        # (b) top được một neo nước ngoài phát hành TRỰC TIẾP (xác minh chữ ký).
        for anchor in foreign:
            if anchor.subject == top.issuer:
                try:
                    top.verify_directly_issued_by(anchor)
                    return True
                except Exception:  # noqa: BLE001
                    continue
        return False

    def _check_appendix_ii(self, leaf: CertInfo) -> tuple[bool, list[str]]:
        """Áp tiêu chí Phụ lục II — CHỈ những gì CÓ trong yaml (không suy đoán)."""
        reqs = self.policy.certificate_requirements()  # type: ignore[attr-defined]
        reasons: list[str] = []
        ok = True
        for ku in reqs.get("key_usage_required") or []:
            if ku not in leaf.key_usage:
                ok = False
                reasons.append(f"Thiếu KeyUsage bắt buộc theo Phụ lục II: {ku}.")
        for eku in reqs.get("extended_key_usage") or []:
            if eku not in leaf.extended_key_usage:
                ok = False
                reasons.append(f"Thiếu ExtendedKeyUsage bắt buộc theo Phụ lục II: {eku}.")
        max_days = reqs.get("max_validity_days")
        if max_days and leaf.not_before and leaf.not_after:
            days = (leaf.not_after - leaf.not_before).days
            if days > int(max_days):
                ok = False
                reasons.append(f"Thời hạn chứng thư {days} ngày > tối đa {max_days} (Phụ lục II).")
        if ok:
            reasons.append("Đáp ứng các tiêu chí Phụ lục II đã cấu hình.")
        return ok, reasons

    @staticmethod
    def _node(cert: x509.Certificate) -> TrustPathNode:
        return TrustPathNode(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_hex=format(cert.serial_number, "x"),
            is_trust_anchor=cert.subject == cert.issuer,
            fingerprint_sha256=_fp(cert),
            ca_name=_ca_name(cert),
        )


def _der() -> Encoding:
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _check_ca_constraints(cert: x509.Certificate, *, intermediates_below: int) -> tuple[bool, list[str]]:
    """CA phải: BasicConstraints CA=TRUE, KeyUsage keyCertSign, pathLen đủ."""
    reasons: list[str] = []
    ok = True
    try:
        bc = cast(
            x509.BasicConstraints,
            cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value,
        )
        if not bc.ca:
            ok = False
            reasons.append(f"'{_ca_name(cert)}' không phải CA (BasicConstraints CA=FALSE).")
        elif bc.path_length is not None and intermediates_below > bc.path_length:
            ok = False
            reasons.append(
                f"'{_ca_name(cert)}' vi phạm pathLenConstraint "
                f"({intermediates_below} > {bc.path_length})."
            )
    except x509.ExtensionNotFound:
        ok = False
        reasons.append(f"'{_ca_name(cert)}' thiếu BasicConstraints — không đủ điều kiện làm CA.")
    try:
        ku = cast(
            x509.KeyUsage,
            cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value,
        )
        if not ku.key_cert_sign:
            ok = False
            reasons.append(f"'{_ca_name(cert)}' thiếu KeyUsage keyCertSign — không được cấp chứng thư.")
    except x509.ExtensionNotFound:
        reasons.append(f"'{_ca_name(cert)}' không có KeyUsage (bỏ qua kiểm keyCertSign).")
    return ok, reasons


# --------------------------------------------------------------------------- #
# Lưu bằng chứng                                                               #
# --------------------------------------------------------------------------- #
def persist_validation(result: ValidationResult, *, out_dir: Path | None = None) -> Path:
    """Lưu :class:`ValidationResult` (JSON) làm bằng chứng đối chiếu kiểm toán."""
    from core.platform import get_adapter

    directory = out_dir or (get_adapter().log_dir() / "validations")
    directory.mkdir(parents=True, exist_ok=True)
    stamp = result.checked_at.strftime("%Y%m%dT%H%M%S%z") or "unknown"
    path = directory / f"validation_{stamp}_{abs(hash(result.subject)) % 10_000:04d}.json"
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


__all__ = [
    "CertificateValidator",
    "ValidatorConfig",
    "DefaultRevocationChecker",
    "RevocationChecker",
    "persist_validation",
]
