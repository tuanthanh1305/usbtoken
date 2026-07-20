"""Kiểm tra trạng thái THU HỒI chứng thư (CRL/OCSP) + lưu ảnh chụp làm bằng chứng.

Điều 5/6 TT 15/2025 yêu cầu: kiểm tra trạng thái thu hồi và LƯU "CRL tại thời
điểm ký". Module này tải CRL từ điểm phân phối (CDP) trong chứng thư, xác thực
chữ ký CRL bằng chứng thư CA phát hành, và trả về ảnh chụp CRL (bytes) để tầng
trên lưu trữ.

Mặc định ``allow_network=False`` (offline-safe): khi tắt mạng, trả
``UNCHECKED`` thay vì bịa kết quả.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from core.models import RevocationStatus

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
    from cryptography.hazmat.primitives.serialization import Encoding


@dataclass(slots=True)
class RevocationOutcome:
    """Kết quả kiểm tra thu hồi + ảnh chụp CRL để lưu bằng chứng."""

    status: RevocationStatus = RevocationStatus.UNCHECKED
    crl_der: bytes | None = None
    crl_sha256: str = ""
    source_url: str = ""
    this_update: datetime | None = None
    next_update: datetime | None = None
    reasons_vi: list[str] = field(default_factory=list)


def _crl_urls(cert: x509.Certificate) -> list[str]:
    """Trích các URL CRL từ phần mở rộng CRL Distribution Points."""
    urls: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except x509.ExtensionNotFound:
        return urls
    for dp in cast(x509.CRLDistributionPoints, ext.value):
        if dp.full_name:
            for name in dp.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    urls.append(name.value)
    return urls


class RevocationChecker:
    """Kiểm tra thu hồi qua CRL (OCSP để chỗ dành sẵn).

    Args:
        timeout: thời gian chờ tải CRL (giây).
    """

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    def check(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate | None,
        *,
        allow_network: bool = False,
    ) -> RevocationOutcome:
        """Kiểm tra ``cert`` có bị thu hồi không dựa trên CRL của nó."""
        outcome = RevocationOutcome()
        urls = _crl_urls(cert)
        if not urls:
            outcome.reasons_vi.append("Chứng thư không có điểm phân phối CRL (CDP).")
            return outcome
        if not allow_network:
            outcome.reasons_vi.append(
                "Chưa kiểm thu hồi: đang ở chế độ offline (allow_network=False)."
            )
            return outcome

        for url in urls:
            crl_bytes = self._download(url)
            if crl_bytes is None:
                continue
            crl = self._parse_crl(crl_bytes)
            if crl is None:
                continue
            outcome.crl_der = crl.public_bytes(_der_encoding())
            outcome.crl_sha256 = hashlib.sha256(outcome.crl_der).hexdigest()
            outcome.source_url = url
            outcome.this_update = _crl_this_update(crl)
            outcome.next_update = _crl_next_update(crl)

            # Xác thực chữ ký CRL bằng khoá công khai của CA phát hành (nếu có).
            if issuer is not None and not self._crl_signature_valid(crl, issuer):
                outcome.status = RevocationStatus.UNKNOWN
                outcome.reasons_vi.append("Chữ ký CRL không hợp lệ so với CA phát hành.")
                return outcome

            # CRL đã HẾT HẠN (nextUpdate quá khứ) -> KHÔNG đáng tin: fail-closed.
            # Không được kết luận GOOD từ một CRL cũ (có thể trước khi cert bị thu hồi).
            if outcome.next_update is not None and outcome.next_update < datetime.now(timezone.utc):
                outcome.status = RevocationStatus.UNKNOWN
                outcome.reasons_vi.append(
                    f"CRL đã HẾT HẠN (nextUpdate {outcome.next_update.isoformat()}) — "
                    "không đủ tin cậy để kết luận, để UNKNOWN (fail-closed)."
                )
                return outcome

            revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            if revoked is not None:
                outcome.status = RevocationStatus.REVOKED
                outcome.reasons_vi.append(
                    f"Chứng thư ĐÃ BỊ THU HỒI (serial {cert.serial_number:x})."
                )
            else:
                outcome.status = RevocationStatus.GOOD
                outcome.reasons_vi.append("Không thấy trong danh sách thu hồi (CRL).")
            return outcome

        outcome.status = RevocationStatus.UNKNOWN
        outcome.reasons_vi.append("Không tải/parse được CRL từ mọi CDP.")
        return outcome

    # -- Nội bộ ---------------------------------------------------------- #
    def _download(self, url: str) -> bytes | None:
        try:
            import httpx

            resp = httpx.get(url, timeout=self.timeout, follow_redirects=True)
            if resp.status_code == 200:
                return resp.content
        except Exception:  # noqa: BLE001 - lỗi mạng -> thử CDP khác
            return None
        return None

    @staticmethod
    def _parse_crl(data: bytes) -> x509.CertificateRevocationList | None:
        try:
            return x509.load_der_x509_crl(data)
        except ValueError:
            pass
        try:
            return x509.load_pem_x509_crl(data)
        except ValueError:
            return None

    @staticmethod
    def _crl_signature_valid(
        crl: x509.CertificateRevocationList, issuer: x509.Certificate
    ) -> bool:
        try:
            return crl.is_signature_valid(
                cast("CertificateIssuerPublicKeyTypes", issuer.public_key())
            )
        except Exception:  # noqa: BLE001
            return False


def _der_encoding() -> Encoding:
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _crl_this_update(crl: x509.CertificateRevocationList) -> datetime | None:
    return _as_utc(getattr(crl, "last_update_utc", None) or getattr(crl, "last_update", None))


def _crl_next_update(crl: x509.CertificateRevocationList) -> datetime | None:
    return _as_utc(getattr(crl, "next_update_utc", None) or getattr(crl, "next_update", None))


__all__ = ["RevocationChecker", "RevocationOutcome"]
