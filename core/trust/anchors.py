"""Kho NEO TIN CẬY — nạp chứng thư gốc NEAC + các CA công cộng.

Neo tin cậy (trust anchor) = chứng thư gốc mà ta tin tuyệt đối. Với Việt Nam,
gốc là Vietnam National Root CA do NEAC phát hành. Kho này cũng chứa chứng thư
trung gian của 26 CA công cộng để dựng đường dẫn tin cậy.

⚠️ Chứng thư trong kho PHẢI được tải từ nguồn chính thức (rootca.gov.vn / NEAC)
và xác minh thủ công (vân tay) trước khi đưa vào ``data/trust_store/`` — KHÔNG
tải tự động rồi tin ngay. Xem ``data/trust_store/README.md``.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509

from core.config import trust_store_dir

_CERT_SUFFIXES = (".der", ".pem", ".crt", ".cer")


def load_certificate(data: bytes) -> x509.Certificate | None:
    """Nạp một chứng thư từ bytes, thử DER rồi PEM. None nếu không parse được."""
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return None


def _is_self_issued(cert: x509.Certificate) -> bool:
    """Chứng thư tự phát hành (subject == issuer) — ứng viên neo gốc."""
    return cert.subject == cert.issuer


class TrustAnchorStore:
    """Tập chứng thư tin cậy: neo gốc (self-signed) + trung gian.

    Cung cấp chỉ mục theo Subject để chain building tìm chứng thư phát hành.
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        self.store_dir = store_dir or trust_store_dir()
        self._certs: list[x509.Certificate] = []
        self._by_subject: dict[bytes, list[x509.Certificate]] = {}
        self._anchor_subjects: set[bytes] = set()
        self._load()

    def _load(self) -> None:
        if not self.store_dir.is_dir():
            return
        for path in sorted(self.store_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in _CERT_SUFFIXES:
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                cert = load_certificate(data)
                if cert is not None:
                    self._register(cert)

    def _register(self, cert: x509.Certificate) -> None:
        self._certs.append(cert)
        key = cert.subject.public_bytes()
        self._by_subject.setdefault(key, []).append(cert)
        if _is_self_issued(cert):
            self._anchor_subjects.add(key)

    # -- Truy vấn -------------------------------------------------------- #
    @property
    def is_empty(self) -> bool:
        return not self._certs

    @property
    def certificates(self) -> list[x509.Certificate]:
        return list(self._certs)

    def anchors(self) -> list[x509.Certificate]:
        """Các neo gốc (chứng thư tự phát hành trong kho)."""
        return [c for c in self._certs if c.subject.public_bytes() in self._anchor_subjects]

    def issuers_of(self, cert: x509.Certificate) -> list[x509.Certificate]:
        """Các chứng thư trong kho có Subject == Issuer của ``cert`` (ứng viên cha)."""
        return list(self._by_subject.get(cert.issuer.public_bytes(), []))

    def is_trust_anchor(self, cert: x509.Certificate) -> bool:
        """``cert`` có phải neo gốc trong kho không (so theo Subject + tự phát hành)."""
        return (
            cert.subject.public_bytes() in self._anchor_subjects
            and _is_self_issued(cert)
        )

    def add_intermediates(self, certs: list[x509.Certificate]) -> None:
        """Nạp thêm chứng thư trung gian (vd. lấy từ token) vào chỉ mục tạm."""
        for cert in certs:
            self._register(cert)


__all__ = ["TrustAnchorStore", "load_certificate"]
