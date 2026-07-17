"""Tiện ích sinh chuỗi chứng thư X.509 THẬT trong bộ nhớ để test chain building.

Không phụ thuộc mạng hay chứng thư ngoài — tạo root/intermediate/leaf bằng
``cryptography`` và tự ký để kiểm tra logic dựng đường dẫn tin cậy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


@dataclass
class IssuedCert:
    cert: x509.Certificate
    key: rsa.RSAPrivateKey

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(Encoding.DER)


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _make(
    subject_cn: str,
    issuer: IssuedCert | None,
    *,
    is_ca: bool,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> IssuedCert:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _name(subject_cn)
    if issuer is None:  # self-signed root
        issuer_name = subject
        signing_key = key
    else:
        issuer_name = issuer.cert.subject
        signing_key = issuer.key

    now = datetime.now(timezone.utc)
    nb = not_before or (now - timedelta(days=1))
    na = not_after or (now + timedelta(days=365))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert = builder.sign(private_key=signing_key, algorithm=hashes.SHA256())
    return IssuedCert(cert=cert, key=key)


def make_chain() -> tuple[IssuedCert, IssuedCert, IssuedCert]:
    """Trả (root, intermediate, leaf) — leaf hợp lệ tại thời điểm hiện tại."""
    root = _make("VN Test Root CA", None, is_ca=True)
    inter = _make("VN Test Public CA", root, is_ca=True)
    leaf = _make("Nguyen Van A", inter, is_ca=False)
    return root, inter, leaf
