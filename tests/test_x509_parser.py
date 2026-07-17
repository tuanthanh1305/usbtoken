"""Test x509_parser: trích đủ trường + định danh VN KHOAN DUNG (không raise)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from core import x509_parser


def _make_cert(subject_extra: list[x509.NameAttribute] | None = None) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
             x509.NameAttribute(NameOID.COMMON_NAME, "Nguyen Van A")]
    attrs.extend(subject_extra or [])
    subject = x509.Name(attrs)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VN Public CA")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                       critical=False)
        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://crl.example.vn/ca.crl")],
            relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
        .add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier("http://ocsp.example.vn")),
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier("http://aia.example.vn/ca.crt")),
        ]), critical=False)
    )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)


def test_parse_full_fields() -> None:
    der = _make_cert()
    info = x509_parser.parse(der)
    assert info.subject_raw and info.issuer_raw
    assert info.serial_number
    assert info.is_expired is False and (info.days_remaining or 0) > 300
    assert info.public_key_algo == "RSA" and info.key_size == 2048
    import hashlib
    assert info.sha256_thumbprint == hashlib.sha256(der).hexdigest()
    assert info.ski and info.aki
    assert info.crl_dp_urls == ["http://crl.example.vn/ca.crl"]
    assert info.ocsp_urls == ["http://ocsp.example.vn"]
    assert info.aia_urls == ["http://aia.example.vn/ca.crt"]
    assert "digital_signature" in info.key_usage
    assert info.basic_constraints.ca is False


def test_vn_org_tax_code_with_context() -> None:
    # serialNumber (OID 2.5.4.5) mang MST -> ngữ cảnh mạnh.
    der = _make_cert([x509.NameAttribute(NameOID.SERIAL_NUMBER, "MST:0101243150")])
    info = x509_parser.parse(der)
    assert "0101243150" in info.vn_ids.get("org_tax_code", [])
    assert info.profile_confidence == "medium"  # có ngữ cảnh MST
    assert any(r["oid"] == "2.5.4.5" for r in info.subject_rdns)  # RDN thô để audit


def test_vn_org_tax_code_13_digit_hyphen() -> None:
    der = _make_cert([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CT ABC 0101243150-001")])
    info = x509_parser.parse(der)
    assert "0101243150-001" in info.vn_ids.get("org_tax_code", [])


def test_vn_personal_id_12_digit() -> None:
    der = _make_cert([x509.NameAttribute(NameOID.SERIAL_NUMBER, "CCCD:012345678901")])
    info = x509_parser.parse(der)
    assert "012345678901" in info.vn_ids.get("personal_id", [])
    assert info.profile_confidence == "medium"


def test_no_vn_id_gives_empty_and_warning() -> None:
    der = _make_cert()  # chỉ CN=Nguyen Van A
    info = x509_parser.parse(der)
    assert info.vn_ids == {}
    assert info.profile_confidence == "unknown"
    assert any("CHƯA nhận diện" in w for w in info.warnings)


def test_garbage_der_no_raise() -> None:
    info = x509_parser.parse(b"not a certificate at all")
    assert info.subject_raw == ""  # không parse được
    assert info.profile_confidence == "unknown"
    assert info.warnings  # có cảnh báo, KHÔNG raise


def test_not_before_is_timezone_aware() -> None:
    info = x509_parser.parse(_make_cert())
    assert info.not_before is not None and info.not_before.tzinfo is not None
