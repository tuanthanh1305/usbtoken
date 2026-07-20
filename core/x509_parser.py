"""Parser X.509 -> :class:`CertInfo` — OS-agnostic (cryptography + asn1crypto).

Trích: subject/issuer (RFC4514), serial, hiệu lực, key_usage, EKU,
basic_constraints, vân tay SHA-1/256, thuật toán khoá + độ dài, SKI, AKI, AIA,
CRL-DP, OCSP (các trường này là ĐẦU VÀO BẮT BUỘC cho chain building + kiểm thu
hồi ở PROMPT 9).

⚠️ ĐỊNH DANH VIỆT NAM — PROFILE CHƯA XÁC MINH -> THIẾT KẾ KHOAN DUNG:
    * Bóc MỌI RDN (kể cả OID lạ 1.3.6.1.4.1.<PEN>.*), giữ raw tất cả.
    * Chạy NHIỀU mẫu (MST tổ chức 10/10-3 · định danh cá nhân 12 · CMND cũ 9);
      xét ngữ cảnh (MST/TAX/VAT · CCCD/CMND/SDDCN/ID) để ước lượng độ tin cậy.
    * LUÔN giữ ``subject_raw`` + ``subject_rdns`` nguyên vẹn để audit.
    * KHÔNG BAO GIỜ raise khi không khớp -> ``vn_ids={}`` + cảnh báo "profile
      chưa nhận diện" + ``profile_confidence`` để cấp trên biết độ chắc.
    * TUYỆT ĐỐI KHÔNG coi các regex này là chuẩn — phải xác minh bằng chứng thư
      thật/văn bản NEAC (PROMPT 17).

Xử lý an toàn cryptography >=42 (``not_valid_before_utc``) lẫn <42
(``not_valid_before`` naive -> gán UTC).
"""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from core.models import BasicConstraints, CertInfo

# --- Mẫu định danh VN (KHOAN DUNG — chưa xác minh profile) ------------------ #
_RE_ORG_TAX = re.compile(r"(?<!\d)(\d{10}(?:-\d{3})?)(?!\d)")
_RE_PERSONAL = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_RE_OLD_ID = re.compile(r"(?<!\d)(\d{9})(?!\d)")

_CTX_ORG = ("mst", "tax", "vat", "tin")
_CTX_PERSONAL = ("cccd", "cmnd", "sddcn", "can cuoc", "căn cước", "id")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _not_before(cert: x509.Certificate) -> datetime | None:
    # cryptography >=42: *_utc (aware); <42: * (naive) -> gán UTC.
    dt = getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)
    return _as_utc(dt)


def _not_after(cert: x509.Certificate) -> datetime | None:
    dt = getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)
    return _as_utc(dt)


# --------------------------------------------------------------------------- #
# RDN thô (asn1crypto) — bóc MỌI OID kể cả lạ                                   #
# --------------------------------------------------------------------------- #
def _raw_rdns(der: bytes) -> list[dict[str, str]]:
    """Trả mọi thuộc tính Subject dạng [{oid, value}] — không bỏ sót OID lạ."""
    out: list[dict[str, str]] = []
    try:
        from asn1crypto import x509 as a_x509

        cert = a_x509.Certificate.load(der)
        for rdn in cert.subject.chosen:  # RDNSequence
            for atv in rdn:  # AttributeTypeAndValue (multi-valued RDN)
                oid = atv["type"].dotted
                try:
                    value = str(atv["value"].native)
                except Exception:  # noqa: BLE001
                    value = repr(atv["value"].contents)
                out.append({"oid": oid, "value": value})
    except Exception:  # noqa: BLE001 - không bao giờ raise
        pass
    return out


def _extract_vn_ids(
    subject_raw: str, rdns: list[dict[str, str]]
) -> tuple[dict[str, list[str]], str, list[str]]:
    """Trích định danh VN theo NHIỀU mẫu. Trả (vn_ids, confidence, warnings).

    Quét từng RDN (ưu tiên) + toàn bộ subject. Có ngữ cảnh -> confidence cao hơn.
    """
    found: dict[str, set[str]] = {"org_tax_code": set(), "personal_id": set(), "old_id_card": set()}
    with_context = False

    def _scan(text: str, context_hint: str) -> None:
        nonlocal with_context
        ctx = (text + " " + context_hint).lower()
        for m in _RE_ORG_TAX.finditer(text):
            found["org_tax_code"].add(m.group(1))
            if any(k in ctx for k in _CTX_ORG):
                with_context = True
        for m in _RE_PERSONAL.finditer(text):
            found["personal_id"].add(m.group(1))
            if any(k in ctx for k in _CTX_PERSONAL):
                with_context = True
        for m in _RE_OLD_ID.finditer(text):
            found["old_id_card"].add(m.group(1))

    # OID serialNumber = 2.5.4.5 thường mang MST — coi là ngữ cảnh mạnh.
    for rdn in rdns:
        hint = "mst" if rdn.get("oid") == "2.5.4.5" else rdn.get("oid", "")
        _scan(rdn.get("value", ""), hint)
    _scan(subject_raw, "")

    vn_ids = {k: sorted(v) for k, v in found.items() if v}
    warnings: list[str] = []
    if not vn_ids:
        confidence = "unknown"
        warnings.append(
            "Profile định danh Việt Nam CHƯA nhận diện được — cần xác minh bằng "
            "chứng thư thật từ nhiều CA hoặc văn bản NEAC. KHÔNG coi là chuẩn."
        )
    else:
        confidence = "medium" if with_context else "low"
        warnings.append(
            "Định danh VN là ƯỚC LƯỢNG (profile chưa xác minh) — giữ subject_raw để đối chiếu."
        )
    return vn_ids, confidence, warnings


# --------------------------------------------------------------------------- #
# Trích extension                                                              #
# --------------------------------------------------------------------------- #
def _key_usage(cert: x509.Certificate) -> list[str]:
    try:
        ku = cast(x509.KeyUsage, cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value)
    except x509.ExtensionNotFound:
        return []
    names = []
    for attr in (
        "digital_signature", "content_commitment", "key_encipherment",
        "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
    ):
        if getattr(ku, attr, False):
            names.append(attr)
    try:
        if ku.key_agreement and ku.encipher_only:
            names.append("encipher_only")
        if ku.key_agreement and ku.decipher_only:
            names.append("decipher_only")
    except ValueError:
        pass
    return names


def _eku(cert: x509.Certificate) -> list[str]:
    try:
        eku = cast(
            x509.ExtendedKeyUsage,
            cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value,
        )
    except x509.ExtensionNotFound:
        return []
    return [getattr(oid, "_name", None) or oid.dotted_string for oid in eku]


def _basic_constraints(cert: x509.Certificate) -> BasicConstraints:
    try:
        bc = cast(
            x509.BasicConstraints,
            cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value,
        )
        return BasicConstraints(ca=bool(bc.ca), path_length=bc.path_length)
    except x509.ExtensionNotFound:
        return BasicConstraints()


def _ski(cert: x509.Certificate) -> str:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return bytes(cast(x509.SubjectKeyIdentifier, ext.value).digest).hex()
    except x509.ExtensionNotFound:
        return ""


def _aki(cert: x509.Certificate) -> str:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        kid = cast(x509.AuthorityKeyIdentifier, ext.value).key_identifier
        return bytes(kid).hex() if kid else ""
    except x509.ExtensionNotFound:
        return ""


def _aia_ocsp(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    aia: list[str] = []
    ocsp: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    except x509.ExtensionNotFound:
        return aia, ocsp
    for desc in cast(x509.AuthorityInformationAccess, ext.value):
        loc = getattr(desc.access_location, "value", None)
        if not isinstance(loc, str):
            continue
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            aia.append(loc)
        elif desc.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp.append(loc)
    return aia, ocsp


def _crl_dps(cert: x509.Certificate) -> list[str]:
    urls: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except x509.ExtensionNotFound:
        return urls
    for dp in cast(x509.CRLDistributionPoints, ext.value):
        for name in dp.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


def _public_key(cert: x509.Certificate) -> tuple[str, int | None]:
    try:
        pk = cert.public_key()
    except Exception:  # noqa: BLE001
        return "", None
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"EC-{pk.curve.name}", pk.curve.key_size
    return type(pk).__name__, getattr(pk, "key_size", None)


# --------------------------------------------------------------------------- #
# API chính                                                                    #
# --------------------------------------------------------------------------- #
def parse(der: bytes) -> CertInfo:
    """Parse DER -> :class:`CertInfo`. KHÔNG BAO GIỜ raise (lỗi -> warnings)."""
    info = CertInfo(der_b64=base64.b64encode(der).decode("ascii"))
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # noqa: BLE001
        info.warnings.append(f"Không parse được chứng thư (DER không hợp lệ): {exc}")
        info.profile_confidence = "unknown"
        return info

    try:
        info.subject_raw = cert.subject.rfc4514_string()
        info.issuer_raw = cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        info.warnings.append("Không đọc được Subject/Issuer chuẩn — xem subject_rdns thô.")

    info.serial_number = format(cert.serial_number, "x")
    info.not_before = _not_before(cert)
    info.not_after = _not_after(cert)
    now = _now()
    if info.not_after is not None:
        info.is_expired = now > info.not_after
        info.days_remaining = (info.not_after - now).days
    info.sha1_thumbprint = hashlib.sha1(der).hexdigest()  # noqa: S324 - vân tay, không dùng bảo mật
    info.sha256_thumbprint = hashlib.sha256(der).hexdigest()

    _safe(lambda: info.key_usage.extend(_key_usage(cert)), info)
    _safe(lambda: info.extended_key_usage.extend(_eku(cert)), info)
    _safe(lambda: setattr(info, "basic_constraints", _basic_constraints(cert)), info)
    _safe(lambda: setattr(info, "ski", _ski(cert)), info)
    _safe(lambda: setattr(info, "aki", _aki(cert)), info)
    _safe(lambda: _set_aia(info, cert), info)
    _safe(lambda: info.crl_dp_urls.extend(_crl_dps(cert)), info)
    algo, size = _public_key(cert)
    info.public_key_algo, info.key_size = algo, size

    # Định danh VN (khoan dung, không raise).
    info.subject_rdns = _raw_rdns(der)
    vn_ids, confidence, warns = _extract_vn_ids(info.subject_raw, info.subject_rdns)
    info.vn_ids = vn_ids
    info.profile_confidence = confidence
    info.warnings.extend(warns)
    return info


def _set_aia(info: CertInfo, cert: x509.Certificate) -> None:
    aia, ocsp = _aia_ocsp(cert)
    info.aia_urls.extend(aia)
    info.ocsp_urls.extend(ocsp)


def _safe(fn: Any, info: CertInfo) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - lỗi 1 extension không hỏng cả parse
        info.warnings.append(f"Bỏ qua một extension do lỗi: {exc}")


__all__ = ["parse"]
