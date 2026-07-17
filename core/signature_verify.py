"""Kiểm tra CHỮ KÝ SỐ tách rời (detached) bằng khoá công khai trong chứng thư.

Thành phần cốt lõi của "phần mềm kiểm tra chữ ký số" (Điều 17 NĐ 23/2025): xác
minh một chữ ký so với dữ liệu gốc, dùng khoá công khai của chứng thư người ký.
Hỗ trợ RSA (PKCS#1 v1.5 và PSS), ECDSA, Ed25519/Ed448. FAIL-CLOSED: mọi lỗi/loại
khoá lạ đều trả ``False`` kèm lý do tiếng Việt (KHÔNG coi là hợp lệ khi nghi ngờ).

⚠️ Đây CHỈ kiểm tính toàn vẹn mật mã của chữ ký. Tính HỢP LỆ pháp lý của chứng
thư (chain tới NEAC, thu hồi, Phụ lục II) do ``core/trust/validator`` quyết định.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha1": hashes.SHA1,  # noqa: S303 - chỉ để tương thích chữ ký cũ; cảnh báo ở tầng trên
}


def _load(cert_der: bytes) -> x509.Certificate | None:
    try:
        return x509.load_der_x509_certificate(cert_der)
    except Exception:  # noqa: BLE001
        try:
            return x509.load_pem_x509_certificate(cert_der)
        except Exception:  # noqa: BLE001
            return None


def verify_detached(
    cert_der: bytes,
    data: bytes,
    signature: bytes,
    *,
    algorithm: str = "sha256",
    rsa_scheme: str = "pkcs1v15",
) -> tuple[bool, str]:
    """Kiểm ``signature`` có phải chữ ký hợp lệ của ``data`` không.

    Args:
        cert_der:   Chứng thư người ký (DER/PEM).
        data:       Dữ liệu gốc đã ký (bản rõ, KHÔNG băm sẵn).
        signature:  Chữ ký cần kiểm.
        algorithm:  Hàm băm: sha256 | sha384 | sha512 | sha1.
        rsa_scheme: Với RSA: pkcs1v15 (mặc định) | pss.

    Returns:
        ``(hợp_lệ, lý_do_tiếng_việt)``.
    """
    cert = _load(cert_der)
    if cert is None:
        return False, "Không đọc được chứng thư người ký (DER/PEM không hợp lệ)."
    pub = cert.public_key()
    algo = algorithm.lower()

    try:
        if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(signature, data)  # EdDSA tự băm nội bộ, không nhận hash ngoài
        elif isinstance(pub, rsa.RSAPublicKey):
            h = _HASHES.get(algo)
            if h is None:
                return False, f"Thuật toán băm không hỗ trợ: {algorithm}."
            if rsa_scheme.lower() == "pss":
                pad: padding.AsymmetricPadding = padding.PSS(
                    mgf=padding.MGF1(h()), salt_length=padding.PSS.MAX_LENGTH
                )
            else:
                pad = padding.PKCS1v15()
            pub.verify(signature, data, pad, h())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            h = _HASHES.get(algo)
            if h is None:
                return False, f"Thuật toán băm không hỗ trợ: {algorithm}."
            pub.verify(signature, data, ec.ECDSA(h()))
        else:
            return False, "Loại khoá công khai không hỗ trợ kiểm chữ ký."
    except InvalidSignature:
        return False, "Chữ ký KHÔNG khớp — dữ liệu đã bị sửa hoặc sai khoá/thuật toán."
    except UnsupportedAlgorithm as exc:
        return False, f"Thuật toán không được hỗ trợ: {exc}."
    except Exception as exc:  # noqa: BLE001 - fail-closed
        return False, f"Lỗi khi kiểm chữ ký: {exc}"
    return True, "Chữ ký HỢP LỆ so với khoá công khai trong chứng thư."


__all__ = ["verify_detached"]
