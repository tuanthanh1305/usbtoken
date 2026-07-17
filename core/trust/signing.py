"""Ký & xác thực KHO NEO TIN CẬY (chống sửa kho cục bộ).

Kho neo tin cậy là hạ tầng tin cậy quốc gia. Sau khi người vận hành áp dụng một
bản sync, manifest của kho được KÝ bằng khoá bí mật của dự án (Ed25519). Runtime
(``core/trust/store.py``) VERIFY chữ ký bằng khoá công khai GHIM SẴN phía code
trước khi tin kho — nếu ai sửa nội dung kho cục bộ mà không có khoá bí mật, chữ
ký sẽ không khớp và kho bị coi là KHÔNG hợp lệ (fail-closed).

Dùng Ed25519 (nhanh, khoá ngắn, an toàn). Khoá bí mật do người vận hành/build
giữ; KHÔNG commit vào repo.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_bytes(manifest: dict[str, Any]) -> bytes:
    """Chuỗi hoá manifest theo dạng CHUẨN TẮC (ổn định) để ký/verify nhất quán."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Sinh / nạp / lưu khoá                                                         #
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def save_private_key(priv: Ed25519PrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        path.chmod(0o600)  # hạn chế quyền đọc khoá bí mật
    except OSError:
        pass


def save_public_key(pub: Ed25519PublicKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key(path: Path) -> Ed25519PrivateKey | None:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        return None
    return key if isinstance(key, Ed25519PrivateKey) else None


def load_public_key(path: Path) -> Ed25519PublicKey | None:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError):
        return None
    return key if isinstance(key, Ed25519PublicKey) else None


# --------------------------------------------------------------------------- #
# Ký / verify                                                                  #
# --------------------------------------------------------------------------- #
def sign(priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)


def verify(pub: Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, data)
        return True
    except InvalidSignature:
        return False


__all__ = [
    "canonical_bytes",
    "generate_keypair",
    "save_private_key",
    "save_public_key",
    "load_private_key",
    "load_public_key",
    "sign",
    "verify",
]
