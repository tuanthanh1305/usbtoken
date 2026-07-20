"""Test KHO NEO TIN CẬY: find_issuer (AKI/SKI + DN), tên CA từ chứng thư,
is_stale, và anti-tamper bằng chữ ký Ed25519 (fail-closed)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.trust import signing
from core.trust import store as store_mod
from tests.certs import _make, make_chain


def _write(dir_: Path, rel: str, data: bytes) -> Path:
    p = dir_ / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


# --------------------------------------------------------------------------- #
# find_issuer — yêu cầu bắt buộc của prompt                                     #
# --------------------------------------------------------------------------- #
def test_find_issuer_returns_correct_ca(tmp_path: Path) -> None:
    root = _make("VN Root CA", None, is_ca=True, with_keyids=True)
    ca = _make("FPT-CA Public", root, is_ca=True, with_keyids=True)
    subscriber = _make("Nguyen Van A", ca, is_ca=False, with_keyids=True)

    _write(tmp_path, "root/root.der", root.der)
    _write(tmp_path, "ca/fptca.der", ca.der)
    store = store_mod.load(tmp_path, verify_signature=False)

    issuer = store.find_issuer(subscriber.cert)
    assert issuer is not None
    assert issuer.subject_dn == ca.cert.subject.rfc4514_string()
    # Không nhầm sang Root (Root không phải người cấp trực tiếp).
    assert issuer.subject_dn != root.cert.subject.rfc4514_string()


def test_find_issuer_by_dn_when_no_keyids(tmp_path: Path) -> None:
    root, ca, leaf = make_chain()  # không có SKI/AKI
    _write(tmp_path, "ca/inter.der", ca.der)
    _write(tmp_path, "root/root.der", root.der)
    store = store_mod.load(tmp_path, verify_signature=False)
    issuer = store.find_issuer(leaf.cert)
    assert issuer is not None
    assert issuer.subject_dn == ca.cert.subject.rfc4514_string()


def test_find_issuer_none_when_absent(tmp_path: Path) -> None:
    _root, ca, leaf = make_chain()
    _write(tmp_path, "ca/inter.der", ca.der)  # thiếu... thực ra có inter
    # Xoá inter khỏi kho: dùng kho chỉ có root
    other = _make("Unrelated Root", None, is_ca=True)
    empty = tmp_path / "empty"
    _write(empty, "root/root.der", other.der)
    store = store_mod.load(empty, verify_signature=False)
    assert store.find_issuer(leaf.cert) is None


def test_get_ca_display_name_from_cert(tmp_path: Path) -> None:
    ca = _make("Viettel-CA", None, is_ca=True)
    assert store_mod.TrustStore.get_ca_display_name(ca.cert) == "Viettel-CA"


# --------------------------------------------------------------------------- #
# is_stale                                                                     #
# --------------------------------------------------------------------------- #
def test_is_stale_without_manifest(tmp_path: Path) -> None:
    root = _make("VN Root CA", None, is_ca=True)
    _write(tmp_path, "root/root.der", root.der)
    store = store_mod.load(tmp_path, verify_signature=False)
    stale, reasons = store.is_stale()
    assert stale is True
    assert any("đồng bộ" in r for r in reasons)


# --------------------------------------------------------------------------- #
# Anti-tamper: chữ ký Ed25519 + sha256 (fail-closed)                            #
# --------------------------------------------------------------------------- #
def _make_signed_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, certs: dict[str, bytes]):  # type: ignore[no-untyped-def]
    priv, pub = signing.generate_keypair()
    pub_path = tmp_path / "pub.pem"
    signing.save_public_key(pub, pub_path)
    # Ghim khoá công khai (monkeypatch để không đụng repo).
    monkeypatch.setattr(store_mod, "trust_signing_pub_path", lambda: pub_path)

    store_dir = tmp_path / "current"
    files = []
    import hashlib

    for rel, data in certs.items():
        _write(store_dir, rel, data)
        files.append({"name": rel, "role": rel.split("/")[0], "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {
        "version": 1,
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "source": "https://rootca.gov.vn",
        "files": files,
    }
    raw = signing.canonical_bytes(manifest)
    (store_dir / "manifest.json").write_bytes(raw)
    (store_dir / "manifest.sig").write_bytes(signing.sign(priv, raw))
    return store_dir


def test_signed_store_verified_and_usable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _make("VN Root CA", None, is_ca=True)
    store_dir = _make_signed_store(tmp_path, monkeypatch, {"root/root.der": root.der})
    store = store_mod.load(store_dir, verify_signature=True)
    assert store.verified is True
    assert store.is_usable is True


def test_tampered_store_not_verified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _make("VN Root CA", None, is_ca=True)
    store_dir = _make_signed_store(tmp_path, monkeypatch, {"root/root.der": root.der})
    # Sửa nội dung file cert sau khi đã ký -> sha256 lệch -> KHÔNG verify.
    (store_dir / "root/root.der").write_bytes(root.der + b"\x00tampered")
    store = store_mod.load(store_dir, verify_signature=True)
    assert store.verified is False
    assert store.is_usable is False  # fail-closed


def test_injected_unlisted_cert_breaks_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # REGRESSION: kẻ tấn công THÊM một neo gốc giả KHÔNG có trong manifest. Chữ ký
    # manifest vẫn hợp lệ, file cũ vẫn khớp sha256 — nhưng kho PHẢI bị coi là KHÔNG
    # verify (nếu không, evil root sẽ trở thành neo tin cậy).
    root = _make("VN Root CA", None, is_ca=True)
    evil = _make("Evil Root CA", None, is_ca=True)
    store_dir = _make_signed_store(tmp_path, monkeypatch, {"root/root.der": root.der})
    (store_dir / "root" / "evil.der").write_bytes(evil.der)  # chèn file ngoài manifest
    store = store_mod.load(store_dir, verify_signature=True)
    assert store.verified is False and store.is_usable is False  # fail-closed
    assert store.is_trust_anchor(evil.cert) is False or not store.verified


def test_empty_manifest_file_list_not_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Manifest có chữ ký hợp lệ nhưng danh sách file RỖNG -> không ràng buộc gì -> từ chối.
    root = _make("VN Root CA", None, is_ca=True)
    store_dir = _make_signed_store(tmp_path, monkeypatch, {"root/root.der": root.der})
    priv, pub = signing.generate_keypair()
    pub_path = tmp_path / "pub2.pem"
    signing.save_public_key(pub, pub_path)
    monkeypatch.setattr(store_mod, "trust_signing_pub_path", lambda: pub_path)
    manifest = {"version": 1, "synced_at": datetime.now(timezone.utc).isoformat(), "files": []}
    raw = signing.canonical_bytes(manifest)
    (store_dir / "manifest.json").write_bytes(raw)
    (store_dir / "manifest.sig").write_bytes(signing.sign(priv, raw))
    store = store_mod.load(store_dir, verify_signature=True)
    assert store.verified is False


def test_unsigned_store_not_usable(tmp_path: Path) -> None:
    root = _make("VN Root CA", None, is_ca=True)
    _write(tmp_path, "root/root.der", root.der)
    store = store_mod.load(tmp_path, verify_signature=True)
    assert store.verified is False
    assert store.is_usable is False  # không ký -> không dùng được (fail-closed)


def test_signing_sign_verify_roundtrip() -> None:
    priv, pub = signing.generate_keypair()
    data = b"trust-store-manifest"
    sig = signing.sign(priv, data)
    assert signing.verify(pub, data, sig) is True
    assert signing.verify(pub, data + b"x", sig) is False
