"""KHO NEO TIN CẬY — module QUAN TRỌNG NHẤT VỀ MẶT PHÁP LÝ.

TT 15/2025 Điều 5 buộc phần mềm "hỗ trợ cài đặt, tích hợp, cập nhật chứng thư số
của NEAC, các CA công cộng và Danh sách tin cậy nước ngoài". Kho này là ĐẦU VÀO
của chain building; không có kho HỢP LỆ thì hệ thống PHẢI **fail-closed** (từ
chối ký, từ chối báo "hợp lệ").

Thiết kế:
    * Chứng thư gốc NEAC = NEO TIN CẬY DUY NHẤT.
    * find_issuer so khớp bằng AKI↔SKI và Issuer DN↔Subject DN (cấu trúc X.509),
      KHÔNG so chuỗi tên.
    * Tên CA lấy từ CHÍNH chứng thư CA đã xác thực (không đoán).
    * Kho được KÝ (Ed25519); ``load()`` verify chữ ký + sha256 từng file trước
      khi tin (chống sửa kho cục bộ).
    * Người vận hành có thể thêm neo nội bộ (CA chuyên dùng) — có nhật ký audit.

CLI: ``python -m core.trust.store --list --verify``
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from core.config import (
    current_trust_store_dir,
    trust_audit_log_path,
    trust_signing_pub_path,
    trust_store_internal_dir,
)

from .anchors import load_certificate
from .signing import load_public_key, verify

_CERT_SUFFIXES = (".der", ".pem", ".crt", ".cer")
_CRL_SUFFIXES = (".crl",)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ski(cert: x509.Certificate) -> bytes | None:
    """Subject Key Identifier (nếu có)."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return bytes(ext.value.digest)
    except x509.ExtensionNotFound:
        return None


def _aki(cert: x509.Certificate) -> bytes | None:
    """Authority Key Identifier (key_identifier, nếu có)."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        kid = ext.value.key_identifier
        return bytes(kid) if kid is not None else None
    except x509.ExtensionNotFound:
        return None


def _display_name(cert: x509.Certificate) -> str:
    """Tên hiển thị CA lấy từ CHÍNH chứng thư: CN, rồi O, rồi Subject DN."""
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = cert.subject.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return cert.subject.rfc4514_string()


@dataclass(slots=True)
class CertEntry:
    """Một chứng thư trong kho, kèm chỉ mục để so khớp phát hành."""

    cert: x509.Certificate
    role: str  # "root" | "ca" | "internal" | "foreign"
    source_path: str
    sha256: str
    subject_dn: str
    issuer_dn: str
    serial_hex: str
    ski: bytes | None
    aki: bytes | None
    not_before: datetime
    not_after: datetime
    ca_name: str

    @property
    def is_self_issued(self) -> bool:
        return self.cert.subject == self.cert.issuer

    def is_time_valid(self, at: datetime | None = None) -> bool:
        now = at or _utcnow()
        return self.not_before <= now <= self.not_after


@dataclass(slots=True)
class CrlEntry:
    """Một CRL trong kho."""

    crl: x509.CertificateRevocationList
    source_path: str
    sha256: str
    issuer_dn: str
    this_update: datetime
    next_update: datetime | None


@dataclass(slots=True)
class TrustStore:
    """Kho neo tin cậy đã nạp: root + CA + CRL + danh sách nước ngoài + provenance."""

    store_dir: Path
    entries: list[CertEntry] = field(default_factory=list)
    crls: list[CrlEntry] = field(default_factory=list)
    synced_at: datetime | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    verified: bool = False
    verification_reason: str = ""

    # -- Nhóm truy vấn -------------------------------------------------- #
    @property
    def root_cert(self) -> x509.Certificate | None:
        for e in self.entries:
            if e.role == "root":
                return e.cert
        # Suy luận: chứng thư tự phát hành duy nhất cũng coi là gốc.
        self_issued = [e for e in self.entries if e.is_self_issued]
        return self_issued[0].cert if self_issued else None

    @property
    def ca_certs(self) -> list[x509.Certificate]:
        return [e.cert for e in self.entries if e.role in ("ca", "root", "internal")]

    @property
    def foreign_trusted_list(self) -> list[x509.Certificate]:
        return [e.cert for e in self.entries if e.role == "foreign"]

    @property
    def is_empty(self) -> bool:
        return not self.entries

    @property
    def is_usable(self) -> bool:
        """Kho có DÙNG ĐƯỢC để kiểm tra/ký không (fail-closed).

        Yêu cầu: không rỗng, có neo gốc, và ĐÃ verify chữ ký. Thiếu bất kỳ điều
        kiện nào -> KHÔNG dùng được (hệ thống phải từ chối, không fail-open).
        """
        return bool(self.entries) and self.root_cert is not None and self.verified

    # -- Nghiệp vụ ------------------------------------------------------ #
    def find_issuer(self, cert: x509.Certificate) -> CertEntry | None:
        """Tìm chứng thư CA đã cấp ``cert``.

        So khớp bằng AKI↔SKI và Issuer DN↔Subject DN (cấu trúc X.509), KHÔNG so
        chuỗi tên. Ưu tiên khớp cả AKI lẫn DN; nếu chứng thư không có AKI thì
        khớp theo DN.
        """
        target_aki = _aki(cert)
        dn_fallback: CertEntry | None = None
        for entry in self.entries:
            if entry.cert.subject != cert.issuer:
                continue  # DN phát hành không khớp -> loại
            if target_aki is not None and entry.ski is not None:
                if target_aki == entry.ski:
                    return entry  # khớp mạnh: DN + AKI/SKI
                continue  # DN khớp nhưng khoá khác -> không phải cha thật
            # Không có AKI/SKI để phân biệt -> giữ làm phương án theo DN.
            dn_fallback = dn_fallback or entry
        return dn_fallback

    def is_trust_anchor(self, cert: x509.Certificate) -> bool:
        """``cert`` có phải NEO GỐC trong kho không.

        Neo gốc = chứng thư gốc NEAC (``role="root"``) hoặc neo nội bộ do người
        vận hành ghim (``role="internal"``). So khớp bằng vân tay SHA-256 (mật mã),
        KHÔNG so chuỗi tên. Danh sách nước ngoài (``role="foreign"``) KHÔNG phải
        neo gốc NEAC — xử lý riêng ở tầng validator.
        """
        fp = cert.fingerprint(hashes.SHA256())
        for entry in self.entries:
            if entry.role in ("root", "internal") and entry.cert.fingerprint(hashes.SHA256()) == fp:
                return True
        return False

    @staticmethod
    def get_ca_display_name(ca_cert: x509.Certificate) -> str:
        """Tên CA lấy TỪ CHÍNH chứng thư CA đã xác thực (không đoán)."""
        return _display_name(ca_cert)

    def is_stale(self, max_age: timedelta = timedelta(days=7)) -> tuple[bool, list[str]]:
        """Cảnh báo nếu kho quá cũ hoặc CRL đã hết hạn (kết quả kém tin cậy)."""
        reasons: list[str] = []
        now = _utcnow()
        if self.synced_at is None:
            reasons.append("Không rõ thời điểm đồng bộ kho (thiếu manifest).")
        elif now - self.synced_at > max_age:
            age = now - self.synced_at
            reasons.append(f"Kho đã đồng bộ cách đây {age.days} ngày (> {max_age.days} ngày).")
        for crl in self.crls:
            if crl.next_update is not None and crl.next_update < now:
                reasons.append(
                    f"CRL của '{crl.issuer_dn}' đã hết hạn "
                    f"(nextUpdate {crl.next_update.isoformat()}) — kiểm tra thu hồi không đáng tin."
                )
        return (bool(reasons), reasons)

    def add_internal_anchor(
        self, cert_der: bytes, *, note: str, operator: str = ""
    ) -> CertEntry:
        """Thêm neo tin cậy NỘI BỘ (CA chuyên dùng) — có ghi nhật ký audit.

        Không thay chứng thư gốc NEAC; chỉ bổ sung neo cho hạ tầng nội bộ. Ghi
        file vào thư mục internal + một dòng audit (chủ đích, có dấu vết).
        """
        cert = load_certificate(cert_der)
        if cert is None:
            raise ValueError("Dữ liệu không phải chứng thư X.509 hợp lệ.")
        sha = _sha256_hex(cert_der)
        internal_dir = trust_store_internal_dir()
        internal_dir.mkdir(parents=True, exist_ok=True)
        dest = internal_dir / f"internal_{sha[:16]}.der"
        dest.write_bytes(cert_der)

        entry = _build_entry(cert, role="internal", source_path=str(dest), sha256=sha)
        self.entries.append(entry)
        _append_audit(
            {
                "ts": _utcnow().isoformat(),
                "action": "add_internal_anchor",
                "subject": entry.subject_dn,
                "sha256": sha,
                "operator": operator,
                "note": note,
            }
        )
        return entry


def _build_entry(
    cert: x509.Certificate, *, role: str, source_path: str, sha256: str
) -> CertEntry:
    return CertEntry(
        cert=cert,
        role=role,
        source_path=source_path,
        sha256=sha256,
        subject_dn=cert.subject.rfc4514_string(),
        issuer_dn=cert.issuer.rfc4514_string(),
        serial_hex=format(cert.serial_number, "x"),
        ski=_ski(cert),
        aki=_aki(cert),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        ca_name=_display_name(cert),
    )


def _append_audit(record: dict[str, Any]) -> None:
    path = trust_audit_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Nạp kho từ đĩa                                                               #
# --------------------------------------------------------------------------- #
def _role_from_path(store_dir: Path, path: Path) -> str:
    """Suy vai trò từ thư mục con (root/ca/foreign/internal)."""
    try:
        rel = path.relative_to(store_dir)
    except ValueError:
        return "ca"
    top = rel.parts[0] if rel.parts else ""
    return {"root": "root", "ca": "ca", "foreign": "foreign", "internal": "internal"}.get(
        top, "ca"
    )


def load(store_dir: Path | None = None, *, verify_signature: bool = True) -> TrustStore:
    """Nạp kho neo tin cậy từ đĩa (mặc định ``data/trust_store/current``).

    Đọc chứng thư + CRL, dựng chỉ mục, đọc manifest (provenance + synced_at) và
    VERIFY chữ ký kho bằng khoá công khai ghim sẵn. Kho không verify được -> vẫn
    nạp dữ liệu nhưng ``verified=False`` (tầng trên phải fail-closed).
    """
    directory = store_dir or current_trust_store_dir()
    store = TrustStore(store_dir=directory)
    if not directory.is_dir():
        store.verification_reason = "Thư mục kho không tồn tại."
        return store

    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in _CERT_SUFFIXES:
            data = _safe_read(path)
            if data is None:
                continue
            cert = load_certificate(data)
            if cert is not None:
                store.entries.append(
                    _build_entry(
                        cert,
                        role=_role_from_path(directory, path),
                        source_path=str(path),
                        sha256=_sha256_hex(data),
                    )
                )
        elif suffix in _CRL_SUFFIXES:
            data = _safe_read(path)
            if data is None:
                continue
            crl = _load_crl(data)
            if crl is not None:
                store.crls.append(
                    CrlEntry(
                        crl=crl,
                        source_path=str(path),
                        sha256=_sha256_hex(data),
                        issuer_dn=crl.issuer.rfc4514_string(),
                        this_update=crl.last_update_utc,
                        next_update=crl.next_update_utc,
                    )
                )

    _load_manifest(store, directory, verify_signature=verify_signature)
    return store


def _safe_read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _load_crl(data: bytes) -> x509.CertificateRevocationList | None:
    try:
        return x509.load_der_x509_crl(data)
    except ValueError:
        pass
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return None


def _load_manifest(store: TrustStore, directory: Path, *, verify_signature: bool) -> None:
    """Đọc manifest + provenance, verify chữ ký + sha256 từng file."""
    manifest_path = directory / "manifest.json"
    sig_path = directory / "manifest.sig"
    if not manifest_path.is_file():
        store.verification_reason = "Thiếu manifest.json — kho chưa được sync/ký."
        return

    raw = _safe_read(manifest_path)
    if raw is None:
        store.verification_reason = "Không đọc được manifest.json."
        return
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError:
        store.verification_reason = "manifest.json hỏng."
        return

    store.provenance = manifest
    synced = manifest.get("synced_at")
    if isinstance(synced, str):
        try:
            store.synced_at = datetime.fromisoformat(synced)
        except ValueError:
            store.synced_at = None

    if not verify_signature:
        return

    # 1) Khoá công khai ghim sẵn phía code.
    pub = load_public_key(trust_signing_pub_path())
    if pub is None:
        store.verification_reason = (
            "Thiếu khoá công khai ghim sẵn (data/trust_signing_pub.pem) — không verify được."
        )
        return
    # 2) Chữ ký manifest.
    sig = _safe_read(sig_path) if sig_path.is_file() else None
    if sig is None:
        store.verification_reason = "Thiếu manifest.sig."
        return
    if not verify(pub, raw, sig):
        store.verification_reason = "Chữ ký manifest KHÔNG hợp lệ (kho có thể đã bị sửa)."
        return
    # 3) sha256 từng file khớp manifest.
    if not _verify_file_hashes(directory, manifest):
        store.verification_reason = "sha256 của file trong kho không khớp manifest."
        return

    store.verified = True
    store.verification_reason = "OK"


def _verify_file_hashes(directory: Path, manifest: dict[str, Any]) -> bool:
    """Verify sha256 mọi file trong manifest VÀ mọi cert/CRL trên đĩa phải có trong
    manifest (chống CHÈN neo tin cậy lạ vào kho đã ký).
    """
    files = manifest.get("files") or []
    if not files:
        return False  # manifest RỖNG không ràng buộc gì -> từ chối (fail-closed)

    manifest_names: set[str] = set()
    for item in files:
        name = item.get("name")
        expected = item.get("sha256")
        if not name or not expected:
            return False
        target = directory / name
        data = _safe_read(target)
        if data is None or _sha256_hex(data) != expected:
            return False
        manifest_names.add(str(name).replace("\\", "/"))

    # ⭐ Mọi file chứng thư/CRL TỒN TẠI TRÊN ĐĨA phải nằm trong manifest đã ký.
    # Nếu không, kẻ tấn công có thể THÊM một neo gốc giả (không có trong manifest)
    # mà chữ ký manifest vẫn hợp lệ -> phá gốc tin cậy.
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix.lower() in (_CERT_SUFFIXES + _CRL_SUFFIXES):
            rel = path.relative_to(directory).as_posix()
            if rel not in manifest_names:
                return False
    return True


# --------------------------------------------------------------------------- #
# CLI: python -m core.trust.store --list --verify                             #
# --------------------------------------------------------------------------- #
def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m core.trust.store")
    parser.add_argument("--list", action="store_true", help="Liệt kê chứng thư/CRL trong kho.")
    parser.add_argument("--verify", action="store_true", help="Verify chữ ký + sha256 kho.")
    parser.add_argument("--store-dir", default="", help="Đường dẫn kho (mặc định current/).")
    args = parser.parse_args(argv)

    directory = Path(args.store_dir) if args.store_dir else None
    store = load(directory, verify_signature=True)

    print(f"Kho: {store.store_dir}")
    print(f"  Chứng thư: {len(store.entries)} · CRL: {len(store.crls)}")
    root = store.root_cert
    print(f"  Neo gốc  : {root.subject.rfc4514_string() if root else '(KHÔNG có)'}")
    if store.synced_at:
        print(f"  Đồng bộ  : {store.synced_at.isoformat()}")
    stale, reasons = store.is_stale()
    print(f"  Cũ?      : {'CÓ' if stale else 'không'}")
    for r in reasons:
        print(f"     ⚠ {r}")

    if args.verify:
        print(f"  Verify   : {'✅ HỢP LỆ' if store.verified else '⚠️ KHÔNG hợp lệ'} — {store.verification_reason}")
        print(f"  Dùng được: {'CÓ' if store.is_usable else 'KHÔNG (fail-closed)'}")

    if args.list:
        print("  --- Chứng thư ---")
        for e in store.entries:
            valid = "hiệu lực" if e.is_time_valid() else "HẾT HẠN"
            print(f"   • [{e.role}] {e.ca_name} · {valid} · SN={e.serial_hex}")
            print(f"       subject={e.subject_dn}")

    # Mã thoát: 0 nếu kho dùng được, 1 nếu không (tiện script CI).
    return 0 if store.is_usable else 1


if __name__ == "__main__":
    import sys

    sys.exit(_main())


__all__ = ["TrustStore", "CertEntry", "CrlEntry", "load"]
