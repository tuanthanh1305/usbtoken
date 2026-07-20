"""Đồng bộ KHO NEO TIN CẬY từ nguồn chính thức rootca.gov.vn.

QUY TẮC AN TOÀN (hạ tầng tin cậy quốc gia):
    * CHỈ tải từ HTTPS thuộc miền rootca.gov.vn (verify TLS). Từ chối URL khác.
    * Ghi provenance cho TỪNG file: sha256 + thời điểm tải + URL nguồn.
    * Parse mỗi chứng thư -> index (subject/issuer/SKI/AKI/serial/hiệu lực/ca_name
      lấy từ CHÍNH chứng thư, không đoán).
    * Phát hiện thay đổi so với lần sync trước -> in diff rõ ràng.
    * KHÔNG tự động ghi đè kho đang dùng: ghi ra STAGING, yêu cầu người vận hành
      XÁC NHẬN (thay neo tin cậy phải có chủ đích).
    * Áp dụng xong -> KÝ manifest (Ed25519) để runtime verify (chống sửa cục bộ).

CLI:
    python -m tools.sync_trust_store --dry-run
    python -m tools.sync_trust_store --apply [--yes] [--signing-key PATH]
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import yaml
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.config import (
    current_trust_store_dir,
    trust_audit_log_path,
    trust_signing_pub_path,
    trust_sources_path,
    trust_store_staging_dir,
)
from core.trust import signing
from core.trust.anchors import load_certificate

_SUFFIX_BY_ROLE = {"root": ".der", "ca": ".der", "foreign": ".der", "crl": ".crl"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


@dataclass(slots=True)
class StagedFile:
    """Một file đã tải về staging kèm provenance."""

    role: str
    name: str  # đường dẫn tương đối trong kho, vd. "ca/FPT-CA.der"
    path: Path
    sha256: str
    url: str
    downloaded_at: str


# --------------------------------------------------------------------------- #
# Nguồn & kiểm tra URL                                                          #
# --------------------------------------------------------------------------- #
def load_sources(path: Path | None = None) -> tuple[str, list[dict[str, Any]]]:
    """Nạp sources.yaml -> (source_host, items)."""
    p = path or trust_sources_path()
    if not p.is_file():
        return "rootca.gov.vn", []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    host = str(data.get("source_host", "rootca.gov.vn"))
    items = data.get("items") or []
    return host, [dict(it) for it in items if isinstance(it, dict)]


def validate_url(url: str, host: str) -> tuple[bool, str]:
    """URL phải là HTTPS và thuộc đúng miền chính thức."""
    if not url:
        return False, "chưa cấu hình URL"
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False, "BẮT BUỘC HTTPS"
    netloc = parsed.hostname or ""
    if not (netloc == host or netloc.endswith("." + host)):
        return False, f"miền không hợp lệ (chỉ chấp nhận {host})"
    return True, ""


# --------------------------------------------------------------------------- #
# Tải (network) — tách riêng để phần còn lại test được offline                  #
# --------------------------------------------------------------------------- #
def download_all(
    items: list[dict[str, Any]], host: str, staging_dir: Path, *, timeout: float = 30.0
) -> tuple[list[StagedFile], list[str]]:
    """Tải mọi item hợp lệ vào staging. Trả (staged, errors)."""
    import httpx

    staged: list[StagedFile] = []
    errors: list[str] = []
    for item in items:
        role = str(item.get("role", "ca"))
        name = str(item.get("name", "unnamed"))
        url = str(item.get("url", "")).strip()

        ok, reason = validate_url(url, host)
        if not ok:
            errors.append(f"[{role}] {name}: {reason}")
            continue
        try:
            resp = httpx.get(url, timeout=timeout, verify=True, follow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"[{role}] {name}: lỗi tải ({exc})")
            continue
        if resp.status_code != 200:
            errors.append(f"[{role}] {name}: HTTP {resp.status_code}")
            continue

        data = resp.content
        rel = f"{role}/{name}{_SUFFIX_BY_ROLE.get(role, '.der')}"
        dest = staging_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        staged.append(
            StagedFile(
                role=role, name=rel, path=dest, sha256=_sha256_hex(data),
                url=url, downloaded_at=_utcnow().isoformat(),
            )
        )
    return staged, errors


# --------------------------------------------------------------------------- #
# Dựng manifest (thuần — test được offline)                                     #
# --------------------------------------------------------------------------- #
def build_manifest(
    staged: list[StagedFile], *, synced_at: datetime, source: str
) -> dict[str, Any]:
    """Dựng manifest từ danh sách file đã staging, kèm metadata parse được."""
    files: list[dict[str, Any]] = []
    for sf in staged:
        entry: dict[str, Any] = {
            "name": sf.name,
            "role": sf.role,
            "sha256": sf.sha256,
            "url": sf.url,
            "downloaded_at": sf.downloaded_at,
        }
        data = sf.path.read_bytes() if sf.path.is_file() else b""
        if sf.role == "crl":
            crl = _try_load_crl(data)
            if crl is not None:
                entry["issuer_dn"] = crl.issuer.rfc4514_string()
                nu = crl.next_update_utc
                entry["next_update"] = nu.isoformat() if nu else ""
        else:
            cert = load_certificate(data)
            if cert is not None:
                entry["subject_dn"] = cert.subject.rfc4514_string()
                entry["serial_hex"] = format(cert.serial_number, "x")
                entry["not_after"] = cert.not_valid_after_utc.isoformat()
                entry["ca_name"] = _cert_display_name(cert)
        files.append(entry)

    return {
        "version": 1,
        "synced_at": synced_at.isoformat(),
        "source": source,
        "files": files,
    }


def _cert_display_name(cert: x509.Certificate) -> str:
    from cryptography.x509.oid import NameOID

    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = cert.subject.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return cert.subject.rfc4514_string()


def _try_load_crl(data: bytes) -> x509.CertificateRevocationList | None:
    try:
        return x509.load_der_x509_crl(data)
    except ValueError:
        pass
    try:
        return x509.load_pem_x509_crl(data)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# So sánh với kho hiện tại (thuần)                                              #
# --------------------------------------------------------------------------- #
def read_current_manifest() -> dict[str, Any]:
    import json

    p = current_trust_store_dir() / "manifest.json"
    if not p.is_file():
        return {}
    try:
        return cast("dict[str, Any]", json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def diff_manifests(old: dict[str, Any], new: dict[str, Any]) -> dict[str, list[str]]:
    """So sánh hai manifest -> báo cáo thay đổi (CA mới / mất / đổi / CRL / hết hạn)."""
    def _certs(m: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for f in m.get("files", []) or []:
            if f.get("role") in ("ca", "root", "foreign") and f.get("subject_dn"):
                out[f["subject_dn"]] = f
        return out

    old_c, new_c = _certs(old), _certs(new)
    now = _utcnow()
    report: dict[str, list[str]] = {
        "new_ca": [], "removed_ca": [], "changed": [], "crl": [], "expired": [],
    }
    for subj, f in new_c.items():
        if subj not in old_c:
            report["new_ca"].append(f"{f.get('ca_name', subj)} ({subj})")
        elif f.get("sha256") != old_c[subj].get("sha256"):
            report["changed"].append(f"{f.get('ca_name', subj)} — sha256 thay đổi")
    for subj, f in old_c.items():
        if subj not in new_c:
            report["removed_ca"].append(f"{f.get('ca_name', subj)} ({subj})")
    for f in new.get("files", []) or []:
        if f.get("role") == "crl":
            report["crl"].append(f"CRL {f.get('issuer_dn', f.get('name'))} (nextUpdate {f.get('next_update', '?')})")
        na = f.get("not_after")
        if na:
            try:
                if datetime.fromisoformat(na) < now:
                    report["expired"].append(f"{f.get('ca_name', f.get('name'))} HẾT HẠN {na}")
            except ValueError:
                pass
    return report


def print_diff(report: dict[str, list[str]]) -> None:
    labels = {
        "new_ca": "CA MỚI", "removed_ca": "CA KHÔNG CÒN", "changed": "CA THAY ĐỔI",
        "crl": "CRL", "expired": "HẾT HẠN",
    }
    any_change = False
    for key, label in labels.items():
        rows = report.get(key, [])
        if rows:
            any_change = True
            print(f"  {label}:")
            for r in rows:
                print(f"    • {r}")
    if not any_change:
        print("  (không có thay đổi so với kho hiện tại)")


# --------------------------------------------------------------------------- #
# Áp dụng (ghi kho + ký)                                                        #
# --------------------------------------------------------------------------- #
def _obtain_signing_key(signing_key_path: str) -> Ed25519PrivateKey:
    """Lấy khoá ký: từ đường dẫn/biến môi trường, hoặc sinh khoá dev (kèm cảnh báo)."""
    import os

    from core.platform import get_adapter

    path = signing_key_path or os.environ.get("VN_ESIGN_TRUST_SIGNING_KEY", "")
    if path:
        priv = signing.load_private_key(Path(path))
        if priv is None:
            raise SystemExit(f"Không nạp được khoá ký Ed25519 từ: {path}")
    else:
        priv, _ = signing.generate_keypair()
        dev_path = get_adapter().config_dir() / "trust_signing_key.pem"
        signing.save_private_key(priv, dev_path)
        print(
            "⚠️  CHƯA có khoá ký — đã SINH KHOÁ DEV tại:\n"
            f"      {dev_path}\n"
            "    PRODUCTION phải dùng khoá do người vận hành/build quản lý (đặt qua\n"
            "    VN_ESIGN_TRUST_SIGNING_KEY) và ghim khoá công khai ở chế độ chỉ-đọc."
        )
    # Ghi/đồng bộ khoá công khai ghim sẵn để runtime verify.
    signing.save_public_key(priv.public_key(), trust_signing_pub_path())
    return priv


def apply_store(staged: list[StagedFile], manifest: dict[str, Any], signing_key_path: str) -> Path:
    """Ghi staging -> kho current/, ký manifest, ghi audit. Trả đường dẫn kho."""
    priv = _obtain_signing_key(signing_key_path)
    current = current_trust_store_dir()

    if current.exists():
        shutil.rmtree(current)
    current.mkdir(parents=True, exist_ok=True)

    for sf in staged:
        dest = current / sf.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sf.path, dest)

    raw = signing.canonical_bytes(manifest)
    (current / "manifest.json").write_bytes(raw)
    (current / "manifest.sig").write_bytes(signing.sign(priv, raw))

    _append_audit({
        "ts": _utcnow().isoformat(),
        "action": "apply_sync",
        "files": len(staged),
        "synced_at": manifest.get("synced_at"),
    })
    return current


def _append_audit(record: dict[str, Any]) -> None:
    import json

    path = trust_audit_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Orchestration + CLI                                                          #
# --------------------------------------------------------------------------- #
def run(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m tools.sync_trust_store")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Tải + so diff, KHÔNG áp dụng.")
    mode.add_argument("--apply", action="store_true", help="Áp dụng vào kho (cần xác nhận).")
    parser.add_argument("--yes", action="store_true", help="Bỏ qua hỏi xác nhận (khi --apply).")
    parser.add_argument("--sources", default="", help="Đường dẫn sources.yaml.")
    parser.add_argument("--signing-key", default="", help="Khoá ký Ed25519 (PEM).")
    args = parser.parse_args(argv)

    host, items = load_sources(Path(args.sources) if args.sources else None)
    if not items:
        print("Chưa cấu hình sources.yaml. Điền URL chính thức từ https://rootca.gov.vn.")
        return 2

    staging = trust_store_staging_dir()
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    print(f"Tải từ miền: {host} (HTTPS + verify TLS)")
    staged, errors = download_all(items, host, staging)
    print(f"Tải được: {len(staged)} file · Bỏ qua/lỗi: {len(errors)}")
    for e in errors:
        print(f"  ⚠ {e}")
    if not staged:
        print("Không tải được file nào (kiểm tra URL trong sources.yaml / mạng).")
        return 1

    manifest = build_manifest(staged, synced_at=_utcnow(), source=f"https://{host}")
    print("\n--- Provenance (sha256 · nguồn) ---")
    for sf in staged:
        print(f"  {sf.name}\n      sha256={sf.sha256}\n      url={sf.url}")

    print("\n--- Thay đổi so với kho hiện tại ---")
    print_diff(diff_manifests(read_current_manifest(), manifest))

    if args.dry_run:
        print("\n[DRY-RUN] Không áp dụng. Kho hiện tại giữ nguyên.")
        return 0

    # --apply: yêu cầu xác nhận (thay neo tin cậy quốc gia phải có chủ đích).
    if not args.yes:
        print("\n⚠️  Sắp GHI ĐÈ kho neo tin cậy đang dùng. Đây là hạ tầng tin cậy quốc gia.")
        try:
            answer = input("    Nhập 'YES' để xác nhận áp dụng: ").strip()
        except EOFError:
            answer = ""
        if answer != "YES":
            print("Đã huỷ (không áp dụng).")
            return 1

    current = apply_store(staged, manifest, args.signing_key)
    print(f"\n✅ Đã áp dụng & ký kho: {current}")
    print("   Kiểm tra: python -m core.trust.store --list --verify")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
