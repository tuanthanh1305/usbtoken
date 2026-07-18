"""Kho BẰNG CHỨNG KÝ + nhật ký kiểm toán — Điều 5 TT 15/2025, TT 19/2025.

Điều 5 buộc phần mềm ký số LƯU TRỮ (tại THỜI ĐIỂM KÝ):
    * Chứng thư gắn khoá bí mật chủ thể đã dùng để ký (+ chuỗi tin cậy).
    * Danh sách thu hồi (CRL) / phản hồi OCSP tại thời điểm ký.
    * Kết quả kiểm tra trạng thái chứng thư (ValidationResult — PROMPT 9).

Thiết kế:
    * APPEND-ONLY + HASH CHAIN: mỗi bản ghi chứa sha256 của bản ghi trước → sửa
      một bản ghi cũ làm gãy chuỗi. Thêm "head anchor" (số bản ghi + hash cuối)
      để phát hiện cả việc CẮT ĐUÔI nhật ký.
    * KHÔNG lưu PIN, KHÔNG lưu private key (hiển nhiên) — chỉ chứng thư công khai,
      CRL/OCSP, kết quả kiểm tra.
    * Lưu tại ``config_dir()/evidence`` với phân quyền chặt (0700/0600).
    * Chính sách lưu giữ cấu hình được; xoá phải CÓ CHỦ ĐÍCH (operator + lý do) và
      được ghi nhật ký; bản ghi ledger KHÔNG bị xoá (thêm "tombstone").
    * ``export_evidence`` gói ZIP nộp khi tranh chấp/kiểm toán.
    * ``verify_evidence_chain`` kiểm toàn vẹn toàn bộ nhật ký + khối dữ liệu.

Nhật ký kiểm toán riêng (:class:`AuditLog`): ký/kiểm tra/đồng bộ kho/đổi cấu
hình → ai, khi nào, kết quả (phục vụ hậu kiểm TT 19/2025).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import stat
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from core.errors import EvidenceError
from core.models import ValidationResult

_GENESIS = "0" * 64

# Hành động audit (TT 19/2025 — hậu kiểm định kỳ).
AUDIT_SIGN = "sign"
AUDIT_VALIDATE = "validate"
AUDIT_TRUST_SYNC = "trust_sync"
AUDIT_CONFIG_CHANGE = "config_change"
AUDIT_EVIDENCE_STORE = "evidence_store"
AUDIT_EVIDENCE_DELETE = "evidence_delete"
AUDIT_EVIDENCE_EXPORT = "evidence_export"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(record: dict[str, Any]) -> bytes:
    """Tuần tự hoá ổn định (khoá đã sắp) để băm nhất quán."""
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _record_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return _sha256_hex(prev_hash.encode("ascii") + _canonical(payload))


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass  # hệ thống không hỗ trợ (vd. một số FS Windows) — không chặn nghiệp vụ


def _secure_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _chmod(path, 0o700)  # chỉ chủ sở hữu


def _write_secure(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    _chmod(path, 0o600)


# --------------------------------------------------------------------------- #
# Nhật ký append-only có hash chain (dùng chung cho evidence & audit)          #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ChainVerification:
    ok: bool
    records_checked: int
    issues: list[str] = field(default_factory=list)


class AppendOnlyLedger:
    """Sổ ghi chỉ-thêm, mỗi bản ghi móc xích sha256 bản ghi trước.

    Head anchor (``<path>.head.json``) giữ (count, head_hash) để phát hiện CẮT
    ĐUÔI. An toàn luồng bằng khoá; mỗi dòng là một JSON.
    """

    def __init__(self, path: Path, *, clock: Callable[[], datetime] = _now) -> None:
        self.path = path
        self._head_path = path.with_name(path.name + ".head.json")
        self._clock = clock
        self._lock = threading.Lock()
        _secure_mkdir(path.parent)

    # -- ghi ------------------------------------------------------------ #
    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Thêm một bản ghi (đóng dấu seq/ts/prev_hash/record_hash)."""
        with self._lock:
            records = self._read_raw()
            prev_hash = records[-1]["record_hash"] if records else _GENESIS
            body = dict(payload)
            body["seq"] = len(records)
            body["ts"] = self._clock().isoformat()
            body["prev_hash"] = prev_hash
            body["record_hash"] = _record_hash(prev_hash, body)
            line = json.dumps(body, ensure_ascii=False) + "\n"
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            _chmod(self.path, 0o600)
            self._write_head(len(records) + 1, body["record_hash"])
            return body

    def _write_head(self, count: int, head_hash: str) -> None:
        _write_secure(
            self._head_path,
            json.dumps({"count": count, "head_hash": head_hash}, ensure_ascii=False).encode("utf-8"),
        )

    # -- đọc ------------------------------------------------------------ #
    def _read_raw(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise EvidenceError("Nhật ký hỏng: dòng JSON không hợp lệ.", detail=str(exc)) from exc
        return out

    def read_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._read_raw()

    # -- kiểm toàn vẹn -------------------------------------------------- #
    def verify(self) -> ChainVerification:
        with self._lock:
            records = self._read_raw()
        issues: list[str] = []
        prev = _GENESIS
        for i, rec in enumerate(records):
            if rec.get("seq") != i:
                issues.append(f"Bản ghi #{i}: seq sai ({rec.get('seq')}) — có thể bị chèn/xoá/đảo.")
            if rec.get("prev_hash") != prev:
                issues.append(f"Bản ghi #{i}: prev_hash không khớp — CHUỖI BỊ GÃY (sửa đổi?).")
            stored = rec.get("record_hash", "")
            body = {k: v for k, v in rec.items() if k != "record_hash"}
            if _record_hash(rec.get("prev_hash", ""), body) != stored:
                issues.append(f"Bản ghi #{i}: record_hash không khớp — NỘI DUNG BỊ SỬA.")
            prev = stored
        # Head anchor: phát hiện cắt đuôi.
        head = self._read_head()
        if head is not None:
            if head.get("count") != len(records):
                issues.append(
                    f"Số bản ghi ({len(records)}) khác head anchor ({head.get('count')}) — "
                    "có thể bị CẮT ĐUÔI nhật ký."
                )
            elif records and head.get("head_hash") != records[-1].get("record_hash"):
                issues.append("Head hash không khớp bản ghi cuối — nhật ký bị thay đổi.")
        return ChainVerification(ok=not issues, records_checked=len(records), issues=issues)

    def _read_head(self) -> dict[str, Any] | None:
        try:
            return json.loads(self._head_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None


# --------------------------------------------------------------------------- #
# Nhật ký kiểm toán (TT 19/2025)                                               #
# --------------------------------------------------------------------------- #
class AuditLog:
    """Ghi mọi thao tác nhạy cảm: ai, khi nào, kết quả (append-only + hash chain)."""

    def __init__(self, path: Path, *, clock: Callable[[], datetime] = _now, software_version: str = "") -> None:
        self._ledger = AppendOnlyLedger(path, clock=clock)
        self._software_version = software_version

    def record(
        self, action: str, *, actor: str, result: str, detail: str = "", **extra: Any
    ) -> dict[str, Any]:
        """Ghi một dòng audit. ``actor`` = ai; ``result`` = ok|refused|error..."""
        payload: dict[str, Any] = {
            "action": action,
            "actor": actor or "unknown",
            "result": result,
            "detail": detail,
            "software_version": self._software_version,
        }
        payload.update(extra)  # metadata bổ sung (KHÔNG đưa dữ liệu nhạy cảm vào đây)
        return self._ledger.append(payload)

    def read_all(self) -> list[dict[str, Any]]:
        return self._ledger.read_all()

    def verify(self) -> ChainVerification:
        return self._ledger.verify()


# --------------------------------------------------------------------------- #
# Chính sách lưu giữ                                                           #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class RetentionPolicy:
    """Chính sách lưu giữ bằng chứng (cấu hình được)."""

    min_retention_days: int = 3650  # mặc định 10 năm — bảo vệ bằng chứng pháp lý
    allow_delete: bool = True       # có cho phép xoá không (kể cả khi đủ tuổi)


# --------------------------------------------------------------------------- #
# Sự kiện ký (đầu vào)                                                         #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class SigningEvent:
    """Dữ liệu một lần ký cần lưu làm bằng chứng (Điều 5)."""

    document_sha256: str
    signer_cert_der: bytes
    validation_result: ValidationResult
    chain_ders: list[bytes] = field(default_factory=list)
    crl_snapshot_der: bytes | None = None
    ocsp_response_der: bytes | None = None
    tsa_token: bytes | None = None
    software_version: str = ""
    trust_store_synced_at: datetime | None = None
    signed_at: datetime | None = None
    signature_algorithm: str = ""
    signature_format: str = ""


# --------------------------------------------------------------------------- #
# Kho bằng chứng                                                               #
# --------------------------------------------------------------------------- #
class EvidenceStore:
    """Lưu trữ bất biến (append-only) các bằng chứng ký + audit."""

    def __init__(
        self,
        base_dir: Path | None = None,
        *,
        adapter: Any = None,
        retention: RetentionPolicy | None = None,
        clock: Callable[[], datetime] = _now,
        software_version: str = "",
    ) -> None:
        if base_dir is None:
            if adapter is None:
                from core.platform import get_adapter

                adapter = get_adapter()
            base_dir = adapter.config_dir() / "evidence"
        self.base_dir = base_dir
        self.items_dir = base_dir / "items"
        self.retention = retention or RetentionPolicy()
        self._clock = clock
        self._software_version = software_version
        _secure_mkdir(self.base_dir)
        _secure_mkdir(self.items_dir)
        self._ledger = AppendOnlyLedger(base_dir / "ledger.jsonl", clock=clock)
        self.audit = AuditLog(base_dir / "audit.jsonl", clock=clock, software_version=software_version)

    # -- LƯU ------------------------------------------------------------ #
    def store_evidence(self, event: SigningEvent, *, actor: str = "") -> str:
        """Lưu một bằng chứng ký (bất biến). Trả ``evidence_id``.

        KHÔNG lưu PIN / private key. Nếu THIẾU CRL/OCSP tại thời điểm ký, bản ghi
        ghi rõ cờ ``revocation_captured=false`` (trung thực về khoảng trống Điều 5).
        """
        evidence_id = secrets.token_hex(16)
        signed_at = (event.signed_at or self._clock()).astimezone(timezone.utc)
        item_dir = self.items_dir / evidence_id
        _secure_mkdir(item_dir)

        # -- ghi các khối dữ liệu (blob) + manifest sha256 -------------- #
        manifest: list[dict[str, str]] = []

        def _blob(name: str, data: bytes) -> str:
            _write_secure(item_dir / name, data)
            digest = _sha256_hex(data)
            manifest.append({"name": name, "sha256": digest})
            return digest

        signer_cert_sha256 = _blob("signer_cert.der", event.signer_cert_der)
        chain_sha256 = [
            _blob(f"chain_{i:02d}.der", der) for i, der in enumerate(event.chain_ders)
        ]
        crl_sha256 = _blob("crl_snapshot.der", event.crl_snapshot_der) if event.crl_snapshot_der else ""
        ocsp_sha256 = _blob("ocsp_response.der", event.ocsp_response_der) if event.ocsp_response_der else ""
        tsa_sha256 = _blob("timestamp.tst", event.tsa_token) if event.tsa_token else ""
        validation_json = event.validation_result.model_dump_json(indent=2).encode("utf-8")
        validation_sha256 = _blob("validation_result.json", validation_json)
        _write_secure(item_dir / "manifest.json",
                      json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))

        revocation_captured = bool(event.crl_snapshot_der or event.ocsp_response_der)

        # -- bản ghi ledger (móc xích) --------------------------------- #
        payload: dict[str, Any] = {
            "type": "signing",
            "evidence_id": evidence_id,
            "signed_at": signed_at.isoformat(),
            "document_sha256": event.document_sha256,
            "signer_cert_sha256": signer_cert_sha256,
            "chain_sha256": chain_sha256,
            "crl_snapshot_sha256": crl_sha256,
            "ocsp_response_sha256": ocsp_sha256,
            "tsa_token_sha256": tsa_sha256,
            "validation_sha256": validation_sha256,
            "validation_status": event.validation_result.status.value,
            "revocation_captured": revocation_captured,
            "trust_store_synced_at": (
                event.trust_store_synced_at.isoformat() if event.trust_store_synced_at else ""
            ),
            "software_version": event.software_version or self._software_version,
            "signature_algorithm": event.signature_algorithm,
            "signature_format": event.signature_format,
            "artifacts_dir": f"items/{evidence_id}",
        }
        record = self._ledger.append(payload)
        self.audit.record(
            AUDIT_EVIDENCE_STORE, actor=actor, result="ok",
            evidence_id=evidence_id, validation_status=payload["validation_status"],
            revocation_captured=revocation_captured,
        )
        return record["evidence_id"]

    # -- ĐỌC ------------------------------------------------------------ #
    def get_record(self, evidence_id: str) -> dict[str, Any] | None:
        for rec in self._ledger.read_all():
            if rec.get("evidence_id") == evidence_id and rec.get("type") == "signing":
                return rec
        return None

    def list_records(self) -> list[dict[str, Any]]:
        return [r for r in self._ledger.read_all() if r.get("type") == "signing"]

    def is_deleted(self, evidence_id: str) -> bool:
        return any(
            r.get("type") == "deletion" and r.get("evidence_id") == evidence_id
            for r in self._ledger.read_all()
        )

    # -- KIỂM TOÀN VẸN -------------------------------------------------- #
    def verify_evidence_chain(self) -> ChainVerification:
        """Kiểm chuỗi ledger + đối chiếu sha256 khối dữ liệu đã lưu."""
        chain = self._ledger.verify()
        issues = list(chain.issues)
        deleted = {
            r["evidence_id"] for r in self._ledger.read_all()
            if r.get("type") == "deletion" and r.get("evidence_id")
        }
        for rec in self.list_records():
            eid = rec.get("evidence_id", "")
            if eid in deleted:
                continue  # đã xoá có chủ đích (tombstone) — bỏ qua kiểm khối
            item_dir = self.base_dir / rec.get("artifacts_dir", f"items/{eid}")
            self._verify_blobs(item_dir, rec, issues)
        return ChainVerification(
            ok=chain.ok and not issues,
            records_checked=chain.records_checked,
            issues=issues,
        )

    @staticmethod
    def _verify_blobs(item_dir: Path, rec: dict[str, Any], issues: list[str]) -> None:
        checks = [("signer_cert.der", rec.get("signer_cert_sha256", ""))]
        for i, sha in enumerate(rec.get("chain_sha256", []) or []):
            checks.append((f"chain_{i:02d}.der", sha))
        if rec.get("crl_snapshot_sha256"):
            checks.append(("crl_snapshot.der", rec["crl_snapshot_sha256"]))
        if rec.get("ocsp_response_sha256"):
            checks.append(("ocsp_response.der", rec["ocsp_response_sha256"]))
        if rec.get("tsa_token_sha256"):
            checks.append(("timestamp.tst", rec["tsa_token_sha256"]))
        if rec.get("validation_sha256"):
            checks.append(("validation_result.json", rec["validation_sha256"]))
        eid = rec.get("evidence_id", "?")
        for name, expected in checks:
            path = item_dir / name
            if not path.is_file():
                issues.append(f"[{eid}] thiếu khối dữ liệu '{name}'.")
                continue
            if _sha256_hex(path.read_bytes()) != expected:
                issues.append(f"[{eid}] khối '{name}' bị SỬA (sha256 không khớp ledger).")

    # -- XUẤT GÓI (nộp khi tranh chấp/kiểm toán) ------------------------ #
    def export_evidence(
        self, evidence_id: str, *, out_path: Path | None = None, actor: str = ""
    ) -> Path:
        """Gói ZIP: khối dữ liệu + bản ghi ledger + toàn bộ ledger (để verify)."""
        rec = self.get_record(evidence_id)
        if rec is None:
            raise EvidenceError(f"Không tìm thấy bằng chứng: {evidence_id}.")
        item_dir = self.base_dir / rec.get("artifacts_dir", f"items/{evidence_id}")
        out_path = out_path or (self.base_dir / f"export_{evidence_id}.zip")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("record.json", json.dumps(rec, ensure_ascii=False, indent=2))
            if item_dir.is_dir():
                for f in sorted(item_dir.iterdir()):
                    if f.is_file():
                        zf.write(f, arcname=f"artifacts/{f.name}")
            # Kèm ledger + head để bên nhận tự kiểm chuỗi.
            if self._ledger.path.is_file():
                zf.write(self._ledger.path, arcname="ledger.jsonl")
            head = self._ledger.path.with_name(self._ledger.path.name + ".head.json")
            if head.is_file():
                zf.write(head, arcname="ledger.jsonl.head.json")
            zf.writestr("README.txt", _EXPORT_README.format(evidence_id=evidence_id))
        _write_secure(out_path, buf.getvalue())
        self.audit.record(AUDIT_EVIDENCE_EXPORT, actor=actor, result="ok", evidence_id=evidence_id)
        return out_path

    # -- XOÁ (có chủ đích + ghi nhật ký) -------------------------------- #
    def delete_evidence(self, evidence_id: str, *, operator: str, reason: str) -> None:
        """Xoá khối dữ liệu MỘT bằng chứng — KHÔNG xoá dòng ledger (thêm tombstone).

        Bắt buộc ``operator`` + ``reason``. Từ chối nếu chưa đủ tuổi lưu giữ hoặc
        chính sách không cho phép xoá. Ghi audit đầy đủ (ai/khi nào/lý do).
        """
        if not operator or not reason:
            self.audit.record(AUDIT_EVIDENCE_DELETE, actor=operator or "unknown",
                              result="refused", evidence_id=evidence_id, detail="thiếu operator/lý do")
            raise EvidenceError("Xoá bằng chứng phải có 'operator' và 'reason' (chủ đích rõ ràng).")
        rec = self.get_record(evidence_id)
        if rec is None:
            raise EvidenceError(f"Không tìm thấy bằng chứng: {evidence_id}.")
        if not self.retention.allow_delete:
            self.audit.record(AUDIT_EVIDENCE_DELETE, actor=operator, result="refused",
                              evidence_id=evidence_id, detail="chính sách không cho phép xoá")
            raise EvidenceError("Chính sách lưu giữ KHÔNG cho phép xoá bằng chứng.")
        age_days = (self._clock() - _parse_dt(rec.get("signed_at"))).days
        if age_days < self.retention.min_retention_days:
            self.audit.record(AUDIT_EVIDENCE_DELETE, actor=operator, result="refused",
                              evidence_id=evidence_id,
                              detail=f"chưa đủ tuổi lưu giữ ({age_days}/{self.retention.min_retention_days} ngày)")
            raise EvidenceError(
                f"Chưa đủ thời gian lưu giữ tối thiểu ({self.retention.min_retention_days} ngày) "
                f"— bằng chứng mới {age_days} ngày. Từ chối xoá."
            )

        # Xoá khối dữ liệu vật lý; GIỮ dòng ledger; thêm tombstone (append-only).
        item_dir = self.base_dir / rec.get("artifacts_dir", f"items/{evidence_id}")
        _rmtree(item_dir)
        self._ledger.append({
            "type": "deletion", "evidence_id": evidence_id,
            "operator": operator, "reason": reason,
        })
        self.audit.record(AUDIT_EVIDENCE_DELETE, actor=operator, result="ok",
                          evidence_id=evidence_id, detail=reason)


# --------------------------------------------------------------------------- #
# Tiện ích                                                                     #
# --------------------------------------------------------------------------- #
_EXPORT_README = (
    "GÓI BẰNG CHỨNG KÝ SỐ — vn-esign-suite (Điều 5 TT 15/2025)\n"
    "evidence_id: {evidence_id}\n\n"
    "Nội dung:\n"
    "  record.json                 — bản ghi ledger của bằng chứng này.\n"
    "  artifacts/signer_cert.der   — chứng thư người ký (tại thời điểm ký).\n"
    "  artifacts/chain_*.der       — chuỗi chứng thư CA tới gốc NEAC.\n"
    "  artifacts/crl_snapshot.der  — CRL tại thời điểm ký (nếu có).\n"
    "  artifacts/ocsp_response.der — phản hồi OCSP tại thời điểm ký (nếu có).\n"
    "  artifacts/validation_result.json — kết quả kiểm tra hiệu lực (đầy đủ).\n"
    "  artifacts/timestamp.tst     — dấu thời gian TSA (nếu có).\n"
    "  ledger.jsonl (+ .head.json) — toàn bộ nhật ký để KIỂM CHUỖI toàn vẹn.\n\n"
    "Kiểm toàn vẹn: dùng EvidenceStore.verify_evidence_chain() hoặc tự kiểm hash\n"
    "chain (mỗi bản ghi chứa sha256 của bản ghi trước).\n"
)


def _parse_dt(value: Any) -> datetime:
    try:
        dt = datetime.fromisoformat(str(value))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _rmtree(path: Path) -> None:
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir():
            _rmtree(child)
        else:
            try:
                child.unlink()
            except OSError:
                pass
    try:
        path.rmdir()
    except OSError:
        pass


__all__ = [
    "EvidenceStore",
    "SigningEvent",
    "RetentionPolicy",
    "AuditLog",
    "AppendOnlyLedger",
    "ChainVerification",
    "AUDIT_SIGN",
    "AUDIT_VALIDATE",
    "AUDIT_TRUST_SYNC",
    "AUDIT_CONFIG_CHANGE",
    "AUDIT_EVIDENCE_STORE",
    "AUDIT_EVIDENCE_DELETE",
    "AUDIT_EVIDENCE_EXPORT",
]
