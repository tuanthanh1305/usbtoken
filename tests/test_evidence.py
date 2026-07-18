"""Test kho BẰNG CHỨNG KÝ + audit (core/evidence.py) — Điều 5 TT15, TT19/2025.

Trọng tâm:
    * Lưu đủ artefact tại thời điểm ký (cert + chain + CRL/OCSP + ValidationResult).
    * APPEND-ONLY + HASH CHAIN: phát hiện sửa bản ghi cũ, sửa khối dữ liệu, và
      CẮT ĐUÔI nhật ký.
    * KHÔNG lưu PIN / private key.
    * Xoá phải có chủ đích (operator + lý do) + tôn trọng lưu giữ + ghi audit.
    * export ZIP nộp kiểm toán; verify toàn bộ chuỗi.
    * Audit log riêng có hash chain.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.errors import EvidenceError
from core.evidence import (
    AUDIT_EVIDENCE_DELETE,
    AppendOnlyLedger,
    EvidenceStore,
    RetentionPolicy,
    SigningEvent,
)
from core.models import ValidationResult, ValidationStatusCode
from tests.certs import make_chain


def _vr(status=ValidationStatusCode.VALID):  # type: ignore[no-untyped-def]
    now = datetime.now(timezone.utc)
    return ValidationResult(status=status, checked_at=now, at_time=now,
                            subject="CN=Nguyen Van A", ca_name="VN Test Public CA")


def _event(**over):  # type: ignore[no-untyped-def]
    root, inter, leaf = make_chain()
    base = dict(
        document_sha256="ab" * 32,
        signer_cert_der=leaf.der,
        validation_result=_vr(),
        chain_ders=[inter.der, root.der],
        crl_snapshot_der=b"CRL-AT-SIGNING-TIME",
        software_version="1.0.0",
    )
    base.update(over)
    return SigningEvent(**base)


def _store(tmp_path, **kw):  # type: ignore[no-untyped-def]
    kw.setdefault("retention", RetentionPolicy(min_retention_days=0))
    return EvidenceStore(base_dir=tmp_path / "evidence", software_version="1.0.0", **kw)


# --------------------------------------------------------------------------- #
# Lưu + đọc                                                                    #
# --------------------------------------------------------------------------- #
def test_store_writes_all_artifacts(tmp_path: Path) -> None:
    store = _store(tmp_path)
    eid = store.store_evidence(_event(), actor="tester")
    rec = store.get_record(eid)
    assert rec is not None and rec["validation_status"] == "valid"
    assert rec["revocation_captured"] is True  # có CRL tại thời điểm ký
    item = tmp_path / "evidence" / "items" / eid
    for name in ("signer_cert.der", "chain_00.der", "chain_01.der",
                 "crl_snapshot.der", "validation_result.json", "manifest.json"):
        assert (item / name).is_file()


def test_store_flags_missing_revocation(tmp_path: Path) -> None:
    # THIẾU CRL/OCSP -> ghi rõ khoảng trống Điều 5 (không giả vờ đã có).
    store = _store(tmp_path)
    eid = store.store_evidence(_event(crl_snapshot_der=None), actor="t")
    assert store.get_record(eid)["revocation_captured"] is False


def test_no_pin_or_private_key_in_store(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.store_evidence(_event(), actor="t")
    blob = b""
    for p in (tmp_path / "evidence").rglob("*"):
        if p.is_file():
            blob += p.read_bytes()
    low = blob.lower()
    assert b"pin" not in low and b"private" not in low and b"begin private key" not in low


# --------------------------------------------------------------------------- #
# Hash chain — phát hiện sửa đổi                                               #
# --------------------------------------------------------------------------- #
def test_chain_verifies_multiple(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for _ in range(3):
        store.store_evidence(_event(), actor="t")
    v = store.verify_evidence_chain()
    assert v.ok and v.records_checked == 3


def test_detects_tampered_ledger_record(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.store_evidence(_event(), actor="t")
    store.store_evidence(_event(), actor="t")
    ledger = tmp_path / "evidence" / "ledger.jsonl"
    lines = ledger.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["document_sha256"] = "00" * 32  # sửa nội dung bản ghi cũ
    lines[0] = json.dumps(rec, ensure_ascii=False)
    ledger.write_text("\n".join(lines) + "\n")
    v = store.verify_evidence_chain()
    assert not v.ok and any("SỬA" in i or "GÃY" in i for i in v.issues)


def test_detects_tampered_blob(tmp_path: Path) -> None:
    store = _store(tmp_path)
    eid = store.store_evidence(_event(), actor="t")
    cert = tmp_path / "evidence" / "items" / eid / "signer_cert.der"
    cert.write_bytes(cert.read_bytes() + b"\x00tampered")
    v = store.verify_evidence_chain()
    assert not v.ok and any("không khớp" in i or "SỬA" in i for i in v.issues)


def test_detects_tail_truncation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.store_evidence(_event(), actor="t")
    store.store_evidence(_event(), actor="t")
    ledger = tmp_path / "evidence" / "ledger.jsonl"
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n")  # cắt bản ghi cuối
    v = store.verify_evidence_chain()
    assert not v.ok and any("CẮT ĐUÔI" in i for i in v.issues)


# --------------------------------------------------------------------------- #
# Xoá có chủ đích + lưu giữ + audit                                           #
# --------------------------------------------------------------------------- #
def test_delete_requires_operator_and_reason(tmp_path: Path) -> None:
    store = _store(tmp_path)
    eid = store.store_evidence(_event(), actor="t")
    with pytest.raises(EvidenceError):
        store.delete_evidence(eid, operator="", reason="")


def test_delete_refused_within_retention(tmp_path: Path) -> None:
    store = _store(tmp_path, retention=RetentionPolicy(min_retention_days=3650))
    eid = store.store_evidence(_event(), actor="t")
    with pytest.raises(EvidenceError) as exc:
        store.delete_evidence(eid, operator="admin", reason="nhầm")
    assert "lưu giữ" in exc.value.message.lower()


def test_delete_tombstones_and_keeps_chain(tmp_path: Path) -> None:
    store = _store(tmp_path)  # min_retention_days=0
    eid = store.store_evidence(_event(), actor="t")
    store.delete_evidence(eid, operator="admin", reason="yêu cầu chủ thể")
    # Khối dữ liệu bị xoá vật lý...
    assert not (tmp_path / "evidence" / "items" / eid).exists()
    # ...nhưng dòng ledger còn + có tombstone; chuỗi VẪN toàn vẹn.
    assert store.is_deleted(eid) is True
    v = store.verify_evidence_chain()
    assert v.ok
    # Audit ghi ai/khi nào/lý do.
    dels = [a for a in store.audit.read_all()
            if a["action"] == AUDIT_EVIDENCE_DELETE and a["result"] == "ok"]
    assert dels and dels[-1]["actor"] == "admin" and "chủ thể" in dels[-1]["detail"]


def test_delete_refused_when_policy_disallows(tmp_path: Path) -> None:
    store = _store(tmp_path, retention=RetentionPolicy(min_retention_days=0, allow_delete=False))
    eid = store.store_evidence(_event(), actor="t")
    with pytest.raises(EvidenceError):
        store.delete_evidence(eid, operator="admin", reason="x")


# --------------------------------------------------------------------------- #
# Export ZIP                                                                   #
# --------------------------------------------------------------------------- #
def test_export_zip_contains_artifacts_and_ledger(tmp_path: Path) -> None:
    store = _store(tmp_path)
    eid = store.store_evidence(_event(), actor="t")
    zp = store.export_evidence(eid, actor="auditor")
    with zipfile.ZipFile(zp) as zf:
        names = set(zf.namelist())
    assert "record.json" in names and "ledger.jsonl" in names and "README.txt" in names
    assert "artifacts/signer_cert.der" in names
    assert "artifacts/validation_result.json" in names


def test_export_unknown_id_raises(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(EvidenceError):
        store.export_evidence("deadbeef", actor="a")


# --------------------------------------------------------------------------- #
# Audit log riêng                                                              #
# --------------------------------------------------------------------------- #
def test_audit_records_store_and_export(tmp_path: Path) -> None:
    store = _store(tmp_path)
    eid = store.store_evidence(_event(), actor="signer1")
    store.export_evidence(eid, actor="auditor")
    actions = [a["action"] for a in store.audit.read_all()]
    assert "evidence_store" in actions and "evidence_export" in actions
    assert store.audit.verify().ok


def test_audit_chain_tamper_detected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.store_evidence(_event(), actor="s")
    audit = tmp_path / "evidence" / "audit.jsonl"
    lines = audit.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["actor"] = "attacker"  # sửa "ai đã thao tác"
    lines[0] = json.dumps(rec, ensure_ascii=False)
    audit.write_text("\n".join(lines) + "\n")
    assert store.audit.verify().ok is False


# --------------------------------------------------------------------------- #
# AppendOnlyLedger đơn vị                                                      #
# --------------------------------------------------------------------------- #
def test_ledger_append_and_verify(tmp_path: Path) -> None:
    led = AppendOnlyLedger(tmp_path / "l.jsonl")
    a = led.append({"x": 1})
    b = led.append({"x": 2})
    assert b["prev_hash"] == a["record_hash"]
    assert led.verify().ok
    assert [r["seq"] for r in led.read_all()] == [0, 1]
