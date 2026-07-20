"""Test công cụ sync (phần THUẦN, không mạng): validate_url, build_manifest, diff."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from tests.certs import _make
from tools import sync_trust_store as sync


def _stage(tmp_path: Path, role: str, name: str, data: bytes) -> sync.StagedFile:
    rel = f"{role}/{name}.der"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return sync.StagedFile(
        role=role, name=rel, path=p, sha256=hashlib.sha256(data).hexdigest(),
        url=f"https://rootca.gov.vn/{name}", downloaded_at="2026-07-17T00:00:00+00:00",
    )


def test_validate_url_rules() -> None:
    host = "rootca.gov.vn"
    assert sync.validate_url("https://rootca.gov.vn/x.der", host)[0] is True
    assert sync.validate_url("https://sub.rootca.gov.vn/x", host)[0] is True
    assert sync.validate_url("http://rootca.gov.vn/x", host)[0] is False  # phải HTTPS
    assert sync.validate_url("https://evil.com/x", host)[0] is False  # sai miền
    assert sync.validate_url("", host)[0] is False


def test_build_manifest_records_provenance_and_metadata(tmp_path: Path) -> None:
    ca = _make("FPT-CA Public", None, is_ca=True)
    staged = [_stage(tmp_path, "ca", "FPT-CA", ca.der)]
    manifest = sync.build_manifest(
        staged, synced_at=datetime.now(timezone.utc), source="https://rootca.gov.vn"
    )
    assert manifest["files"][0]["sha256"] == staged[0].sha256
    assert manifest["files"][0]["url"].startswith("https://rootca.gov.vn")
    assert manifest["files"][0]["subject_dn"] == ca.cert.subject.rfc4514_string()
    assert manifest["files"][0]["ca_name"] == "FPT-CA Public"


def test_diff_detects_new_ca(tmp_path: Path) -> None:
    ca = _make("Newtel-CA", None, is_ca=True)
    staged = [_stage(tmp_path, "ca", "Newtel-CA", ca.der)]
    new = sync.build_manifest(staged, synced_at=datetime.now(timezone.utc), source="x")
    report = sync.diff_manifests({}, new)  # kho cũ rỗng
    assert any("Newtel-CA" in r for r in report["new_ca"])


def test_diff_detects_removed_ca(tmp_path: Path) -> None:
    ca = _make("MISA-CA", None, is_ca=True)
    old = sync.build_manifest(
        [_stage(tmp_path, "ca", "MISA-CA", ca.der)],
        synced_at=datetime.now(timezone.utc), source="x",
    )
    report = sync.diff_manifests(old, {"files": []})
    assert any("MISA-CA" in r for r in report["removed_ca"])
