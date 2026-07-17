"""Test loader BẢNG VÀNG (core/intel.py): schema, index, override, hypothesis."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.intel import ENV_INTEL_FILE, IntelEntry, load_intel


def test_fptca_entry_confirmed() -> None:
    """Yêu cầu bắt buộc: entry fptca_linux_v4 tồn tại, confidence=confirmed."""
    db = load_intel()
    fptca = [e for e in db.entries if e.id == "fptca_linux_v4"]
    assert len(fptca) == 1
    e = fptca[0]
    assert e.track == "B"
    assert e.os == "linux"
    assert e.ca_hint == "FPT-CA"
    assert e.confidence == "confirmed"
    assert e.filenames == ("fptca_v4.so",)
    assert e.package_name == "fptca-4.0"
    assert "ELF32" in e.arch_warning
    assert not db.errors  # bảng vàng cơ sở phải hợp lệ


def test_track_a_documented_and_opensc_mac_is_so() -> None:
    db = load_intel()
    mac = {e.id: e for e in db.filter(os_name="macos", track="A")}
    assert "opensc_mac" in mac
    assert mac["opensc_mac"].filenames == ("opensc-pkcs11.so",)  # .so trên mac!
    assert all(e.confidence == "documented" for e in db.filter(track="A"))


def test_windows_has_no_p11kit() -> None:
    db = load_intel()
    win_ids = {e.id for e in db.filter(os_name="windows")}
    assert "p11kit_mac" not in win_ids and "p11kit_linux" not in win_ids


def test_hypothesis_cas_have_no_filenames() -> None:
    db = load_intel()
    hyp = db.filter(confidence="hypothesis")
    assert len(hyp) == 25  # 25 CA còn lại
    assert all(e.filenames == () for e in hyp)  # KHÔNG đoán tên file
    assert all(e.glob_hints for e in hyp)  # nhưng có glob_hints cho Tầng 4
    names = {e.ca_hint for e in hyp}
    # CA2, SmartSign, I-CA là ba CA riêng biệt.
    assert {"CA2", "SmartSign", "I-CA"} <= names


def test_filter_os_linux_track_b_includes_fptca_and_hypothesis() -> None:
    db = load_intel()
    b_linux = db.filter(os_name="linux", track="B")
    ids = {e.id for e in b_linux}
    assert "fptca_linux_v4" in ids
    # hypothesis os=any -> cũng khớp linux.
    assert any(e.confidence == "hypothesis" for e in b_linux)


def test_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    override = tmp_path / "override.yaml"
    override.write_text(
        "entries:\n"
        "  - id: fptca_linux_v4\n"
        "    track: B\n"
        "    os: linux\n"
        "    ca_hint: FPT-CA\n"
        "    filenames: [fptca_v5.so]\n"
        "    confidence: confirmed\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(ENV_INTEL_FILE, str(override))
    db = load_intel()
    fptca = next(e for e in db.entries if e.id == "fptca_linux_v4")
    assert fptca.filenames == ("fptca_v5.so",)  # override thắng


def test_validation_rejects_hypothesis_with_filenames(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "entries:\n"
        "  - id: bad_guess\n"
        "    track: B\n"
        "    os: linux\n"
        "    ca_hint: SomeCA\n"
        "    filenames: [guessed.so]\n"
        "    confidence: hypothesis\n",
        encoding="utf-8",
    )
    db = load_intel(base_path=bad)
    assert not any(e.id == "bad_guess" for e in db.entries)  # bị loại
    assert any("cấm đoán tên file" in err for err in db.errors)


def test_confidence_score_ordering() -> None:
    a = IntelEntry(id="x", track="A", os="linux", chip_vendor="v", confidence="confirmed")
    b = IntelEntry(id="y", track="A", os="linux", chip_vendor="v", confidence="hypothesis")
    assert a.confidence_score > b.confidence_score
