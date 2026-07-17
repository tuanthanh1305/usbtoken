"""Test phát hiện module HAI NHÁNH (Track A theo chip, Track B CA rebrand).

Đặc biệt kiểm chứng: hệ thống dò ra FPT-CA (Track B, fptca_v4.so) — điều mà quét
Track A đơn thuần KHÔNG bao giờ làm được.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from core.discovery import discover_modules
from core.models import ModuleTrack
from core.platform.linux import LinuxAdapter


def _make_elf(path: Path) -> None:
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = 2
    h[5] = 1
    struct.pack_into("<H", h, 18, 0x3E)
    path.write_bytes(bytes(h) + b"\x00" * 40)


@pytest.fixture
def linux_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    ad = LinuxAdapter()
    monkeypatch.setattr(ad, "library_search_paths", lambda: [tmp_path])
    monkeypatch.setattr(ad, "discover_from_system", lambda: [])
    monkeypatch.setattr(ad, "discover_from_user_config", lambda: [])
    return ad


def test_track_a_by_chip(linux_scan, tmp_path: Path) -> None:
    _make_elf(tmp_path / "libeToken.so")  # SafeNet/Thales (Track A)
    mods = {Path(m.path).name: m for m in discover_modules(linux_scan)}
    assert "libeToken.so" in mods
    m = mods["libeToken.so"]
    assert m.track is ModuleTrack.A_CHIP
    assert m.chip_hint == "SafeNet/Thales"
    assert m.validated is True


def test_track_b_fptca_rebrand(linux_scan, tmp_path: Path) -> None:
    _make_elf(tmp_path / "fptca_v4.so")  # FPT-CA (Track B — CA rebrand)
    mods = {Path(m.path).name: m for m in discover_modules(linux_scan)}
    assert "fptca_v4.so" in mods, "PHẢI dò ra FPT-CA qua Track B"
    m = mods["fptca_v4.so"]
    assert m.track is ModuleTrack.B_CA_REBRAND
    assert m.chip_hint == "FPT-CA"


def test_unknown_file_not_collected(linux_scan, tmp_path: Path) -> None:
    _make_elf(tmp_path / "random-unrelated.so")
    names = {Path(m.path).name for m in discover_modules(linux_scan)}
    assert "random-unrelated.so" not in names  # không có trong vendor_intel -> bỏ
