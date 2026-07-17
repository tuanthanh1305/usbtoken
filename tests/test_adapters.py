"""Test 3 adapter — tập trung vào logic phát hiện MỚI (mock filesystem/subprocess).

Chạy được trên mọi OS: header ELF/PE dựng bằng bytes, subprocess được mock.
"""

from __future__ import annotations

import struct
import types
from pathlib import Path

import pytest

from core.config import text_matches_ca_keyword
from core.platform.base import BinaryArch
from core.platform.linux import LinuxAdapter
from core.platform.macos import MacOSAdapter
from core.platform.windows import WindowsAdapter


def _make_elf(path: Path, ei_class: int = 2, e_machine: int = 0x3E) -> None:
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = ei_class
    h[5] = 1
    struct.pack_into("<H", h, 18, e_machine)
    path.write_bytes(bytes(h) + b"\x00" * 40)


# --------------------------------------------------------------------------- #
# Từ khoá CA (dùng chung Windows/Linux/macOS Tầng 1)                            #
# --------------------------------------------------------------------------- #
def test_ca_keyword_matching() -> None:
    assert text_matches_ca_keyword("FPT Token Manager 4.0")  # 'token'
    assert text_matches_ca_keyword("Trình ký số VNPT-CA")  # tên CA + 'ký số'
    assert text_matches_ca_keyword("BkavCA Plugin")
    assert not text_matches_ca_keyword("Mozilla Firefox")
    assert not text_matches_ca_keyword("Cisco AnyConnect")  # KHÔNG match bare 'ca'


# --------------------------------------------------------------------------- #
# LinuxAdapter — TẦNG 1 dpkg (chính xác tuyệt đối)                              #
# --------------------------------------------------------------------------- #
def test_linux_dpkg_discovers_fptca(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    so_path = tmp_path / "fptca_v4.so"
    _make_elf(so_path)

    def fake_run(cmd: list[str]) -> bytes:
        if cmd[:2] == ["dpkg", "-l"]:
            return b"ii  fptca-4.0  4.0  amd64  FPT Token Manager cho Ubuntu\n"
        if cmd[:2] == ["dpkg", "-L"] and cmd[2] == "fptca-4.0":
            return f"/usr/share/doc/fptca-4.0\n{so_path}\n".encode()
        return b""

    ad = LinuxAdapter()
    monkeypatch.setattr(ad, "_run", fake_run)
    monkeypatch.setattr(ad, "_desktop_modules", lambda: [])  # cô lập nhiễu .desktop
    found = ad.discover_from_system()
    assert so_path in found  # dpkg -L fptca-4.0 -> /usr/lib/fptca_v4.so (mock)


def test_linux_dpkg_skips_non_ca_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str]) -> bytes:
        if cmd[:2] == ["dpkg", "-l"]:
            return b"ii  vim  9.0  amd64  Vi IMproved editor\n"
        return b""

    ad = LinuxAdapter()
    monkeypatch.setattr(ad, "_run", fake_run)
    monkeypatch.setattr(ad, "_desktop_modules", lambda: [])
    assert ad._dpkg_modules() == []  # 'vim' không khớp từ khoá CA


def test_linux_ldd_missing_dependency_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    so = tmp_path / "libold.so"
    _make_elf(so)
    fake = types.SimpleNamespace(
        stdout="\tlibcrypto.so.1.0.0 => not found\n\tlibc.so.6 => /lib/libc.so.6\n",
        returncode=0,
    )
    ad = LinuxAdapter()
    monkeypatch.setattr(ad, "_run_proc", lambda cmd: fake)
    warns = ad.library_warnings(so)
    assert warns and "libcrypto.so.1.0.0" in warns[0]


def test_linux_search_paths_include_flat_usr_lib() -> None:
    paths = [str(p) for p in LinuxAdapter().library_search_paths()]
    assert "/usr/lib" in paths  # PHẲNG — nơi FPT đặt fptca_v4.so


# --------------------------------------------------------------------------- #
# MacOSAdapter — cảnh báo đặc thù                                              #
# --------------------------------------------------------------------------- #
def test_macos_notes_include_library_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    ad = MacOSAdapter()
    monkeypatch.setattr(ad, "_run", lambda cmd: b"")
    monkeypatch.setattr(ad, "_sysctl_int", lambda key: None)
    monkeypatch.setattr(ad, "_homebrew_pcscd", lambda: None)
    notes = ad.platform_notes()
    assert any("Library Validation" in n for n in notes)


def test_macos_homebrew_pcscd_conflict_note(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_pcscd = tmp_path / "pcscd"
    fake_pcscd.write_text("#!/bin/sh\n")
    ad = MacOSAdapter()
    monkeypatch.setattr(ad, "_run", lambda cmd: b"")
    monkeypatch.setattr(ad, "_sysctl_int", lambda key: None)
    monkeypatch.setattr(ad, "_homebrew_pcscd", lambda: fake_pcscd)
    notes = ad.platform_notes()
    assert any("xung đột" in n.lower() or "pcscd" in n.lower() for n in notes)


def test_macos_scan_ca_apps_filters_by_name() -> None:
    # /Applications không có app CA trên CI -> rỗng, không nổ.
    assert isinstance(MacOSAdapter()._scan_ca_applications(), list)


# --------------------------------------------------------------------------- #
# WindowsAdapter — bitness & thư mục                                           #
# --------------------------------------------------------------------------- #
def test_windows_search_paths_include_syswow64() -> None:
    paths = [str(p) for p in WindowsAdapter().library_search_paths()]
    assert any("SysWOW64" in p for p in paths)  # 32-bit — BẮT BUỘC


def test_windows_config_dir() -> None:
    assert "vn-esign-suite" in str(WindowsAdapter().config_dir())


def test_windows_pe_arch_parsing(tmp_path: Path) -> None:
    buf = bytearray(200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x84, 0x014C)  # x86 32-bit
    f = tmp_path / "lib.dll"
    f.write_bytes(bytes(buf))
    assert WindowsAdapter().check_binary_arch(f) == BinaryArch.X86_32


def test_windows_needs_bridge_32bit_on_64host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    buf = bytearray(200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x84, 0x014C)
    f = tmp_path / "lib.dll"
    f.write_bytes(bytes(buf))
    ad = WindowsAdapter()
    monkeypatch.setattr(ad, "host_arch", lambda: {"bits": 64, "machine": "x86_64", "rosetta": False})
    assert ad.needs_arch_bridge(f) is True
