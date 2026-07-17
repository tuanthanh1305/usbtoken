"""Test tầng platform: factory, host_arch (bits/machine/rosetta), parse header."""

from __future__ import annotations

import struct
from pathlib import Path

from core.platform import PlatformAdapter, get_adapter
from core.platform.base import BinaryArch


def test_get_adapter_valid_and_cached() -> None:
    a = get_adapter()
    assert isinstance(a, PlatformAdapter)
    assert a.name() in {"windows", "macos", "linux"}
    assert get_adapter() is a


def test_host_arch_shape_includes_rosetta() -> None:
    arch = get_adapter().host_arch()
    assert arch["bits"] in (64, 32)
    assert arch["machine"] in ("arm64", "x86_64")
    assert isinstance(arch["rosetta"], bool)


def test_glob_patterns_match_os() -> None:
    a = get_adapter()
    ext = {"windows": ".dll", "macos": ".dylib", "linux": ".so"}[a.name()]
    assert any(ext in p for p in a.glob_patterns())


def test_config_and_log_dir_nonempty() -> None:
    a = get_adapter()
    assert str(a.config_dir())
    assert str(a.log_dir())
    assert "vn-esign-suite" in str(a.config_dir())


def test_parse_elf_arch(tmp_path: Path) -> None:
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = 2
    h[5] = 1
    struct.pack_into("<H", h, 18, 0x3E)
    f = tmp_path / "lib.so"
    f.write_bytes(bytes(h) + b"\x00" * 40)
    assert PlatformAdapter._parse_elf_arch(f) == BinaryArch.X86_64


def test_parse_pe_arch(tmp_path: Path) -> None:
    buf = bytearray(200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x84, 0x8664)
    f = tmp_path / "lib.dll"
    f.write_bytes(bytes(buf))
    assert PlatformAdapter._parse_pe_arch(f) == BinaryArch.X86_64


def test_parse_macho_universal(tmp_path: Path) -> None:
    f = tmp_path / "lib.dylib"
    f.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 60)
    assert PlatformAdapter._parse_macho_arch(f) == BinaryArch.UNIVERSAL
