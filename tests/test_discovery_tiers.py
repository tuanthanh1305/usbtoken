"""Test discovery 4 tầng: Tầng 4 xác thực C_GetInfo, p11-kit shortcut, cờ arch,
chẩn đoán thông minh. Validator được TIÊM bản giả (không cần PyKCS11/subprocess).
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

import core.discovery as disc
from core.discovery import DiscoveryResult, ProbeResult, discover
from core.models import ErrorCode, ModuleTrack
from core.platform.linux import LinuxAdapter


def _make_elf(path: Path, ei_class: int = 2, e_machine: int = 0x3E) -> None:
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = ei_class  # 1=ELF32, 2=ELF64
    h[5] = 1
    struct.pack_into("<H", h, 18, e_machine)
    path.write_bytes(bytes(h) + b"\x00" * 40)


class FakeValidator:
    """Trả 'hợp lệ' cho file có tên khớp; slots theo cấu hình."""

    def __init__(self, ok_substrings: tuple[str, ...], slots: dict[str, int] | None = None) -> None:
        self.ok = ok_substrings
        self.slots = slots or {}
        self.calls: list[str] = []

    def validate(self, path: Path, needs_bridge: bool) -> ProbeResult:
        self.calls.append(path.name)
        if any(s in path.name for s in self.ok):
            return ProbeResult(ok=True, cryptoki_version=(2, 40),
                               manufacturer="ACME", token_slots=self.slots.get(path.name, 0))
        return ProbeResult(ok=False, error="không phải PKCS#11")

    def close(self) -> None:
        pass


@pytest.fixture
def linux(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    ad = LinuxAdapter()
    monkeypatch.setattr(ad, "library_search_paths", lambda: [tmp_path])
    monkeypatch.setattr(ad, "discover_from_system", lambda: [])
    monkeypatch.setattr(ad, "discover_from_user_config", lambda: [])
    return ad


# --------------------------------------------------------------------------- #
# TẦNG 4 — tự phát hiện qua C_GetInfo                                           #
# --------------------------------------------------------------------------- #
def test_tier4_accepts_valid_pkcs11(monkeypatch: pytest.MonkeyPatch, linux, tmp_path: Path) -> None:
    mod = tmp_path / "unknownca.so"  # không có trong bảng vàng
    _make_elf(mod)
    monkeypatch.setattr(disc, "_glob_candidates", lambda a, d, o, e: [mod])
    result = discover(linux, deep=True, validator=FakeValidator(("unknownca",)))
    paths = {Path(m.path).name: m for m in result.modules}
    assert "unknownca.so" in paths
    m = paths["unknownca.so"]
    assert m.tier == 4 and m.confidence_label == "confirmed" and m.validated
    assert m.track is ModuleTrack.B_CA_REBRAND
    assert any("Cryptoki" in w for w in m.warnings)


def test_tier4_rejects_non_pkcs11(monkeypatch: pytest.MonkeyPatch, linux, tmp_path: Path) -> None:
    junk = tmp_path / "libcairo.so"  # khớp glob *ca* nhưng KHÔNG phải PKCS#11
    _make_elf(junk)
    monkeypatch.setattr(disc, "_glob_candidates", lambda a, d, o, e: [junk])
    result = discover(linux, deep=True, validator=FakeValidator(()))  # validator luôn False
    assert not any(Path(m.path).name == "libcairo.so" for m in result.modules)


def test_tier4_respects_cap(monkeypatch: pytest.MonkeyPatch, linux, tmp_path: Path) -> None:
    many = []
    for i in range(disc.MAX_PROBE + 5):
        f = tmp_path / f"x{i}ca.so"
        _make_elf(f)
        many.append(f)
    monkeypatch.setattr(disc, "_glob_candidates", lambda a, d, o, e: many)
    result = discover(linux, deep=True, validator=FakeValidator(()))
    assert result.probe_capped == 5


# --------------------------------------------------------------------------- #
# p11-kit-proxy shortcut                                                        #
# --------------------------------------------------------------------------- #
def test_p11kit_shortcut_skips_tier4(monkeypatch: pytest.MonkeyPatch, linux, tmp_path: Path) -> None:
    proxy = tmp_path / "p11-kit-proxy.so"  # khớp bảng vàng (tier 3)
    _make_elf(proxy)
    other = tmp_path / "otherca.so"
    _make_elf(other)
    called = {"glob": False}

    def spy_glob(a, d, o, e):  # type: ignore[no-untyped-def]
        called["glob"] = True
        return [other]

    monkeypatch.setattr(disc, "_glob_candidates", spy_glob)
    fake = FakeValidator(("p11-kit-proxy",), slots={"p11-kit-proxy.so": 2})
    result = discover(linux, deep=True, validator=fake)
    assert result.used_p11kit_shortcut is True
    assert 4 not in result.tiers_run  # Tầng 4 bị bỏ
    assert called["glob"] is False


def test_force_scan_ignores_shortcut(monkeypatch: pytest.MonkeyPatch, linux, tmp_path: Path) -> None:
    proxy = tmp_path / "p11-kit-proxy.so"
    _make_elf(proxy)
    monkeypatch.setattr(disc, "_glob_candidates", lambda a, d, o, e: [])
    fake = FakeValidator(("p11-kit-proxy",), slots={"p11-kit-proxy.so": 2})
    result = discover(linux, deep=True, force_scan=True, validator=fake)
    assert 4 in result.tiers_run  # force-scan -> vẫn chạy Tầng 4


# --------------------------------------------------------------------------- #
# Cờ arch (ĐÁNH CỜ, KHÔNG loại bỏ)                                              #
# --------------------------------------------------------------------------- #
def test_arch_mismatch_flagged_not_removed(monkeypatch: pytest.MonkeyPatch, linux, tmp_path: Path) -> None:
    fptca = tmp_path / "fptca_v4.so"  # tier 3, Track B
    _make_elf(fptca, ei_class=1, e_machine=0x03)  # ELF32 x86 (32-bit)
    monkeypatch.setattr(linux, "host_arch", lambda: {"bits": 64, "machine": "x86_64", "rosetta": False})
    result = discover(linux, deep=False)  # không cần Tầng 4
    m = next((m for m in result.modules if Path(m.path).name == "fptca_v4.so"), None)
    assert m is not None  # KHÔNG bị loại
    assert m.needs_arch_bridge is True  # chỉ ĐÁNH CỜ
    assert m.arch == "x86_32"


# --------------------------------------------------------------------------- #
# Chẩn đoán thông minh                                                          #
# --------------------------------------------------------------------------- #
def test_diagnostics_when_no_modules(linux) -> None:
    result = discover(linux, deep=False)
    assert result.modules == []
    codes = [d.code for d in result.diagnostics]
    assert codes[0] is ErrorCode.ARCH_MISMATCH  # (a) đầu tiên
    assert ErrorCode.NO_MODULE_FOUND in codes  # (b)
    assert ErrorCode.LOGIN_REQUIRED in codes  # (f)
    assert all(d.message_vi for d in result.diagnostics)  # tiếng Việt


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #
def test_cli_scan_no_deep(capsys: pytest.CaptureFixture[str]) -> None:
    code = disc._main(["--scan", "--no-deep", "--no-cache"])
    out = capsys.readouterr().out
    assert code in (0, 1)
    assert "Module PKCS#11 phát hiện" in out


def test_result_model_serializable(linux) -> None:
    result = discover(linux, deep=False)
    assert isinstance(result, DiscoveryResult)
    # Serialize được (phục vụ cache + service).
    assert '"modules"' in result.model_dump_json()
