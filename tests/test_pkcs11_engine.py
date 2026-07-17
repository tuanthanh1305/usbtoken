"""Test engine liệt kê token: enrich TRỤC 1, CHIP THẬT (TRỤC 2) độc lập tên
module, cô lập lỗi, timeout, tuyến bridge. Ops/manager được tiêm bản giả."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

import core.pkcs11_engine as engine
from core.models import ErrorCode, ModuleCandidate, ModuleTrack


def _cand(path: str, *, track: ModuleTrack, chip_hint: str, arch: str = "x86_64") -> ModuleCandidate:
    return ModuleCandidate(path=path, track=track, chip_hint=chip_hint, source="vendor_intel", arch=arch)


def _token_dict(mid: str = "FEITIAN", model: str = "ePass2003") -> dict[str, Any]:
    return {
        "slot_id": 0, "label": "Chu Ky So", "manufacturer_id": mid, "model": model,
        "serial": "SN999", "flags": 0x4,
        "pin_state": {"login_required": True, "count_low": False, "final_try": False,
                      "locked": False, "protected_auth_path": False},
    }


class FakeOps:
    """core.pkcs11_ops giả: path -> list token, hoặc callable/exception."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.mapping = mapping

    def enumerate_tokens(self, mp: str) -> list[dict[str, Any]]:
        val = self.mapping.get(mp, [])
        if isinstance(val, Exception):
            raise val
        if callable(val):
            return val()
        return val


class FakeManager:
    def __init__(self, mapping: dict[str, Any]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def call(self, module_path: str, method: str, params: dict[str, Any] | None = None,
             *, timeout: float | None = None) -> Any:
        self.calls.append(module_path)
        return self.mapping.get(module_path, [])

    def close(self) -> None:
        pass


class FakeAdapter:
    def __init__(self, bridge_paths: set[str] | None = None) -> None:
        self._bridge = bridge_paths or set()

    def name(self) -> str:
        return "linux"

    def needs_arch_bridge(self, path: Path) -> bool:
        return str(path) in self._bridge


# --------------------------------------------------------------------------- #
# Enrich TRỤC 1 + CHIP THẬT (TRỤC 2) độc lập                                    #
# --------------------------------------------------------------------------- #
def test_chip_that_independent_of_module_name() -> None:
    # Nạp bằng fptca_v4.so (tên CA, Track B) nhưng chip THẬT là Feitian.
    cand = _cand("/usr/lib/fptca_v4.so", track=ModuleTrack.B_CA_REBRAND, chip_hint="FPT-CA")
    ops = FakeOps({"/usr/lib/fptca_v4.so": [_token_dict(mid="FEITIAN", model="ePass2003")]})
    tokens = engine.enumerate_tokens([cand], adapter=FakeAdapter(), ops=ops)  # type: ignore[arg-type]
    assert len(tokens) == 1
    t = tokens[0]
    assert t.manufacturer_id == "FEITIAN"  # ⭐ CHIP THẬT (TRỤC 2)
    assert t.model == "ePass2003"
    assert t.chip_hint == "FPT-CA"  # gợi ý từ tên module (TRỤC 1) — KHÁC chip thật
    assert t.track == "B"
    assert t.source == "vendor_intel"
    assert t.module_path == "/usr/lib/fptca_v4.so"
    assert t.via_bridge is False


def test_pin_state_mapped() -> None:
    d = _token_dict()
    d["pin_state"]["locked"] = True
    cand = _cand("/m.so", track=ModuleTrack.A_CHIP, chip_hint="Feitian")
    tokens = engine.enumerate_tokens([cand], adapter=FakeAdapter(), ops=FakeOps({"/m.so": [d]}))  # type: ignore[arg-type]
    assert tokens[0].pin_state.locked is True


# --------------------------------------------------------------------------- #
# Cô lập lỗi                                                                    #
# --------------------------------------------------------------------------- #
def test_one_module_failure_isolated() -> None:
    good = _cand("/good.so", track=ModuleTrack.A_CHIP, chip_hint="Feitian")
    bad = _cand("/bad.so", track=ModuleTrack.A_CHIP, chip_hint="X")
    ops = FakeOps({"/good.so": [_token_dict()], "/bad.so": RuntimeError("module nổ")})
    result = engine.enumerate_detailed([bad, good], adapter=FakeAdapter(), ops=ops)  # type: ignore[arg-type]
    assert len(result.tokens) == 1  # module tốt vẫn ra token
    errored = [r for r in result.reports if r.error]
    assert len(errored) == 1 and "nổ" in errored[0].error.message_vi


def test_timeout_isolated() -> None:
    slow = _cand("/slow.so", track=ModuleTrack.A_CHIP, chip_hint="X")
    ops = FakeOps({"/slow.so": lambda: (time.sleep(5), [])[1]})
    result = engine.enumerate_detailed(
        [slow], adapter=FakeAdapter(), ops=ops, per_module_timeout=0.2,  # type: ignore[arg-type]
    )
    assert result.tokens == []
    assert result.reports[0].error is not None
    assert result.reports[0].error.code is ErrorCode.INTERNAL_ERROR


# --------------------------------------------------------------------------- #
# Tuyến bridge                                                                  #
# --------------------------------------------------------------------------- #
def test_via_bridge_flag_and_route() -> None:
    cand = _cand("/x86only.so", track=ModuleTrack.B_CA_REBRAND, chip_hint="FPT-CA")
    adapter = FakeAdapter(bridge_paths={"/x86only.so"})  # lệch arch -> bridge
    mgr = FakeManager({"/x86only.so": [_token_dict(mid="WATCHDATA")]})
    tokens = engine.enumerate_tokens([cand], adapter=adapter, manager=mgr)  # type: ignore[arg-type]
    assert tokens[0].via_bridge is True
    assert tokens[0].manufacturer_id == "WATCHDATA"  # chip thật vẫn đọc qua bridge
    assert mgr.calls == ["/x86only.so"]  # đã đi qua manager (bridge)


def test_inprocess_vs_bridge_identical_tokeninfo() -> None:
    # Cùng dữ liệu token -> TokenInfo GIỐNG HỆT dù tuyến nào (trừ cờ via_bridge).
    d = _token_dict(mid="THALES", model="eToken")
    ip = engine.enumerate_tokens(
        [_cand("/a.so", track=ModuleTrack.A_CHIP, chip_hint="SafeNet")],
        adapter=FakeAdapter(), ops=FakeOps({"/a.so": [d]}),  # type: ignore[arg-type]
    )[0]
    br = engine.enumerate_tokens(
        [_cand("/a.so", track=ModuleTrack.A_CHIP, chip_hint="SafeNet")],
        adapter=FakeAdapter(bridge_paths={"/a.so"}), manager=FakeManager({"/a.so": [d]}),  # type: ignore[arg-type]
    )[0]
    a, b = ip.model_dump(), br.model_dump()
    a.pop("via_bridge"), b.pop("via_bridge")
    assert a == b


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #
def test_cli_json(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    canned = engine.EngineResult(
        tokens=engine.enumerate_tokens(
            [_cand("/m.so", track=ModuleTrack.A_CHIP, chip_hint="Feitian")],
            adapter=FakeAdapter(), ops=FakeOps({"/m.so": [_token_dict()]}),  # type: ignore[arg-type]
        )
    )
    monkeypatch.setattr(engine, "enumerate_detailed", lambda **kw: canned)
    code = engine.main(["--json"])
    out = capsys.readouterr().out
    assert code == 0 and '"manufacturer_id"' in out


def test_cli_list(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(engine, "enumerate_detailed", lambda **kw: engine.EngineResult())
    code = engine.main(["--list"])
    assert code == 1  # không token
    assert "Token tìm được: 0" in capsys.readouterr().out
