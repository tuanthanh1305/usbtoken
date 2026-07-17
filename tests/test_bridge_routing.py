"""Test tuyến THỐNG NHẤT: in-process vs bridge cho ra TokenInfo/CertInfo Y HỆT,
+ vòng đời BridgeManager (spawn/restart/kill/remediation) + che PIN khỏi log.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from typing import Any

import pytest

from core.bridge import BridgeManager, ModuleSession
from core.bridge.protocol import SENSITIVE_FIELDS, redact_params_for_log
from core.errors import BridgeUnavailableError
from core.models import ErrorCode
from core.platform.linux import LinuxAdapter
from tests.certs import make_chain

# Dữ liệu token/cert giả — CÙNG shape cho cả hai tuyến.
_root, _inter, _leaf = make_chain()
_LEAF_DER_B64 = base64.b64encode(_leaf.der).decode()

CANNED_TOKENS = [{
    "slot_id": 0, "label": "VN TOKEN", "manufacturer_id": "FEITIAN",
    "model": "ePass2003", "serial": "SN12345", "flags": 0x40004,
    "pin_state": {"login_required": True, "count_low": False, "final_try": False,
                  "locked": False, "protected_auth_path": False},
}]
CANNED_CERTS = [{"der_b64": _LEAF_DER_B64, "id_hex": "a1b2", "label": "chu ky"}]
CANNED_SIG = {"signature_b64": base64.b64encode(b"SIGNATURE").decode()}


class FakeOps:
    """Bản giả core.pkcs11_ops (tuyến in-process)."""

    def get_info(self, mp: str) -> dict[str, Any]:
        return {"ok": True, "cryptoki_version": [2, 40], "manufacturer": "X"}

    def enumerate_tokens(self, mp: str) -> list[dict[str, Any]]:
        return CANNED_TOKENS

    def read_certs(self, mp: str, slot_id: int, pin: str | None = None) -> list[dict[str, Any]]:
        return CANNED_CERTS

    def sign(self, mp: str, slot_id: int, key_id: str, mechanism: str,
             data_b64: str, pin: str | None = None) -> dict[str, Any]:
        return CANNED_SIG


class FakeManager:
    """Bản giả BridgeManager (tuyến bridge) trả CÙNG dữ liệu như FakeOps."""

    RESULTS = {
        "get_info": {"ok": True, "cryptoki_version": [2, 40], "manufacturer": "X"},
        "enumerate_tokens": CANNED_TOKENS,
        "read_certs": CANNED_CERTS,
        "sign": CANNED_SIG,
    }

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, module_path: str, method: str, params: dict[str, Any] | None = None,
             *, timeout: float | None = None) -> Any:
        self.calls.append((method, params or {}))
        return self.RESULTS[method]

    def close(self) -> None:
        pass


class FakeAdapter:
    def __init__(self, bridge: bool) -> None:
        self._bridge = bridge

    def name(self) -> str:
        return "linux"

    def needs_arch_bridge(self, path: Path) -> bool:
        return self._bridge


def _inproc(path: str = "/fake/mod.so") -> ModuleSession:
    return ModuleSession(path, adapter=FakeAdapter(False), ops=FakeOps())  # type: ignore[arg-type]


def _bridged(path: str = "/fake/mod.so") -> ModuleSession:
    return ModuleSession(path, adapter=FakeAdapter(True), manager=FakeManager())  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Kết quả GIỐNG HỆT bất kể tuyến                                                #
# --------------------------------------------------------------------------- #
def test_route_selection() -> None:
    assert _inproc().route == "in_process"
    assert _bridged().route == "bridge"


def test_enumerate_tokens_identical() -> None:
    a = _inproc().enumerate_tokens()
    b = _bridged().enumerate_tokens()
    assert [t.model_dump() for t in a] == [t.model_dump() for t in b]
    assert a[0].manufacturer_id == "FEITIAN"  # TRỤC 2: chip thật
    assert a[0].pin_state.login_required is True


def test_read_certs_identical_and_parsed() -> None:
    a = _inproc().read_certs(slot_id=0, pin="1234")
    b = _bridged().read_certs(slot_id=0, pin="1234")
    assert [c.model_dump() for c in a] == [c.model_dump() for c in b]
    assert a[0].subject == _leaf.cert.subject.rfc4514_string()  # parse DER ở host
    assert a[0].key_id_hex == "a1b2"


def test_sign_identical() -> None:
    data = b"hello"
    a = _inproc().sign(0, "a1b2", "SHA256_RSA_PKCS", data, pin="1234")
    b = _bridged().sign(0, "a1b2", "SHA256_RSA_PKCS", data, pin="1234")
    assert a == b == b"SIGNATURE"


def test_bridge_receives_data_b64_not_raw() -> None:
    sess = _bridged()
    sess.sign(0, "a1b2", "RSA_PKCS", b"\x00\x01raw", pin="1234")
    method, params = sess._manager.calls[-1]  # type: ignore[union-attr]
    assert method == "sign"
    assert params["data_b64"] == base64.b64encode(b"\x00\x01raw").decode()


# --------------------------------------------------------------------------- #
# Che PIN khỏi log                                                             #
# --------------------------------------------------------------------------- #
def test_pin_redacted_for_log() -> None:
    assert "pin" in SENSITIVE_FIELDS
    red = redact_params_for_log({"module_path": "/x", "slot_id": 0, "pin": "SECRET"})
    assert red["pin"] == "***"
    assert red["slot_id"] == 0
    assert "SECRET" not in str(red)


# --------------------------------------------------------------------------- #
# Vòng đời BridgeManager (subprocess thật)                                      #
# --------------------------------------------------------------------------- #
def test_manager_spawn_and_ping(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VN_ESIGN_BRIDGE_PYTHON", sys.executable)
    monkeypatch.delenv("VN_ESIGN_BRIDGE_LAUNCHER", raising=False)
    mgr = BridgeManager(LinuxAdapter())
    try:
        res = mgr.call("/fake/mod.so", "ping", {})
        assert res["pong"] is True
        assert mgr.active_helpers() == 1
    finally:
        mgr.close()
    assert mgr.active_helpers() == 0


def test_manager_auto_restart(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VN_ESIGN_BRIDGE_PYTHON", sys.executable)
    mgr = BridgeManager(LinuxAdapter())
    try:
        assert mgr.call("/fake/mod.so", "ping", {})["pong"] is True
        mgr._client._proc.kill()  # type: ignore[union-attr] - giả lập helper chết
        # Lần gọi sau: manager phát hiện chết -> restart -> vẫn trả pong.
        assert mgr.call("/fake/mod.so", "ping", {})["pong"] is True
    finally:
        mgr.close()


def test_manager_spawn_failure_remediation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VN_ESIGN_BRIDGE_PYTHON", raising=False)  # chưa cấu hình
    mgr = BridgeManager(LinuxAdapter())
    with pytest.raises(BridgeUnavailableError) as ei:
        mgr.call("/fake/mod.so", "ping", {})
    err = mgr.error_info(ei.value)
    assert err.code is ErrorCode.BRIDGE_UNAVAILABLE
    assert err.message_vi and "i386" in err.remediation  # remediation ĐÚNG Linux
    mgr.close()
