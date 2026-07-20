"""Tầng THỐNG NHẤT — gọi module PKCS#11 GIỐNG HỆT dù in-process hay qua bridge.

:class:`ModuleSession` tự quyết định tuyến dựa trên
``adapter.needs_arch_bridge(module)``:
    * cùng arch  -> gọi TRỰC TIẾP ``core.pkcs11_ops`` trong tiến trình daemon.
    * lệch arch  -> gọi qua :class:`BridgeManager` -> helper (subprocess).

Cả hai tuyến chạy CÙNG mã ``core.pkcs11_ops`` và trả dict JSON GIỐNG HỆT, nên
việc map sang :class:`TokenInfo`/:class:`CertInfo` là DUY NHẤT — tầng trên không
cần biết token được nạp bằng cách nào.

⚠️ ``pin`` đi thẳng tới ops/helper để login, KHÔNG được log ở bất kỳ đâu.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from core import pkcs11_ops
from core.models import CertInfo, PinState, TokenInfo
from core.platform import PlatformAdapter, get_adapter

from .manager import BridgeManager
from .protocol import (
    M_ENUMERATE,
    M_GET_INFO,
    M_GET_MECHANISMS,
    M_READ_CERTS,
    M_SIGN,
)


def _safe_needs_bridge(adapter: PlatformAdapter, path: Path) -> bool:
    try:
        return adapter.needs_arch_bridge(path)
    except (OSError, NotImplementedError):
        return False


class ModuleSession:
    """Phiên làm việc với MỘT module — API thống nhất (in-process hoặc bridge)."""

    def __init__(
        self,
        module_path: str,
        adapter: PlatformAdapter | None = None,
        *,
        manager: BridgeManager | None = None,
        ops: Any = None,
    ) -> None:
        self.adapter = adapter or get_adapter()
        self.path = Path(module_path)
        self._ops = ops or pkcs11_ops
        self._needs_bridge = _safe_needs_bridge(self.adapter, self.path)
        self._manager = manager
        self._owns_manager = manager is None

    @property
    def needs_bridge(self) -> bool:
        return self._needs_bridge

    @property
    def route(self) -> str:
        return "bridge" if self._needs_bridge else "in_process"

    # -- Định tuyến chung ----------------------------------------------- #
    def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Gọi ``method`` với ``params`` — CÙNG shape trả về bất kể tuyến."""
        params = params or {}
        if self._needs_bridge:
            return self._get_manager().call(str(self.path), method, params)
        # In-process: gọi thẳng ops với CÙNG bộ tham số.
        fn = getattr(self._ops, method)
        return fn(str(self.path), **params)

    def _get_manager(self) -> BridgeManager:
        if self._manager is None:
            self._manager = BridgeManager(self.adapter)
        return self._manager

    # -- API nghiệp vụ (trả model GIỐNG HỆT) ---------------------------- #
    def get_info(self) -> dict[str, Any]:
        result = self._call(M_GET_INFO)
        return dict(result) if isinstance(result, dict) else {"ok": False}

    def enumerate_tokens(self) -> list[TokenInfo]:
        raw = self._call(M_ENUMERATE)
        return [self._to_token(d) for d in (raw or [])]

    def read_certs(self, slot_id: int, pin: str | None = None) -> list[CertInfo]:
        params: dict[str, Any] = {"slot_id": slot_id}
        if pin is not None:
            params["pin"] = pin  # ⚠️ nhạy cảm
        raw = self._call(M_READ_CERTS, params)
        return [self._to_cert(d) for d in (raw or [])]

    def get_mechanisms(self, slot_id: int) -> list[str]:
        """Cơ chế token hỗ trợ (tên KHÔNG tiền tố CKM_) — cùng shape mọi tuyến."""
        raw = self._call(M_GET_MECHANISMS, {"slot_id": slot_id})
        return [str(m) for m in (raw or [])]

    def sign(
        self, slot_id: int, key_id: str, mechanism: str, data: bytes, pin: str | None = None
    ) -> bytes:
        params: dict[str, Any] = {
            "slot_id": slot_id,
            "key_id": key_id,
            "mechanism": mechanism,
            "data_b64": base64.b64encode(data).decode("ascii"),
        }
        if pin is not None:
            params["pin"] = pin  # ⚠️ nhạy cảm
        result = self._call(M_SIGN, params)
        sig_b64 = (result or {}).get("signature_b64", "")
        return base64.b64decode(sig_b64) if sig_b64 else b""

    def close(self) -> None:
        if self._manager is not None and self._owns_manager:
            self._manager.close()
            self._manager = None

    def __enter__(self) -> ModuleSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- Map dict -> model (DUY NHẤT cho cả hai tuyến) ------------------ #
    def _to_token(self, d: dict[str, Any]) -> TokenInfo:
        ps = d.get("pin_state") or {}
        return TokenInfo(
            module_path=str(self.path),
            slot_id=int(d.get("slot_id", -1)),
            label=str(d.get("label", "")),
            manufacturer_id=str(d.get("manufacturer_id", "")),
            model=str(d.get("model", "")),
            serial=str(d.get("serial", "")),
            flags=int(d.get("flags", 0)),
            pin_state=PinState(
                login_required=bool(ps.get("login_required", True)),
                count_low=bool(ps.get("count_low", False)),
                final_try=bool(ps.get("final_try", False)),
                locked=bool(ps.get("locked", False)),
                protected_auth_path=bool(ps.get("protected_auth_path", False)),
            ),
        )

    @staticmethod
    def _to_cert(d: dict[str, Any]) -> CertInfo:
        """Parse DER -> CertInfo ở HOST (dùng x509_parser DUY NHẤT)."""
        from core import x509_parser

        der_b64 = str(d.get("der_b64", ""))
        if not der_b64:
            return CertInfo(der_b64=der_b64, key_id_hex=str(d.get("id_hex", "")))
        info = x509_parser.parse(base64.b64decode(der_b64))
        info.key_id_hex = str(d.get("id_hex", ""))
        return info


__all__ = ["ModuleSession"]
