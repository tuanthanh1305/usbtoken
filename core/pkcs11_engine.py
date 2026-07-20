"""Engine liệt kê token — CHUNG 3 OS. Đặc thù đi qua adapter/bridge.

``enumerate_tokens(modules)`` nạp từng module (in-process nếu cùng arch, qua
bridge nếu lệch) và trả ``list[TokenInfo]``. Mỗi module dùng MỘT instance
``PyKCS11Lib`` RIÊNG (nhiều module chung một tiến trình dễ xung đột global
state); PyKCS11.load() gọi ``C_Initialize`` với ``CKF_OS_LOCKING_OK`` (an toàn
daemon đa luồng) và ``core/pkcs11_ops`` còn tuần tự hoá thêm bằng khoá.

⭐ TRỤC 2 — CHIP THẬT: ``TokenInfo.manufacturer_id`` + ``model`` đọc từ
``C_GetTokenInfo``, ghi nhận ĐỘC LẬP với tên module. Đây là cách hoá giải Track
B: nạp bằng ``fptca_v4.so`` (tên CA) nhưng vẫn biết CHIP thật của hãng nào.

CÔ LẬP LỖI: một module fail TUYỆT ĐỐI không làm sập tiến trình hay chặn module
khác — try/finally C_Finalize (trong ops), timeout mỗi module, giải phóng instance.

CLI: ``python -m core.pkcs11_engine --list`` | ``--json``.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from core.bridge import BridgeManager, ModuleSession
from core.discovery import discover_modules
from core.errors import BridgeUnavailableError, VNeSignError
from core.models import ErrorCode, ErrorInfo, ModuleCandidate, TokenInfo
from core.platform import PlatformAdapter, get_adapter

DEFAULT_PER_MODULE_TIMEOUT = 8.0


class ModuleReport(BaseModel):
    """Kết quả xử lý MỘT module (phục vụ chẩn đoán, không chặn module khác)."""

    module_path: str
    track: str = ""
    chip_hint: str = ""
    arch: str = "unknown"
    via_bridge: bool = False
    token_count: int = 0
    error: ErrorInfo | None = None


class EngineResult(BaseModel):
    """Tổng hợp: token tìm được + báo cáo từng module."""

    tokens: list[TokenInfo] = []
    reports: list[ModuleReport] = []


def enumerate_detailed(
    modules: list[ModuleCandidate] | None = None,
    *,
    adapter: PlatformAdapter | None = None,
    manager: BridgeManager | None = None,
    per_module_timeout: float = DEFAULT_PER_MODULE_TIMEOUT,
    ops: Any = None,
) -> EngineResult:
    """Liệt kê token trên các module, cô lập lỗi từng module."""
    ad = adapter or get_adapter()
    if modules is None:
        modules = discover_modules(ad)  # đường nhanh (Tầng 1-3)

    own_manager = manager is None
    mgr = manager or BridgeManager(ad)

    tokens: list[TokenInfo] = []
    reports: list[ModuleReport] = []
    try:
        for cand in modules:
            report = ModuleReport(
                module_path=cand.path, track=cand.track.value,
                chip_hint=cand.chip_hint, arch=cand.arch,
            )
            try:
                toks = _enumerate_one(ad, cand, mgr, per_module_timeout, ops)
                report.via_bridge = toks[0].via_bridge if toks else _via_bridge(ad, cand)
                report.token_count = len(toks)
                tokens.extend(toks)
            except BridgeUnavailableError as exc:
                report.error = mgr.error_info(exc)
                report.via_bridge = True
            except TimeoutError:
                report.error = _err(
                    ad, ErrorCode.INTERNAL_ERROR,
                    f"Module phản hồi quá {per_module_timeout:g}s — bỏ qua để không chặn module khác.",
                    remediation="Kiểm tra middleware/token có treo; hoặc tăng timeout.",
                )
            except VNeSignError as exc:
                report.error = _err(ad, exc.code, exc.message, detail=exc.detail)
            except Exception as exc:  # noqa: BLE001 - CÔ LẬP mọi lỗi khác
                report.error = _err(ad, ErrorCode.INTERNAL_ERROR, f"Lỗi khi liệt kê: {exc}")
            reports.append(report)
    finally:
        if own_manager:
            mgr.close()

    return EngineResult(tokens=tokens, reports=reports)


def enumerate_tokens(
    modules: list[ModuleCandidate] | None = None,
    *,
    adapter: PlatformAdapter | None = None,
    manager: BridgeManager | None = None,
    per_module_timeout: float = DEFAULT_PER_MODULE_TIMEOUT,
    ops: Any = None,
) -> list[TokenInfo]:
    """Trả list[TokenInfo] (bọc mỏng quanh :func:`enumerate_detailed`)."""
    return enumerate_detailed(
        modules, adapter=adapter, manager=manager,
        per_module_timeout=per_module_timeout, ops=ops,
    ).tokens


def _enumerate_one(
    adapter: PlatformAdapter,
    cand: ModuleCandidate,
    manager: BridgeManager,
    timeout: float,
    ops: Any,
) -> list[TokenInfo]:
    """Liệt kê token cho MỘT module (in-process hoặc bridge), có timeout."""
    session = ModuleSession(cand.path, adapter=adapter, manager=manager, ops=ops)
    try:
        tokens = _run_with_timeout(session.enumerate_tokens, timeout)
    finally:
        session.close()  # không đóng manager (được chia sẻ)

    via_bridge = session.needs_bridge
    for tok in tokens:
        # Enrich metadata TRỤC 1 (tên module) — KHÔNG đụng manufacturer_id (chip thật).
        tok.track = cand.track.value
        tok.chip_hint = cand.chip_hint
        tok.source = cand.source
        tok.arch = cand.arch
        tok.via_bridge = via_bridge
    return tokens


def _via_bridge(adapter: PlatformAdapter, cand: ModuleCandidate) -> bool:
    from pathlib import Path

    try:
        return adapter.needs_arch_bridge(Path(cand.path))
    except (OSError, NotImplementedError):
        return False


def _run_with_timeout(fn: Callable[[], Any], timeout: float) -> Any:
    """Chạy ``fn`` trong luồng riêng + timeout (module treo không chặn tiến trình)."""
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            box["r"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["e"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError("hết thời gian chờ module")
    if "e" in box:
        raise box["e"]
    return box.get("r", [])


def _err(
    adapter: PlatformAdapter, code: ErrorCode, message: str, *,
    remediation: str = "", detail: str = "",
) -> ErrorInfo:
    return ErrorInfo(
        code=code, message_vi=message, remediation=remediation,
        platform=adapter.name(), detail=detail,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #
def _print_table(result: EngineResult) -> None:
    print(f"Token tìm được: {len(result.tokens)}")
    print("-" * 80)
    for t in result.tokens:
        pin = [n for n, v in (
            ("PIN-thấp", t.pin_state.count_low), ("lần-cuối", t.pin_state.final_try),
            ("ĐÃ-KHOÁ", t.pin_state.locked), ("pinpad", t.pin_state.protected_auth_path),
        ) if v]
        pin_s = (" [" + ",".join(pin) + "]") if pin else ""
        bridge = " ·via-bridge" if t.via_bridge else ""
        # ⭐ Phân biệt CHIP THẬT (TRỤC 2) với GỢI Ý từ tên module (TRỤC 1).
        print(f"  • CHIP THẬT: {t.manufacturer_id or '(trống)'} / {t.model or '-'} · "
              f"slot {t.slot_id} · {t.label or '(không nhãn)'} · SN={t.serial or '-'}{pin_s}")
        print(f"      module: [Track {t.track}] gợi-ý='{t.chip_hint or '-'}' · {t.arch}{bridge}")
        print(f"      {t.module_path}")
    if result.reports:
        errs = [r for r in result.reports if r.error]
        print("-" * 80)
        print(f"Module đã thử: {len(result.reports)} · lỗi: {len(errs)}")
        for r in errs:
            assert r.error is not None
            print(f"  ✗ [{r.error.code.value}] {r.module_path}")
            print(f"      {r.error.message_vi}")
            if r.error.remediation:
                for line in r.error.remediation.splitlines():
                    print(f"       {line}")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m core.pkcs11_engine")
    parser.add_argument("--list", action="store_true", help="In bảng token (mặc định).")
    parser.add_argument("--json", action="store_true", help="Xuất JSON đầy đủ.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_PER_MODULE_TIMEOUT)
    args = parser.parse_args(argv)

    result = enumerate_detailed(per_module_timeout=args.timeout)
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        _print_table(result)
    return 0 if result.tokens else 1


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["enumerate_tokens", "enumerate_detailed", "EngineResult", "ModuleReport"]
