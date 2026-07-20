"""Thăm dò PC/SC (pyscard) — API CHUNG, backend khác theo OS.

Trước mọi thao tác PC/SC phải kiểm ``adapter.pcsc_backend_ready()``; chưa sẵn
sàng -> :class:`ErrorInfo` + remediation ĐÚNG OS (Linux systemctl pcscd · Win
sc start SCardSvr · mac cảnh báo xung đột pcsc-lite Homebrew).

Chức năng:
    * :meth:`list_readers` — liệt kê đầu đọc.
    * :meth:`read_atr` — đọc ATR (bytes) của thẻ trong một đầu đọc.
    * :meth:`fingerprint_by_atr` — đoán CHIP từ ATR (bảng ngoài, cập nhật được)
      để discovery ưu tiên đúng module thay vì nạp mù.
    * :meth:`watch_events` — cắm/rút realtime (CardMonitor; fallback polling 1s).

⚠️ ATR CHỈ để TỐI ƯU thứ tự dò. TUYỆT ĐỐI không dùng ATR để kết luận CA — CA
chỉ xác định bằng chain building (PROMPT 9). Vì vậy :class:`AtrFingerprint`
KHÔNG có bất kỳ trường nào về CA.

pyscard được nạp LƯỜI: thiếu pyscard -> coi như backend chưa sẵn sàng (ErrorInfo).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any, Protocol

import yaml
from pydantic import BaseModel

from core.config import atr_table_path
from core.errors import PCSCNotReadyError
from core.models import ErrorCode, ErrorInfo
from core.platform import PlatformAdapter, get_adapter


# --------------------------------------------------------------------------- #
# Backend (mặc định pyscard; test tiêm bản giả)                                 #
# --------------------------------------------------------------------------- #
class PCSCBackend(Protocol):
    def list_readers(self) -> list[str]: ...
    def read_atr(self, reader_name: str) -> bytes | None: ...


class PyscardBackend:
    """Backend thật dùng pyscard (nạp lười)."""

    def list_readers(self) -> list[str]:
        from smartcard.System import readers  # type: ignore[import-untyped]

        return [str(r) for r in readers()]

    def read_atr(self, reader_name: str) -> bytes | None:
        from smartcard.System import readers  # type: ignore[import-untyped]

        for r in readers():
            if str(r) != reader_name:
                continue
            try:
                conn = r.createConnection()
                conn.connect()  # kết nối tới thẻ (lỗi nếu không có thẻ)
                atr = bytes(conn.getATR())
                conn.disconnect()
                return atr
            except Exception:  # noqa: BLE001 - không có thẻ / lỗi đọc
                return None
        return None


# --------------------------------------------------------------------------- #
# Kết quả fingerprint (KHÔNG có trường CA — ATR không kết luận CA)              #
# --------------------------------------------------------------------------- #
class AtrFingerprint(BaseModel):
    """Gợi ý CHIP từ ATR — KHÔNG có trường nào về CA (ATR không kết luận CA)."""

    atr_hex: str
    matched: bool = False
    description: str = ""
    chip_hint: str = ""
    module_hints: list[str] = []
    verified: bool = False
    confidence: str = "unknown"  # unknown | low | medium (KHÔNG bao giờ high)
    source: str = ""
    note: str = "ATR chỉ để tối ưu thứ tự dò — KHÔNG kết luận CA (dùng chain building)."


class PCSCProbe:
    """Đầu mối thăm dò PC/SC (API chung 3 OS)."""

    def __init__(self, adapter: PlatformAdapter | None = None, backend: PCSCBackend | None = None) -> None:
        self.adapter = adapter or get_adapter()
        self.backend = backend or PyscardBackend()

    # -- Kiểm tra sẵn sàng --------------------------------------------- #
    def readiness(self) -> tuple[bool, ErrorInfo | None]:
        """(ready, ErrorInfo|None). Remediation lấy từ adapter (đúng OS)."""
        ready, remediation = self.adapter.pcsc_backend_ready()
        if ready:
            return True, None
        return False, ErrorInfo(
            code=ErrorCode.PCSC_NOT_READY,
            message_vi="Tầng PC/SC chưa sẵn sàng (không giao tiếp được đầu đọc/token).",
            remediation=remediation,
            platform=self.adapter.name(),  # type: ignore[arg-type]
        )

    def _require_ready(self) -> None:
        ready, err = self.readiness()
        if not ready:
            assert err is not None
            raise PCSCNotReadyError(err.message_vi, detail=err.remediation)

    # -- Liệt kê / đọc ATR --------------------------------------------- #
    def list_readers(self) -> list[str]:
        self._require_ready()
        try:
            return self.backend.list_readers()
        except Exception as exc:  # noqa: BLE001 - thiếu pyscard/pcscd
            _, remediation = self.adapter.pcsc_backend_ready()
            raise PCSCNotReadyError(
                "Không liệt kê được đầu đọc PC/SC (thiếu pyscard hoặc pcscd).",
                detail=remediation or str(exc),
            ) from exc

    def read_atr(self, reader_name: str) -> bytes | None:
        self._require_ready()
        try:
            return self.backend.read_atr(reader_name)
        except Exception:  # noqa: BLE001
            return None

    # -- Fingerprint ATR ----------------------------------------------- #
    def fingerprint_by_atr(self, atr: bytes) -> AtrFingerprint:
        """Đoán CHIP từ ATR (chỉ để tối ưu thứ tự dò). Không khớp -> unknown."""
        return fingerprint_by_atr(atr, os_name=self.adapter.name())

    # -- Theo dõi cắm/rút ---------------------------------------------- #
    def poll_diff(
        self, previous: dict[str, str]
    ) -> tuple[list[dict[str, str]], dict[str, str]]:
        """So sánh trạng thái thẻ hiện tại với ``previous`` -> (events, current).

        ``state`` map ``reader -> atr_hex`` ("" nếu không có thẻ). Dùng cho
        fallback polling và test (không cần luồng nền).
        """
        current: dict[str, str] = {}
        for reader in self.backend.list_readers():
            atr = self.backend.read_atr(reader)
            current[reader] = atr.hex() if atr else ""

        events: list[dict[str, str]] = []
        for reader, atr_hex in current.items():
            prev = previous.get(reader, "")
            if atr_hex and atr_hex != prev:
                events.append({"action": "inserted", "reader": reader, "atr": atr_hex})
            elif not atr_hex and prev:
                events.append({"action": "removed", "reader": reader, "atr": ""})
        for reader, prev in previous.items():
            if reader not in current and prev:
                events.append({"action": "removed", "reader": reader, "atr": ""})
        return events, current

    def watch_events(
        self,
        callback: Callable[[dict[str, str]], None],
        *,
        poll_interval: float = 1.0,
        stop: Callable[[], bool] | None = None,
        use_monitor: bool = True,
    ) -> None:
        """Theo dõi cắm/rút realtime tới khi ``stop()`` True.

        Ưu tiên pyscard CardMonitor; không có -> fallback polling ``poll_interval``
        giây + so diff. Mỗi sự kiện gọi ``callback(event)``.
        """
        self._require_ready()
        if use_monitor and self._try_card_monitor(callback, stop):
            return
        # Fallback polling.
        state: dict[str, str] = {}
        while not (stop and stop()):
            try:
                events, state = self.poll_diff(state)
            except Exception:  # noqa: BLE001 - đầu đọc biến mất tạm thời
                events = []
            for ev in events:
                callback(ev)
            time.sleep(poll_interval)

    def _try_card_monitor(
        self, callback: Callable[[dict[str, str]], None], stop: Callable[[], bool] | None
    ) -> bool:
        """Thử pyscard CardMonitor. Trả True nếu đã thiết lập (chạy nền)."""
        try:
            from smartcard.CardMonitoring import (  # type: ignore[import-untyped]
                CardMonitor,
                CardObserver,
            )
        except Exception:  # noqa: BLE001
            return False

        class _Observer(CardObserver):  # type: ignore[misc]
            def update(self, observable: Any, actions: Any) -> None:
                added, removed = actions
                for card in added:
                    callback({"action": "inserted", "reader": str(getattr(card, "reader", "")),
                              "atr": bytes(getattr(card, "atr", b"")).hex()})
                for card in removed:
                    callback({"action": "removed", "reader": str(getattr(card, "reader", "")),
                              "atr": ""})

        monitor = CardMonitor()
        observer = _Observer()
        monitor.addObserver(observer)
        try:
            while not (stop and stop()):
                time.sleep(0.2)
        finally:
            monitor.deleteObserver(observer)
        return True


# --------------------------------------------------------------------------- #
# Bảng ATR (nạp từ file ngoài, cập nhật được)                                   #
# --------------------------------------------------------------------------- #
def _normalize_atr(atr_hex: str) -> str:
    return re.sub(r"[^0-9A-Fa-f.]", "", atr_hex).upper()


def _atr_regex(pattern: str) -> re.Pattern[str]:
    """Chuyển mẫu ATR (hex + '.' wildcard nibble) thành regex full-match."""
    norm = _normalize_atr(pattern)
    body = "".join("[0-9A-F]" if ch == "." else ch for ch in norm)
    return re.compile(f"^{body}$")


def load_atr_table(path: Any = None) -> dict[str, Any]:
    p = path or atr_table_path()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _module_hints_for(description: str, os_name: str) -> list[str]:
    """Suy module_hints bằng cách khớp description với chip_vendor trong intel."""
    from core.intel import load_intel

    desc = description.lower()
    hints: list[str] = []
    for entry in load_intel().filter(os_name=os_name, track="A"):
        vendor_tokens = re.split(r"[/\s]+", entry.chip_vendor.lower())
        if any(tok and tok in desc for tok in vendor_tokens):
            for fn in entry.filenames:
                if fn not in hints:
                    hints.append(fn)
    return hints


def fingerprint_by_atr(
    atr: bytes, *, os_name: str = "linux", table: dict[str, Any] | None = None
) -> AtrFingerprint:
    """Khớp ATR với bảng -> :class:`AtrFingerprint`. Không khớp -> unknown."""
    atr_hex = atr.hex().upper()
    fp = AtrFingerprint(atr_hex=atr_hex)
    data = table if table is not None else load_atr_table()
    fp.source = str(data.get("source", ""))
    for entry in data.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        try:
            rx = _atr_regex(str(entry.get("atr", "")))
        except re.error:
            continue
        if rx.match(atr_hex):
            fp.matched = True
            fp.description = str(entry.get("description", ""))
            fp.verified = bool(entry.get("verified", False))
            fp.chip_hint = fp.description
            fp.module_hints = _module_hints_for(fp.description, os_name)
            # Không bao giờ "high": ATR chỉ để tối ưu, không phải bằng chứng.
            fp.confidence = "medium" if "." not in _normalize_atr(str(entry.get("atr", ""))) else "low"
            return fp
    return fp


__all__ = [
    "PCSCProbe", "PyscardBackend", "PCSCBackend", "AtrFingerprint",
    "fingerprint_by_atr", "load_atr_table",
]
