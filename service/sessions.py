"""Phiên đăng nhập PIN — LƯU TRONG RAM, TTL ngắn, ZEROIZE khi hết hạn/logout.

AN TOÀN PIN (bắt buộc, theo đặc tả):
    * PIN chỉ tồn tại trong RAM dưới dạng ``bytearray`` (ghi đè 0 được), TUYỆT
      ĐỐI KHÔNG lưu đĩa, KHÔNG log.
    * Mỗi phiên có TTL ngắn; hết hạn -> zeroize + xoá. Logout -> zeroize ngay.
    * Session id là chuỗi ngẫu nhiên mật mã (``secrets``), KHÔNG đoán được.

⚠️ PIN đến daemon qua JSON nên có một bản ``str`` bất biến thoáng qua ở tầng
HTTP; tầng này chuyển sang ``bytearray`` NGAY và chỉ giữ bản bytearray đó.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Callable

DEFAULT_TTL_SECONDS = 120.0


def _to_bytearray(raw: bytes | bytearray | str) -> bytearray:
    if isinstance(raw, bytearray):
        return raw
    if isinstance(raw, bytes):
        return bytearray(raw)
    return bytearray(str(raw).encode("utf-8"))


class PinSession:
    """Một phiên: PIN (bytearray) + token gắn kèm + hạn dùng (đồng hồ monotonic)."""

    __slots__ = ("id", "token_id", "_pin", "created_at", "expires_at")

    def __init__(
        self, session_id: str, token_id: str, pin: bytearray,
        created_at: float, expires_at: float,
    ) -> None:
        self.id = session_id
        self.token_id = token_id
        self._pin = pin
        self.created_at = created_at
        self.expires_at = expires_at

    def pin_bytes(self) -> bytes:
        """Bản sao PIN để đẩy MỘT CHIỀU vào token (caller nên zeroize bản của mình)."""
        return bytes(self._pin)

    def zeroize(self) -> None:
        """Ghi đè 0 lên vùng nhớ PIN (không dùng str bất biến)."""
        for i in range(len(self._pin)):
            self._pin[i] = 0


class SessionStore:
    """Kho phiên PIN an toàn luồng, tự hết hạn + zeroize."""

    def __init__(
        self, *, ttl: float = DEFAULT_TTL_SECONDS, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._by_id: dict[str, PinSession] = {}

    @property
    def ttl(self) -> float:
        return self._ttl

    def login(self, token_id: str, pin: bytes | bytearray | str) -> PinSession:
        """Tạo phiên mới cho ``token_id`` (PIN chuyển sang bytearray, giữ trong RAM)."""
        now = self._clock()
        session = PinSession(
            session_id=secrets.token_urlsafe(24),
            token_id=token_id,
            pin=_to_bytearray(pin),
            created_at=now,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._by_id[session.id] = session
        return session

    def get(self, session_id: str) -> PinSession | None:
        """Trả phiên còn hạn; nếu hết hạn -> zeroize + xoá + trả None (fail-closed)."""
        with self._lock:
            session = self._by_id.get(session_id)
            if session is None:
                return None
            if self._clock() >= session.expires_at:
                session.zeroize()
                del self._by_id[session_id]
                return None
            return session

    def logout(self, session_id: str) -> bool:
        """Đăng xuất: zeroize + xoá. Trả True nếu có phiên để xoá."""
        with self._lock:
            session = self._by_id.pop(session_id, None)
        if session is None:
            return False
        session.zeroize()
        return True

    def sweep(self) -> int:
        """Quét & zeroize mọi phiên hết hạn. Trả số phiên đã dọn."""
        now = self._clock()
        removed = 0
        with self._lock:
            for sid in list(self._by_id.keys()):
                if now >= self._by_id[sid].expires_at:
                    self._by_id[sid].zeroize()
                    del self._by_id[sid]
                    removed += 1
        return removed

    def clear(self) -> None:
        """Tắt daemon: zeroize TẤT CẢ phiên (không để PIN sót lại trong RAM)."""
        with self._lock:
            for session in self._by_id.values():
                session.zeroize()
            self._by_id.clear()

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._by_id)


__all__ = ["PinSession", "SessionStore", "DEFAULT_TTL_SECONDS"]
