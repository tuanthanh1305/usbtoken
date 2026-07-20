"""Chống chịu lỗi cho kênh ra mạng: retry/backoff + circuit breaker.

An toàn để viết TRƯỚC (không phụ thuộc giao thức Cổng eSign): đây là hạ tầng
truyền tải chung. Circuit breaker chặn "bão gọi" khi Cổng lỗi kéo dài; retry với
backoff mũ xử lý lỗi mạng thoáng qua. Đồng hồ + hàm ngủ TIÊM ĐƯỢC để test không
cần chờ thực.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


class CircuitOpenError(RuntimeError):
    """Circuit đang MỞ — từ chối gọi để bảo vệ Cổng (fast-fail)."""


@dataclass(slots=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_base_seconds: float = 0.5
    backoff_max_seconds: float = 8.0

    def delay_for(self, attempt: int) -> float:
        """Độ trễ trước lần thử ``attempt`` (1-based) — backoff mũ, có trần."""
        if attempt <= 1:
            return 0.0
        raw = self.backoff_base_seconds * (2 ** (attempt - 2))
        return min(raw, self.backoff_max_seconds)


class CircuitBreaker:
    """Bộ ngắt mạch CLOSED → OPEN → HALF_OPEN.

    * CLOSED: cho gọi; đủ ``failure_threshold`` lỗi liên tiếp -> OPEN.
    * OPEN: fast-fail cho tới khi qua ``reset_timeout`` -> HALF_OPEN.
    * HALF_OPEN: cho MỘT lượt thử; thành công -> CLOSED, thất bại -> OPEN lại.
    """

    def __init__(
        self, *, failure_threshold: int = 5, reset_timeout: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._threshold = max(1, failure_threshold)
        self._reset_timeout = reset_timeout
        self._clock = clock
        self._failures = 0
        self._state = "closed"
        self._opened_at = 0.0

    @property
    def state(self) -> str:
        # Cho phép chuyển OPEN -> HALF_OPEN theo thời gian khi được hỏi.
        if self._state == "open" and (self._clock() - self._opened_at) >= self._reset_timeout:
            self._state = "half_open"
        return self._state

    def allow(self) -> bool:
        """Có được phép gọi ngay bây giờ không."""
        return self.state in ("closed", "half_open")

    def record_success(self) -> None:
        self._failures = 0
        self._state = "closed"

    def record_failure(self) -> None:
        if self.state == "half_open":
            self._trip()
            return
        self._failures += 1
        if self._failures >= self._threshold:
            self._trip()

    def _trip(self) -> None:
        self._state = "open"
        self._opened_at = self._clock()


def run_with_resilience(
    fn: Callable[[], T],
    *,
    retry: RetryPolicy,
    breaker: CircuitBreaker,
    is_retryable: Callable[[Exception], bool],
    sleep: Callable[[float], None] = time.sleep,
    on_attempt: Callable[[int, Exception | None], None] | None = None,
) -> T:
    """Chạy ``fn`` với circuit breaker + retry/backoff.

    ``is_retryable(exc)`` quyết định lỗi có đáng thử lại (lỗi mạng/5xx) hay không
    (4xx = lỗi client, KHÔNG thử lại). Circuit MỞ -> :class:`CircuitOpenError`.
    """
    last_exc: Exception | None = None
    for attempt in range(1, retry.max_attempts + 1):
        if not breaker.allow():
            raise CircuitOpenError("Circuit tới Cổng eSign đang MỞ — tạm dừng gọi.")
        delay = retry.delay_for(attempt)
        if delay:
            sleep(delay)
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            breaker.record_failure()
            if on_attempt is not None:
                on_attempt(attempt, exc)
            if not is_retryable(exc) or attempt >= retry.max_attempts:
                raise
            continue
        breaker.record_success()
        if on_attempt is not None:
            on_attempt(attempt, None)
        return result
    assert last_exc is not None  # pragma: no cover
    raise last_exc


__all__ = ["RetryPolicy", "CircuitBreaker", "CircuitOpenError", "run_with_resilience"]
