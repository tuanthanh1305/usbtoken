"""Nạp SPEC kết nối Cổng eSign từ ``data/compliance/esign_gateway_spec.yaml``.

⛔ Đây CHỈ là bộ nạp cấu hình. Nội dung spec (endpoint, định dạng bản tin, xác
thực) PHẢI đến từ Hướng dẫn kỹ thuật của Bộ KH&CN (Điều 8 TT 15/2025). Khi
``status`` chưa ``filled`` -> :meth:`EsignGatewaySpec.is_configured` = False và
gateway TỪ CHỐI mọi thao tác mạng (fail-closed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.config import esign_gateway_spec_path
from core.esign.resilience import CircuitBreaker, RetryPolicy

_FILLED_STATES = {"filled", "verified", "reviewed", "done"}


@dataclass(slots=True)
class OperationSpec:
    path: str = ""
    method: str = ""

    @property
    def defined(self) -> bool:
        return bool(self.path and self.method)


@dataclass(slots=True)
class EsignGatewaySpec:
    """Spec kết nối (đọc từ yaml). Rỗng/chưa điền -> KHÔNG dùng được."""

    status: str = "not_filled"
    base_url: str = ""
    message_format: str = ""
    auth_mechanism: str = ""
    verify_tls: bool = True
    tls_min_version: str = ""
    allowed_domains: tuple[str, ...] = ()
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    breaker_failure_threshold: int = 5
    breaker_reset_timeout: float = 30.0
    operations: dict[str, OperationSpec] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def filled(self) -> bool:
        return str(self.status).strip().lower() in _FILLED_STATES

    @property
    def is_configured(self) -> bool:
        """Đủ điều kiện để KẾT NỐI THẬT (fail-closed nếu thiếu bất kỳ điều kiện)."""
        return (
            self.filled
            and bool(self.base_url)
            and bool(self.allowed_domains)
            and any(op.defined for op in self.operations.values())
        )

    def operation(self, name: str) -> OperationSpec | None:
        op = self.operations.get(name)
        return op if (op and op.defined) else None

    def make_breaker(self, *, clock: Any = None) -> CircuitBreaker:
        kwargs: dict[str, Any] = {
            "failure_threshold": self.breaker_failure_threshold,
            "reset_timeout": self.breaker_reset_timeout,
        }
        if clock is not None:
            kwargs["clock"] = clock
        return CircuitBreaker(**kwargs)


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_spec(data: dict[str, Any] | None = None) -> EsignGatewaySpec:
    """Nạp spec từ yaml (hoặc từ ``data`` cho test). Không ném — trả spec rỗng nếu lỗi."""
    if data is None:
        from core.config import _load_yaml  # tái dùng loader an toàn

        data = _load_yaml(esign_gateway_spec_path())
    data = data or {}

    auth = data.get("auth") or {}
    tls = data.get("tls") or {}
    timeouts = data.get("timeouts") or {}
    retry = data.get("retry") or {}
    breaker = data.get("circuit_breaker") or {}
    ops_raw = data.get("operations") or {}

    domains = data.get("allowed_domains") or []
    operations = {
        name: OperationSpec(path=str((cfg or {}).get("path", "")), method=str((cfg or {}).get("method", "")))
        for name, cfg in ops_raw.items()
        if isinstance(cfg, dict)
    }
    return EsignGatewaySpec(
        status=str(data.get("status", "not_filled")),
        base_url=str(data.get("base_url", "")).strip(),
        message_format=str(data.get("message_format", "")).strip().lower(),
        auth_mechanism=str(auth.get("mechanism", "")).strip().lower(),
        verify_tls=bool(tls.get("verify", True)),
        tls_min_version=str(tls.get("min_version", "")),
        allowed_domains=tuple(str(d).strip().lower() for d in domains if str(d).strip()),
        connect_timeout=_as_float(timeouts.get("connect_seconds"), 10.0),
        read_timeout=_as_float(timeouts.get("read_seconds"), 30.0),
        retry=RetryPolicy(
            max_attempts=_as_int(retry.get("max_attempts"), 3),
            backoff_base_seconds=_as_float(retry.get("backoff_base_seconds"), 0.5),
            backoff_max_seconds=_as_float(retry.get("backoff_max_seconds"), 8.0),
        ),
        breaker_failure_threshold=_as_int(breaker.get("failure_threshold"), 5),
        breaker_reset_timeout=_as_float(breaker.get("reset_timeout_seconds"), 30.0),
        operations=operations,
        raw=data,
    )


__all__ = ["EsignGatewaySpec", "OperationSpec", "load_spec"]
