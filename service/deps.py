"""Bộ phụ thuộc của daemon — GẮN vào ``app.state.deps``.

Mọi collaborator (adapter, kho phiên, rate-limit, bridge, validator, quét
token, đọc cert, nguồn sự kiện) đều TIÊM ĐƯỢC để test không cần token/mạng.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from core.models import AggregateResult, TokenInfo
from core.platform import PlatformAdapter, get_adapter
from service.security import (
    DEFAULT_ALLOWED_HOSTS,
    DEFAULT_ALLOWED_ORIGINS,
    RateLimiter,
)
from service.sessions import SessionStore

# Chữ ký các hàm tiêm.
AggregateFn = Callable[..., AggregateResult]
EnumerateFn = Callable[[], list[TokenInfo]]
ReadFn = Callable[..., Any]  # (token, pin_callback) -> CertReadResult
ValidatorFactory = Callable[[], Any]  # () -> CertificateValidator
EventsSourceFactory = Callable[[], Any]  # () -> đối tượng có .readers()/.poll()


@dataclass
class ServiceDeps:
    adapter: PlatformAdapter
    sessions: SessionStore
    login_limiter: RateLimiter
    bridge: Any  # BridgeManager (lazy, đóng khi shutdown)
    validator_factory: ValidatorFactory
    aggregate_fn: AggregateFn
    enumerate_fn: EnumerateFn
    read_fn: ReadFn
    signer_factory: Callable[[], Any]  # () -> core.signer.Signer
    events_source_factory: EventsSourceFactory
    allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS
    event_poll_interval: float = 1.0
    extra: dict[str, Any] = field(default_factory=dict)

    def bridge_active(self) -> bool:
        try:
            return bool(self.bridge.active_helpers())
        except Exception:  # noqa: BLE001
            return False

    def close(self) -> None:
        """Tắt sạch: zeroize mọi phiên PIN + đóng bridge helper."""
        try:
            self.sessions.clear()
        finally:
            try:
                self.bridge.close()
            except Exception:  # noqa: BLE001
                pass


def build_default_deps(adapter: PlatformAdapter | None = None) -> ServiceDeps:
    """Dựng bộ phụ thuộc THẬT (dùng khi chạy daemon thực tế)."""
    from core.aggregator import merge_all_sources
    from core.bridge import BridgeManager
    from core.cert_reader import read_certificates
    from core.pcsc_probe import PCSCProbe
    from core.pkcs11_engine import enumerate_tokens
    from core.signer import Signer
    from core.trust.validator import CertificateValidator

    ad = adapter or get_adapter()

    def aggregate(**kwargs: Any) -> AggregateResult:
        return merge_all_sources(ad, **kwargs)

    def enumerate_() -> list[TokenInfo]:
        return enumerate_tokens(adapter=ad)

    return ServiceDeps(
        adapter=ad,
        sessions=SessionStore(),
        login_limiter=RateLimiter(),
        bridge=BridgeManager(ad),
        validator_factory=lambda: CertificateValidator(),
        aggregate_fn=aggregate,
        enumerate_fn=enumerate_,
        read_fn=read_certificates,
        signer_factory=lambda: Signer(adapter=ad),
        events_source_factory=lambda: PcscEventsSource(PCSCProbe(ad)),
    )


# Import trễ để tránh vòng phụ thuộc ở đầu file.
from service.runtime import PcscEventsSource  # noqa: E402


__all__ = ["ServiceDeps", "build_default_deps"]
