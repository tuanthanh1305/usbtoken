"""Kết nối Cổng eSign công cộng — KHUNG TRỪU TƯỢNG (fail-closed).

CĂN CỨ: Điều 44 NĐ 23/2025/NĐ-CP; Điều 7 & Điều 8 TT 15/2025/TT-BKHCN. Phần mềm
ký số phải có khả năng kết nối TRỰC TIẾP với Cổng kết nối dịch vụ chứng thực chữ
ký số công cộng, tuân thủ "Hướng dẫn kỹ thuật về kết nối" do Bộ KH&CN ban hành.

⛔ CHƯA HIỆN THỰC — CHỜ HƯỚNG DẪN KỸ THUẬT CỦA BỘ KH&CN.
    Giao thức / endpoint / định dạng bản tin / cơ chế xác thực CHỈ được biết qua
    văn bản đó (Điều 8). KHÔNG suy đoán. Khi spec chưa điền, factory trả
    :class:`NullEsignGateway` — mọi thao tác đều TỪ CHỐI kèm hướng dẫn.

An toàn để viết TRƯỚC (không phụ thuộc giao thức): interface + hạ tầng truyền
tải đã gia cố (allowlist domain, BẮT BUỘC TLS verify, retry/backoff, circuit
breaker, audit log KHÔNG lộ dữ liệu nhạy cảm). Phần đặc thù giao thức (endpoint,
mã hoá bản tin, xác thực) do spec cấp — trống thì không chạy.
"""

from __future__ import annotations

import abc
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from core.errors import ESignGatewayError
from core.esign.resilience import CircuitBreaker, CircuitOpenError, run_with_resilience
from core.esign.spec import EsignGatewaySpec, load_spec

_log = logging.getLogger("vn_esign.esign")

_NOT_READY = (
    "CHƯA HIỆN THỰC — CHỜ HƯỚNG DẪN KỸ THUẬT CỦA BỘ KH&CN (Điều 8 TT 15/2025). "
    "Liên hệ NEAC (115 Trần Duy Hưng, Hà Nội) lấy văn bản chính thức, điền "
    "data/compliance/esign_gateway_spec.yaml rồi đặt status: filled."
)


# --------------------------------------------------------------------------- #
# Kiểu truyền tải (tiêm được -> mock server cho CI)                             #
# --------------------------------------------------------------------------- #
class TransportError(RuntimeError):
    """Lỗi mạng ở tầng truyền tải (đáng thử lại)."""


@dataclass(slots=True)
class HttpResponse:
    status_code: int
    content: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


class Transport(abc.ABC):
    """Hợp đồng truyền tải HTTP tối giản (để tiêm mock trong test)."""

    @abc.abstractmethod
    def request(
        self, method: str, url: str, *, headers: dict[str, str], content: bytes,
        connect_timeout: float, read_timeout: float, verify: bool,
    ) -> HttpResponse: ...


class HttpxTransport(Transport):
    """Truyền tải thật bằng httpx — TLS verify BẮT BUỘC (không cho tắt)."""

    def request(
        self, method: str, url: str, *, headers: dict[str, str], content: bytes,
        connect_timeout: float, read_timeout: float, verify: bool,
    ) -> HttpResponse:
        try:
            import httpx

            timeout = httpx.Timeout(
                connect=connect_timeout, read=read_timeout, write=read_timeout, pool=connect_timeout
            )
            resp = httpx.request(
                method, url, headers=headers, content=content,
                timeout=timeout, verify=True,  # ⭐ LUÔN verify TLS, bất kể tham số
            )
            return HttpResponse(resp.status_code, resp.content, dict(resp.headers))
        except Exception as exc:  # noqa: BLE001 - lỗi mạng -> đáng thử lại
            raise TransportError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Bản tin (opaque — định dạng thật do Hướng dẫn kỹ thuật quy định)              #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class GatewayResponse:
    operation: str
    ok: bool
    status_code: int
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class HealthStatus:
    reachable: bool
    status_code: int = 0
    detail: str = ""


# --------------------------------------------------------------------------- #
# Interface                                                                    #
# --------------------------------------------------------------------------- #
class EsignGateway(abc.ABC):
    """Hợp đồng kết nối Cổng eSign (Điều 7/8).

    Bản tin là ``dict`` opaque cho tới khi Hướng dẫn kỹ thuật xác định định dạng
    chính thức — KHÔNG cứng hoá schema theo phỏng đoán.
    """

    @abc.abstractmethod
    def register(self, payload: dict[str, Any]) -> GatewayResponse: ...

    @abc.abstractmethod
    def submit_signature(self, payload: dict[str, Any]) -> GatewayResponse: ...

    @abc.abstractmethod
    def query_status(self, payload: dict[str, Any]) -> GatewayResponse: ...

    @abc.abstractmethod
    def health(self) -> HealthStatus: ...


# --------------------------------------------------------------------------- #
# Mặc định khi CHƯA có spec: từ chối mọi thứ (fail-closed, trung thực)          #
# --------------------------------------------------------------------------- #
class NullEsignGateway(EsignGateway):
    """Gateway "chưa hiện thực": mọi thao tác ném :class:`ESignGatewayError`."""

    def _refuse(self, op: str) -> GatewayResponse:
        raise ESignGatewayError(f"{op}: {_NOT_READY}")

    def register(self, payload: dict[str, Any]) -> GatewayResponse:
        return self._refuse("register")

    def submit_signature(self, payload: dict[str, Any]) -> GatewayResponse:
        return self._refuse("submit_signature")

    def query_status(self, payload: dict[str, Any]) -> GatewayResponse:
        return self._refuse("query_status")

    def health(self) -> HealthStatus:
        raise ESignGatewayError(f"health: {_NOT_READY}")


# --------------------------------------------------------------------------- #
# Adapter HTTP có gia cố (dùng khi spec ĐÃ điền)                                #
# --------------------------------------------------------------------------- #
class _RetryableError(Exception):
    """Lỗi đáng thử lại (mạng / HTTP 5xx)."""


class HttpEsignGateway(EsignGateway):
    """Adapter HTTP: allowlist domain + TLS verify + retry/backoff + circuit breaker.

    Đặc thù giao thức lấy TỪ SPEC (endpoint, method, định dạng bản tin). Chỉ hỗ
    trợ định dạng đã hiện thực (hiện: ``json``); khác -> từ chối rõ ràng (chờ bổ
    sung theo Hướng dẫn kỹ thuật).
    """

    def __init__(
        self,
        spec: EsignGatewaySpec,
        *,
        transport: Transport | None = None,
        auth_headers: dict[str, str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.spec = spec
        self.transport = transport or HttpxTransport()
        self._auth_headers = dict(auth_headers or {})
        self._sleep = sleep
        self._breaker: CircuitBreaker = spec.make_breaker(clock=clock)

    # -- API ------------------------------------------------------------ #
    def register(self, payload: dict[str, Any]) -> GatewayResponse:
        return self._call("register", payload)

    def submit_signature(self, payload: dict[str, Any]) -> GatewayResponse:
        return self._call("submit_signature", payload)

    def query_status(self, payload: dict[str, Any]) -> GatewayResponse:
        return self._call("query_status", payload)

    def health(self) -> HealthStatus:
        try:
            resp = self._call("health", {})
        except ESignGatewayError as exc:
            return HealthStatus(reachable=False, detail=exc.message)
        return HealthStatus(reachable=resp.ok, status_code=resp.status_code, detail="OK")

    # -- Lõi gọi có gia cố ---------------------------------------------- #
    def _call(self, operation: str, payload: dict[str, Any]) -> GatewayResponse:
        self._require_ready()
        op = self.spec.operation(operation)
        if op is None:
            raise ESignGatewayError(
                f"{operation}: spec chưa định nghĩa endpoint/method (chờ Hướng dẫn kỹ thuật)."
            )
        url = urljoin(self.spec.base_url.rstrip("/") + "/", op.path.lstrip("/"))
        self._check_egress(url)
        body = self._encode(payload)
        headers = self._headers()

        def _do() -> HttpResponse:
            started = time.monotonic()
            try:
                resp = self.transport.request(
                    op.method.upper(), url, headers=headers, content=body,
                    connect_timeout=self.spec.connect_timeout, read_timeout=self.spec.read_timeout,
                    verify=True,
                )
            except TransportError as exc:
                self._audit(operation, url, op.method, None, started, error=str(exc))
                raise _RetryableError(str(exc)) from exc
            self._audit(operation, url, op.method, resp.status_code, started)
            if resp.status_code >= 500:
                raise _RetryableError(f"HTTP {resp.status_code}")
            if resp.status_code >= 400:
                raise ESignGatewayError(f"Cổng eSign trả lỗi HTTP {resp.status_code}.")  # 4xx: không thử lại
            return resp

        try:
            resp = run_with_resilience(
                _do, retry=self.spec.retry, breaker=self._breaker,
                is_retryable=lambda e: isinstance(e, _RetryableError), sleep=self._sleep,
            )
        except CircuitOpenError as exc:
            raise ESignGatewayError(
                "Tạm dừng kết nối Cổng eSign (circuit breaker MỞ).", detail=str(exc)
            ) from exc
        except _RetryableError as exc:
            raise ESignGatewayError(
                "Không kết nối được Cổng eSign sau các lần thử.", detail=str(exc)
            ) from exc

        return GatewayResponse(
            operation=operation, ok=200 <= resp.status_code < 300,
            status_code=resp.status_code, data=self._decode(resp),
        )

    # -- Gia cố kênh ra mạng -------------------------------------------- #
    def _require_ready(self) -> None:
        if not self.spec.is_configured:
            raise ESignGatewayError(_NOT_READY)
        if not self.spec.verify_tls:
            raise ESignGatewayError(
                "Spec đặt verify_tls=false — TỪ CHỐI: bắt buộc xác minh TLS khi kết nối Cổng eSign."
            )
        if self.spec.message_format not in ("json",):
            raise ESignGatewayError(
                f"Định dạng bản tin '{self.spec.message_format or '(trống)'}' chưa được hiện thực "
                "— cần bổ sung theo Hướng dẫn kỹ thuật (hiện hỗ trợ: json)."
            )

    def _check_egress(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ESignGatewayError(
                f"TỪ CHỐI kết nối phi-HTTPS tới Cổng eSign: '{parts.scheme or '(trống)'}'."
            )
        host = (parts.hostname or "").lower()
        if host not in self.spec.allowed_domains:
            raise ESignGatewayError(
                f"Domain '{host}' KHÔNG thuộc allowlist Cổng eSign — từ chối ra mạng.",
                detail=f"allowlist={list(self.spec.allowed_domains)}",
            )

    # -- Mã hoá / giải mã bản tin (chỉ json; khác đã chặn ở _require_ready) --- #
    def _encode(self, payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def _decode(self, resp: HttpResponse) -> dict[str, Any]:
        if not resp.content:
            return {}
        try:
            data = json.loads(resp.content)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {"_raw": data}

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update(self._auth_headers)  # bí mật do người vận hành cấp lúc chạy
        return headers

    # -- Audit (KHÔNG log body/PIN/chữ ký/khoá/Authorization) ----------- #
    def _audit(
        self, operation: str, url: str, method: str, status: int | None,
        started: float, *, error: str = "",
    ) -> None:
        host = urlsplit(url).hostname or ""
        elapsed_ms = int((time.monotonic() - started) * 1000)
        # CHỈ metadata — tuyệt đối không kèm nội dung bản tin.
        _log.info(
            "esign op=%s method=%s host=%s status=%s elapsed_ms=%d%s",
            operation, method.upper(), host, status if status is not None else "ERR",
            elapsed_ms, (f" error={error[:120]}" if error else ""),
        )


# --------------------------------------------------------------------------- #
# Factory                                                                      #
# --------------------------------------------------------------------------- #
def make_gateway(
    spec: EsignGatewaySpec | None = None, *, transport: Transport | None = None, **kwargs: Any
) -> EsignGateway:
    """Trả gateway phù hợp: đã cấu hình -> :class:`HttpEsignGateway`; ngược lại
    :class:`NullEsignGateway` (fail-closed)."""
    resolved = spec if spec is not None else load_spec()
    if resolved.is_configured:
        return HttpEsignGateway(resolved, transport=transport, **kwargs)
    return NullEsignGateway()


__all__ = [
    "EsignGateway",
    "NullEsignGateway",
    "HttpEsignGateway",
    "GatewayResponse",
    "HealthStatus",
    "Transport",
    "HttpxTransport",
    "HttpResponse",
    "TransportError",
    "make_gateway",
]
