"""Test KHUNG kết nối Cổng eSign (core/esign/*) — KHÔNG ra mạng thật.

Trọng tâm KHUNG TRỪU TƯỢNG + hạ tầng gia cố (an toàn để viết trước Hướng dẫn kỹ
thuật):
    * Chưa điền spec -> NullEsignGateway TỪ CHỐI mọi thao tác (fail-closed).
    * Đã điền spec -> HttpEsignGateway: allowlist domain, BẮT BUỘC TLS/HTTPS,
      retry/backoff, circuit breaker, audit KHÔNG lộ dữ liệu nhạy cảm.
    * "Mock server" = Transport tiêm sẵn phản hồi kịch bản.

⚠️ KHÔNG test nào tuyên bố tuân thủ Điều 7/8 — chỉ kiểm cơ chế khung.
"""

from __future__ import annotations

import logging

import pytest

from core.errors import ESignGatewayError
from core.esign import load_spec, make_gateway
from core.esign.gateway import (
    HttpEsignGateway,
    HttpResponse,
    NullEsignGateway,
    Transport,
    TransportError,
)
from core.esign.resilience import CircuitBreaker, RetryPolicy


# --------------------------------------------------------------------------- #
# Mock server (Transport tiêm)                                                 #
# --------------------------------------------------------------------------- #
class MockTransport(Transport):
    def __init__(self, responses):  # type: ignore[no-untyped-def]
        self._responses = list(responses)
        self.calls: list[dict] = []

    def request(self, method, url, *, headers, content, connect_timeout, read_timeout, verify):  # type: ignore[no-untyped-def]
        self.calls.append({"method": method, "url": url, "headers": headers,
                           "content": content, "verify": verify})
        r = self._responses.pop(0) if self._responses else HttpResponse(200, b"{}")
        if isinstance(r, Exception):
            raise r
        return r


def _spec_dict(**over):  # type: ignore[no-untyped-def]
    d = {
        "status": "filled",
        "base_url": "https://esign.neac.gov.vn",
        "message_format": "json",
        "tls": {"verify": True},
        "allowed_domains": ["esign.neac.gov.vn"],
        "timeouts": {"connect_seconds": 1, "read_seconds": 1},
        "retry": {"max_attempts": 3, "backoff_base_seconds": 0.01, "backoff_max_seconds": 0.02},
        "circuit_breaker": {"failure_threshold": 5, "reset_timeout_seconds": 30},
        "operations": {
            "register": {"path": "/v1/register", "method": "POST"},
            "submit_signature": {"path": "/v1/sign", "method": "POST"},
            "query_status": {"path": "/v1/status", "method": "GET"},
            "health": {"path": "/v1/health", "method": "GET"},
        },
    }
    d.update(over)
    return d


def _gw(transport, **over):  # type: ignore[no-untyped-def]
    spec = load_spec(_spec_dict(**over))
    return HttpEsignGateway(spec, transport=transport, sleep=lambda _s: None)


# --------------------------------------------------------------------------- #
# Fail-closed: chưa có Hướng dẫn kỹ thuật -> từ chối                            #
# --------------------------------------------------------------------------- #
def test_real_spec_file_is_not_filled() -> None:
    # File repo phải giữ trạng thái CHƯA điền (trung thực về tuân thủ).
    assert load_spec().is_configured is False


def test_make_gateway_returns_null_when_unconfigured() -> None:
    gw = make_gateway(load_spec({"status": "not_filled"}))
    assert isinstance(gw, NullEsignGateway)
    for call in (lambda: gw.register({}), lambda: gw.submit_signature({}),
                 lambda: gw.query_status({}), gw.health):
        with pytest.raises(ESignGatewayError) as exc:
            call()
        assert "CHƯA HIỆN THỰC" in exc.value.message


def test_make_gateway_returns_http_when_configured() -> None:
    gw = make_gateway(load_spec(_spec_dict()), transport=MockTransport([]))
    assert isinstance(gw, HttpEsignGateway)


# --------------------------------------------------------------------------- #
# Happy path qua mock                                                          #
# --------------------------------------------------------------------------- #
def test_submit_signature_ok() -> None:
    tr = MockTransport([HttpResponse(200, b'{"receipt_id":"R1"}')])
    res = _gw(tr).submit_signature({"doc": "abc"})
    assert res.ok and res.status_code == 200
    assert res.data == {"receipt_id": "R1"}
    call = tr.calls[0]
    assert call["url"] == "https://esign.neac.gov.vn/v1/sign" and call["method"] == "POST"
    assert call["verify"] is True  # TLS verify bắt buộc


def test_health_reachable_and_unreachable() -> None:
    assert _gw(MockTransport([HttpResponse(200, b"{}")])).health().reachable is True
    # 5xx lặp -> hết retry -> health().reachable False (không ném).
    down = _gw(MockTransport([HttpResponse(503), HttpResponse(503), HttpResponse(503)]))
    assert down.health().reachable is False


# --------------------------------------------------------------------------- #
# Gia cố kênh: allowlist domain, HTTPS, TLS, định dạng                          #
# --------------------------------------------------------------------------- #
def test_domain_not_in_allowlist_refused() -> None:
    gw = _gw(MockTransport([]), base_url="https://evil.example.com")
    with pytest.raises(ESignGatewayError) as exc:
        gw.submit_signature({})
    assert "allowlist" in exc.value.message.lower()


def test_non_https_refused() -> None:
    gw = _gw(MockTransport([]), base_url="http://esign.neac.gov.vn")
    with pytest.raises(ESignGatewayError) as exc:
        gw.submit_signature({})
    assert "HTTPS" in exc.value.message


def test_verify_tls_false_refused() -> None:
    gw = _gw(MockTransport([]), tls={"verify": False})
    with pytest.raises(ESignGatewayError) as exc:
        gw.submit_signature({})
    assert "TLS" in exc.value.message


def test_unsupported_message_format_refused() -> None:
    gw = _gw(MockTransport([]), message_format="soap")
    with pytest.raises(ESignGatewayError) as exc:
        gw.submit_signature({})
    assert "định dạng" in exc.value.message.lower()


# --------------------------------------------------------------------------- #
# Retry / backoff / circuit breaker                                           #
# --------------------------------------------------------------------------- #
def test_retry_on_5xx_then_success() -> None:
    tr = MockTransport([HttpResponse(503), HttpResponse(503), HttpResponse(200, b'{"ok":1}')])
    res = _gw(tr).register({})
    assert res.ok and len(tr.calls) == 3  # thử lại 2 lần rồi thành công


def test_retry_on_network_error() -> None:
    tr = MockTransport([TransportError("reset"), HttpResponse(200, b"{}")])
    res = _gw(tr).register({})
    assert res.ok and len(tr.calls) == 2


def test_4xx_not_retried() -> None:
    tr = MockTransport([HttpResponse(400, b'{"error":"bad"}')])
    with pytest.raises(ESignGatewayError) as exc:
        _gw(tr).register({})
    assert "HTTP 400" in exc.value.message
    assert len(tr.calls) == 1  # 4xx = lỗi client -> KHÔNG thử lại


def test_retry_exhausted_raises() -> None:
    tr = MockTransport([HttpResponse(500), HttpResponse(500), HttpResponse(500)])
    with pytest.raises(ESignGatewayError) as exc:
        _gw(tr).register({})
    assert "sau các lần thử" in exc.value.message
    assert len(tr.calls) == 3


def test_circuit_breaker_opens_after_repeated_failures() -> None:
    # max_attempts=1 -> mỗi lời gọi = 1 lỗi; ngưỡng 2 -> lần thứ 3 bị chặn nhanh.
    over = {"retry": {"max_attempts": 1}, "circuit_breaker": {"failure_threshold": 2, "reset_timeout_seconds": 30}}
    tr = MockTransport([TransportError("x")] * 10)
    gw = _gw(tr, **over)
    with pytest.raises(ESignGatewayError):
        gw.register({})
    with pytest.raises(ESignGatewayError):
        gw.register({})
    before = len(tr.calls)
    with pytest.raises(ESignGatewayError) as exc:
        gw.register({})
    assert "circuit breaker MỞ" in exc.value.message
    assert len(tr.calls) == before  # fast-fail: KHÔNG gọi transport nữa


# --------------------------------------------------------------------------- #
# Audit KHÔNG lộ dữ liệu nhạy cảm                                              #
# --------------------------------------------------------------------------- #
def test_audit_does_not_log_payload(caplog) -> None:  # type: ignore[no-untyped-def]
    tr = MockTransport([HttpResponse(200, b"{}")])
    secret = "SUPER-SECRET-SIGNATURE-BYTES"
    with caplog.at_level(logging.INFO, logger="vn_esign.esign"):
        _gw(tr).submit_signature({"signature": secret})
    assert secret not in caplog.text  # nội dung bản tin KHÔNG vào log
    assert "op=submit_signature" in caplog.text and "host=esign.neac.gov.vn" in caplog.text


# --------------------------------------------------------------------------- #
# Resilience đơn vị                                                            #
# --------------------------------------------------------------------------- #
def test_retry_policy_backoff_capped() -> None:
    rp = RetryPolicy(max_attempts=5, backoff_base_seconds=1.0, backoff_max_seconds=4.0)
    assert rp.delay_for(1) == 0.0
    assert rp.delay_for(2) == 1.0 and rp.delay_for(3) == 2.0
    assert rp.delay_for(5) == 4.0  # bị trần


def test_circuit_breaker_half_open_recovers() -> None:
    clock = {"t": 0.0}
    cb = CircuitBreaker(failure_threshold=1, reset_timeout=10.0, clock=lambda: clock["t"])
    cb.record_failure()
    assert cb.allow() is False  # OPEN
    clock["t"] = 11.0
    assert cb.allow() is True  # HALF_OPEN sau reset_timeout
    cb.record_success()
    assert cb.state == "closed"
