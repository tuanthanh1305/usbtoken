"""Test endpoint daemon (service/app.py) với ServiceDeps TIÊM — không cần token.

Bao phủ: bảo mật Host/Origin, /health, /diagnose, /tokens (+fallback đánh dấu),
/tokens/{id}/certs (phiên PIN), /login (rate-limit, phiên), /logout (zeroize),
/validate (hiệu lực + chữ ký số), WS /events (cắm/rút).
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient

from core.aggregator import SOURCE_PKCS11
from core.cert_reader import CertReadResult
from core.models import (
    AggregateResult,
    CAInfo,
    CertRecord,
    ErrorCode,
    ErrorInfo,
    KeyInfo,
    TokenBundle,
    TokenInfo,
    TrustPathNode,
    ValidationResult,
    ValidationStatusCode,
)
from core.platform import FALLBACK_LINUX_NSS, get_adapter
from service.app import create_app
from service.api.gateway import token_public_id
from service.deps import ServiceDeps
from service.security import RateLimiter
from service.sessions import SessionStore
from core import x509_parser
from tests.certs import make_chain


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #
class FakeBridge:
    def __init__(self, active: int = 0) -> None:
        self._active = active
        self.closed = False

    def active_helpers(self) -> int:
        return self._active

    def close(self) -> None:
        self.closed = True


class StubValidator:
    def __init__(self, status=ValidationStatusCode.INVALID, trust_path=None):  # type: ignore[no-untyped-def]
        self.status = status
        self.trust_path = trust_path or []

    def validate(self, der: bytes, at_time=None):  # type: ignore[no-untyped-def]
        now = datetime.now(timezone.utc)
        return ValidationResult(
            status=self.status, checked_at=now, at_time=now,
            trust_path=self.trust_path, reasons_vi=["(stub)"],
        )


class FakeEvents:
    def __init__(self, readers, batches):  # type: ignore[no-untyped-def]
        self._readers = readers
        self._batches = list(batches)

    def readers(self):  # type: ignore[no-untyped-def]
        return self._readers

    def poll(self):  # type: ignore[no-untyped-def]
        return self._batches.pop(0) if self._batches else []


def _token(slot=1, module="/usr/lib/libtoken.so", serial="SN1"):  # type: ignore[no-untyped-def]
    return TokenInfo(module_path=module, slot_id=slot, serial=serial)


def _certinfo(issued, *, with_key):  # type: ignore[no-untyped-def]
    ci = x509_parser.parse(issued.der)
    if with_key:
        ci.key = KeyInfo(has_private_key=True, key_class="private")
    return ci


def _deps(**over):  # type: ignore[no-untyped-def]
    ad = get_adapter()
    tokens = over.get("tokens", [])

    def enumerate_():  # type: ignore[no-untyped-def]
        return list(tokens)

    def read_fn(token, pin_callback=None):  # type: ignore[no-untyped-def]
        fn = over.get("read_fn")
        if fn is not None:
            return fn(token, pin_callback)
        return over.get("read_result", CertReadResult())

    def aggregate(**kw):  # type: ignore[no-untyped-def]
        return over.get("aggregate", AggregateResult())

    return ServiceDeps(
        adapter=ad,
        sessions=over.get("sessions", SessionStore()),
        login_limiter=over.get("limiter", RateLimiter()),
        bridge=over.get("bridge", FakeBridge()),
        validator_factory=lambda: over.get("validator", StubValidator()),
        aggregate_fn=aggregate,
        enumerate_fn=enumerate_,
        read_fn=read_fn,
        events_source_factory=lambda: over.get("events", FakeEvents([], [])),
        event_poll_interval=0.01,
    )


def _client(deps) -> TestClient:  # type: ignore[no-untyped-def]
    return TestClient(create_app(deps), base_url="http://127.0.0.1:8787")


# --------------------------------------------------------------------------- #
# Bảo mật                                                                      #
# --------------------------------------------------------------------------- #
def test_host_header_rejected() -> None:
    c = TestClient(create_app(_deps()), base_url="http://evil.example.com")
    assert c.get("/health").status_code == 403  # chống DNS rebinding


def test_origin_rejected() -> None:
    c = _client(_deps())
    r = c.get("/health", headers={"Origin": "http://evil.com"})
    assert r.status_code == 403


def test_origin_whitelisted_ok() -> None:
    c = _client(_deps())
    r = c.get("/health", headers={"Origin": "http://127.0.0.1:8787"})
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# /health, /diagnose                                                           #
# --------------------------------------------------------------------------- #
def test_health_reports_bridge_and_trust_store() -> None:
    c = _client(_deps(bridge=FakeBridge(active=1)))
    body = c.get("/health").json()
    assert body["ok"] is True
    assert body["platform"]["bridge_active"] is True
    assert "trust_store" in body and "stale" in body["trust_store"]


def test_diagnose_has_diagnostics_and_note() -> None:
    body = _client(_deps()).get("/diagnose").json()
    assert isinstance(body["diagnostics"], list) and body["diagnostics"]
    assert "trust_store" in body
    assert "installer" in body["note"].lower()  # cam kết không tự chạy installer


# --------------------------------------------------------------------------- #
# /tokens                                                                      #
# --------------------------------------------------------------------------- #
def test_tokens_lists_bundles_and_marks_fallback() -> None:
    root, inter, leaf = make_chain()
    tok = _token()
    now = datetime.now(timezone.utc)
    vr = ValidationResult(status=ValidationStatusCode.UNKNOWN, checked_at=now, at_time=now)
    token_rec = CertRecord(cert=_certinfo(leaf, with_key=True), validation=vr, source=SOURCE_PKCS11, from_token=True)
    fb_rec = CertRecord(cert=_certinfo(inter, with_key=False), validation=vr, source=FALLBACK_LINUX_NSS, from_token=False)
    agg = AggregateResult(
        tokens=[TokenBundle(token=tok, certificates=[token_rec])],
        fallback_certificates=[fb_rec],
        sources_scanned=[SOURCE_PKCS11, FALLBACK_LINUX_NSS],
    )
    body = _client(_deps(aggregate=agg)).get("/tokens").json()
    assert len(body["tokens"]) == 1
    assert body["tokens"][0]["id"] == token_public_id(tok)
    assert body["tokens"][0]["certificates"][0]["from_token"] is True
    assert len(body["fallback_certificates"]) == 1
    assert body["fallback_certificates"][0]["from_token"] is False


def test_tokens_response_has_no_private_key_material() -> None:
    _, _, leaf = make_chain()
    tok = _token()
    now = datetime.now(timezone.utc)
    vr = ValidationResult(status=ValidationStatusCode.UNKNOWN, checked_at=now, at_time=now)
    rec = CertRecord(cert=_certinfo(leaf, with_key=True), validation=vr, source=SOURCE_PKCS11, from_token=True)
    agg = AggregateResult(tokens=[TokenBundle(token=tok, certificates=[rec])])
    body = _client(_deps(aggregate=agg)).get("/tokens").json()
    cert_view = body["tokens"][0]["certificates"][0]["cert"]
    # KeyInfo chỉ là metadata: có cờ has_private_key nhưng KHÔNG có bytes khoá.
    assert cert_view["key"]["has_private_key"] is True
    assert "private_key" not in cert_view and "private_key_pem" not in cert_view


# --------------------------------------------------------------------------- #
# /tokens/{id}/certs — phiên PIN                                               #
# --------------------------------------------------------------------------- #
def test_token_certs_without_session_public_only() -> None:
    _, _, leaf = make_chain()
    tok = _token()
    seen = {}

    def read_fn(token, pin_callback=None):  # type: ignore[no-untyped-def]
        seen["pin_cb"] = pin_callback
        return CertReadResult(certificates=[_certinfo(leaf, with_key=False)])

    body = _client(_deps(tokens=[tok], read_fn=read_fn)).get(
        f"/tokens/{token_public_id(tok)}/certs"
    ).json()
    assert body["logged_in"] is False
    assert seen["pin_cb"] is None  # KHÔNG có PIN khi chưa đăng nhập
    assert len(body["certificates"]) == 1


def test_token_certs_with_session_uses_pin() -> None:
    _, _, leaf = make_chain()
    tok = _token()
    tid = token_public_id(tok)
    sessions = SessionStore()
    session = sessions.login(tid, "424242")
    captured = {}

    def read_fn(token, pin_callback=None):  # type: ignore[no-untyped-def]
        captured["pin"] = pin_callback() if pin_callback else None
        return CertReadResult(certificates=[_certinfo(leaf, with_key=True)], logged_in=True)

    c = _client(_deps(tokens=[tok], read_fn=read_fn, sessions=sessions))
    body = c.get(f"/tokens/{tid}/certs", params={"session_id": session.id}).json()
    assert body["logged_in"] is True
    assert captured["pin"] == b"424242"  # PIN đi MỘT CHIỀU vào token


def test_token_certs_404_unknown_token() -> None:
    c = _client(_deps(tokens=[]))
    assert c.get("/tokens/deadbeef/certs").status_code == 404


# --------------------------------------------------------------------------- #
# /login, /logout                                                             #
# --------------------------------------------------------------------------- #
def test_login_success_creates_session() -> None:
    _, _, leaf = make_chain()
    tok = _token()
    tid = token_public_id(tok)
    sessions = SessionStore()

    def read_fn(token, pin_callback=None):  # type: ignore[no-untyped-def]
        assert pin_callback() == b"111111"
        return CertReadResult(certificates=[_certinfo(leaf, with_key=True)], logged_in=True)

    c = _client(_deps(tokens=[tok], read_fn=read_fn, sessions=sessions))
    r = c.post("/login", json={"token_id": tid, "pin": "111111"})
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"] and sessions.get(body["session_id"]) is not None
    assert body["token_id"] == tid


def test_login_wrong_pin_returns_401_no_session() -> None:
    tok = _token()
    tid = token_public_id(tok)
    sessions = SessionStore()

    def read_fn(token, pin_callback=None):  # type: ignore[no-untyped-def]
        return CertReadResult(error=ErrorInfo(code=ErrorCode.LOGIN_REQUIRED, message_vi="Mã PIN không đúng."))

    c = _client(_deps(tokens=[tok], read_fn=read_fn, sessions=sessions))
    r = c.post("/login", json={"token_id": tid, "pin": "000000"})
    assert r.status_code == 401
    assert sessions.active_count == 0  # KHÔNG tạo phiên khi PIN sai


def test_login_rate_limited() -> None:
    tok = _token()
    tid = token_public_id(tok)
    limiter = RateLimiter(max_attempts=2, window=60.0)

    def read_fn(token, pin_callback=None):  # type: ignore[no-untyped-def]
        return CertReadResult(error=ErrorInfo(code=ErrorCode.LOGIN_REQUIRED, message_vi="sai"))

    c = _client(_deps(tokens=[tok], read_fn=read_fn, limiter=limiter))
    assert c.post("/login", json={"token_id": tid, "pin": "1"}).status_code == 401
    assert c.post("/login", json={"token_id": tid, "pin": "2"}).status_code == 401
    assert c.post("/login", json={"token_id": tid, "pin": "3"}).status_code == 429  # bị chặn


def test_logout_zeroizes_session() -> None:
    tok = _token()
    tid = token_public_id(tok)
    sessions = SessionStore()
    session = sessions.login(tid, "555555")
    c = _client(_deps(tokens=[tok], sessions=sessions))
    r = c.post("/logout", json={"session_id": session.id})
    assert r.json()["logged_out"] is True
    assert sessions.get(session.id) is None
    assert bytes(session._pin) == b"\x00" * 6


# --------------------------------------------------------------------------- #
# /validate — hiệu lực + chữ ký số                                             #
# --------------------------------------------------------------------------- #
def test_validate_certificate_only() -> None:
    _, _, leaf = make_chain()
    c = _client(_deps())
    r = c.post("/validate", json={"certificate_b64": base64.b64encode(leaf.der).decode()})
    assert r.status_code == 200
    assert r.json()["validation"]["status"] == "invalid"  # stub validator


def test_validate_with_signature_valid() -> None:
    signer = make_chain()[2]  # leaf, khoá RSA
    data = b"tai lieu ky so"
    sig = signer.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    c = _client(_deps())
    r = c.post("/validate", json={
        "certificate_b64": base64.b64encode(signer.der).decode(),
        "signature": {
            "data_b64": base64.b64encode(data).decode(),
            "signature_b64": base64.b64encode(sig).decode(),
            "algorithm": "sha256",
        },
    })
    body = r.json()
    assert body["signature_valid"] is True
    assert "HỢP LỆ" in body["signature_reason_vi"]


def test_validate_with_signature_tampered() -> None:
    signer = make_chain()[2]
    data = b"tai lieu ky so"
    sig = signer.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    c = _client(_deps())
    r = c.post("/validate", json={
        "certificate_b64": base64.b64encode(signer.der).decode(),
        "signature": {
            "data_b64": base64.b64encode(b"da bi sua").decode(),
            "signature_b64": base64.b64encode(sig).decode(),
        },
    })
    assert r.json()["signature_valid"] is False


# --------------------------------------------------------------------------- #
# WS /events                                                                   #
# --------------------------------------------------------------------------- #
def test_ws_events_streams_insert_remove() -> None:
    events = FakeEvents(
        readers=["Reader 0"],
        batches=[
            [{"action": "inserted", "reader": "Reader 0", "atr": "3baa00"}],
            [{"action": "removed", "reader": "Reader 0", "atr": ""}],
        ],
    )
    c = _client(_deps(events=events))
    with c.websocket_connect("/events", headers={"host": "127.0.0.1:8787"}) as ws:
        ready = ws.receive_json()
        assert ready["type"] == "ready" and ready["readers"] == ["Reader 0"]
        e1 = ws.receive_json()
        assert e1["type"] == "token_event" and e1["action"] == "inserted"
        e2 = ws.receive_json()
        assert e2["action"] == "removed"


def test_ws_events_rejects_bad_origin() -> None:
    c = _client(_deps())
    import pytest as _pytest

    with _pytest.raises(Exception):  # noqa: BLE001 - đóng 1008 -> raise phía client
        with c.websocket_connect(
            "/events", headers={"host": "127.0.0.1:8787", "Origin": "http://evil.com"}
        ) as ws:
            ws.receive_json()
