"""Unit test hạ tầng daemon: phiên PIN, bảo mật (Host/Origin/rate-limit),
runtime (cổng, file trạng thái, che PIN), và kiểm chữ ký số tách rời."""

from __future__ import annotations

import logging
import socket
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from core.signature_verify import verify_detached
from service.runtime import (
    PinRedactionFilter,
    configure_logging,
    find_free_port,
    read_state_file,
    remove_state_file,
    write_state_file,
)
from service.security import (
    RateLimiter,
    connection_allowed,
    host_only,
)
from service.sessions import SessionStore
from tests.certs import _make


# --------------------------------------------------------------------------- #
# SessionStore — TTL, zeroize, an toàn                                          #
# --------------------------------------------------------------------------- #
class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_session_login_get_logout() -> None:
    store = SessionStore(ttl=100.0)
    s = store.login("tok1", "123456")
    assert store.get(s.id) is s
    assert s.pin_bytes() == b"123456"
    assert store.logout(s.id) is True
    assert store.get(s.id) is None  # đã xoá


def test_session_expiry_zeroizes() -> None:
    clock = _Clock()
    store = SessionStore(ttl=30.0, clock=clock)
    s = store.login("tok1", "999999")
    pin_ref = s._pin  # tham chiếu bytearray nội bộ
    clock.t += 31.0  # quá hạn
    assert store.get(s.id) is None
    assert bytes(pin_ref) == b"\x00" * 6  # ĐÃ zeroize


def test_session_clear_zeroizes_all() -> None:
    store = SessionStore()
    a = store.login("t1", "111111")
    b = store.login("t2", "222222")
    refs = [a._pin, b._pin]
    store.clear()
    assert store.active_count == 0
    assert all(bytes(r) == b"\x00" * 6 for r in refs)


def test_session_pin_is_bytearray_not_str() -> None:
    store = SessionStore()
    s = store.login("t", "1234")
    assert isinstance(s._pin, bytearray)  # zeroize được (không phải str bất biến)


def test_session_login_copies_pin_defensively() -> None:
    # REGRESSION: caller zeroize BẢN CỦA HỌ sau khi login KHÔNG được xoá PIN trong
    # phiên (nếu chia sẻ bộ nhớ, mọi lần ký sau sẽ gửi PIN toàn số 0 -> khoá token).
    store = SessionStore()
    caller_pin = bytearray(b"123456")
    s = store.login("tok", caller_pin)
    for i in range(len(caller_pin)):  # caller tự zeroize
        caller_pin[i] = 0
    assert s.pin_bytes() == b"123456"  # phiên vẫn giữ PIN gốc
    assert store.get(s.id).pin_bytes() == b"123456"


# --------------------------------------------------------------------------- #
# Bảo mật — host parsing, Host/Origin, rate limit                              #
# --------------------------------------------------------------------------- #
def test_host_only_parsing() -> None:
    assert host_only("127.0.0.1:8787") == "127.0.0.1"
    assert host_only("localhost") == "localhost"
    assert host_only("[::1]:8787") == "::1"
    assert host_only("[::1]") == "::1"
    assert host_only("evil.com:80") == "evil.com"


def test_connection_allowed_host_and_origin() -> None:
    hosts = {"127.0.0.1", "localhost"}
    origins = {"http://127.0.0.1:8787"}

    class H(dict):
        pass

    # Host loopback, không Origin -> OK.
    assert connection_allowed(H({"host": "127.0.0.1:8787"}), hosts, origins) is True
    # Host lạ -> chặn (chống DNS rebinding).
    assert connection_allowed(H({"host": "evil.com"}), hosts, origins) is False
    # Origin lạ -> chặn.
    assert connection_allowed(
        H({"host": "127.0.0.1", "origin": "http://evil.com"}), hosts, origins
    ) is False


def test_rate_limiter_window() -> None:
    clock = _Clock()
    rl = RateLimiter(max_attempts=3, window=60.0, clock=clock)
    assert [rl.allow("k") for _ in range(4)] == [True, True, True, False]
    clock.t += 61.0  # cửa sổ trôi qua
    assert rl.allow("k") is True
    rl.reset("k")
    assert rl.allow("k") is True


# --------------------------------------------------------------------------- #
# Runtime — cổng, file trạng thái, che PIN                                      #
# --------------------------------------------------------------------------- #
def test_find_free_port_returns_preferred_when_available() -> None:
    # Lấy một cổng chắc chắn trống rồi yêu cầu đúng nó.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    assert find_free_port(free) == free


def test_find_free_port_falls_back_when_busy() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()  # đang LẮNG NGHE -> bind lại cùng cổng sẽ thất bại
        taken = busy.getsockname()[1]
        got = find_free_port(taken)  # cổng đang bận -> phải cấp cổng khác
        assert got != taken and got > 0


def test_state_file_roundtrip(tmp_path: Path) -> None:
    path = write_state_file(tmp_path, host="127.0.0.1", port=9999, version="1.2.3")
    assert path.exists()
    data = read_state_file(tmp_path)
    assert data is not None
    assert data["host"] == "127.0.0.1" and data["port"] == 9999
    assert data["url"] == "http://127.0.0.1:9999" and "pid" in data
    remove_state_file(tmp_path)
    assert read_state_file(tmp_path) is None


def test_pin_redaction_filter() -> None:
    filt = PinRedactionFilter()
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, 'login pin="123456" done', None, None)
    filt.filter(rec)
    assert "123456" not in rec.getMessage()
    assert "***" in rec.getMessage()


def test_configure_logging_idempotent(tmp_path: Path) -> None:
    a = configure_logging(tmp_path)
    n = len(a.handlers)
    b = configure_logging(tmp_path)
    assert a is b and len(b.handlers) == n  # không nhân đôi handler


# --------------------------------------------------------------------------- #
# Kiểm chữ ký số tách rời                                                       #
# --------------------------------------------------------------------------- #
def test_verify_detached_rsa_valid_and_tampered() -> None:
    signer = _make("Nguyen Van A", None, is_ca=False)  # tự ký, khoá RSA
    data = b"hop dong dien tu 2026"
    sig = signer.key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    ok, reason = verify_detached(signer.der, data, sig, algorithm="sha256")
    assert ok is True and "HỢP LỆ" in reason

    bad, reason2 = verify_detached(signer.der, data + b"x", sig, algorithm="sha256")
    assert bad is False and "KHÔNG khớp" in reason2


def test_verify_detached_bad_cert() -> None:
    ok, reason = verify_detached(b"not-a-cert", b"d", b"s")
    assert ok is False and "chứng thư" in reason.lower()


def test_verify_detached_unsupported_hash() -> None:
    signer = _make("A", None, is_ca=False)
    ok, reason = verify_detached(signer.der, b"d", b"s", algorithm="md5")
    assert ok is False and "băm không hỗ trợ" in reason
