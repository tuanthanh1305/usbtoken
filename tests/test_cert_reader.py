"""Test cert_reader: luồng 2 bước, an toàn PIN (zeroize), lỗi tiếng Việt.

Reader được TIÊM bản giả (không cần PyKCS11/token thật).
"""

from __future__ import annotations

import base64
from typing import Any

from core import cert_reader
from core.models import ErrorCode, PinState, TokenInfo
from tests.certs import make_chain

_root, _inter, _leaf = make_chain()


def _certdict(der: bytes, id_hex: str = "a1", has_key: bool = True) -> dict[str, Any]:
    return {
        "der_b64": base64.b64encode(der).decode(), "id_hex": id_hex, "label": "Chu Ky",
        "key": {"has_private_key": has_key, "key_type": "RSA", "key_size": 2048,
                "usable_for_signing": True, "allowed_mechanisms": [], "id_hex": id_hex},
    }


def _token(**pin_flags: bool) -> TokenInfo:
    return TokenInfo(
        module_path="/usr/lib/fptca_v4.so", slot_id=0, manufacturer_id="FEITIAN",
        pin_state=PinState(**pin_flags),
    )


# --------------------------------------------------------------------------- #
# B1: cert public (không cần login)                                            #
# --------------------------------------------------------------------------- #
def test_b1_public_cert_no_login() -> None:
    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        return {"certs": [_certdict(_leaf.der)]}

    result = cert_reader.read_certificates(_token(), reader=reader)
    assert result.error is None
    assert result.logged_in is False
    assert len(result.certificates) == 1
    assert result.certificates[0].key.has_private_key is True
    assert result.certificates[0].subject_raw  # đã parse


# --------------------------------------------------------------------------- #
# B2: cert private -> login + zeroize PIN                                       #
# --------------------------------------------------------------------------- #
def test_b2_login_and_pin_zeroized() -> None:
    calls: list[Any] = []

    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        calls.append((pin, protected_auth))
        if pin is None and not protected_auth:
            return {"certs": []}  # B1 rỗng -> private
        return {"certs": [_certdict(_leaf.der)]}  # sau login

    pin_buf = bytearray(b"12345678")

    def pin_cb() -> bytearray:
        return pin_buf

    result = cert_reader.read_certificates(_token(login_required=True), pin_callback=pin_cb, reader=reader)
    assert result.logged_in is True and len(result.certificates) == 1
    # PIN đã bị ZEROIZE sau khi dùng.
    assert bytes(pin_buf) == b"\x00" * 8
    # Reader nhận PIN ở bước 2 (bytes), không phải None.
    assert calls[1][0] is not None


def test_b2_no_callback_returns_error() -> None:
    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        return {"certs": []}

    result = cert_reader.read_certificates(_token(login_required=True), pin_callback=None, reader=reader)
    assert result.error is not None
    assert result.error.code is ErrorCode.LOGIN_REQUIRED


# --------------------------------------------------------------------------- #
# PIN safety: locked từ chối, final_try cảnh báo đỏ                             #
# --------------------------------------------------------------------------- #
def test_locked_refuses_login() -> None:
    called = {"login": False}

    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        if pin is not None:
            called["login"] = True
        return {"certs": []}

    result = cert_reader.read_certificates(
        _token(locked=True), pin_callback=lambda: bytearray(b"1234"), reader=reader,
    )
    assert result.error is not None and result.error.code is ErrorCode.LOGIN_REQUIRED
    assert "KHOÁ" in result.error.message_vi
    assert called["login"] is False  # TUYỆT ĐỐI không thử login khi đã khoá


def test_final_try_red_warning() -> None:
    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        if pin is None and not protected_auth:
            return {"certs": []}
        return {"certs": [_certdict(_leaf.der)]}

    result = cert_reader.read_certificates(
        _token(final_try=True), pin_callback=lambda: bytearray(b"1234"), reader=reader,
    )
    assert any("LẦN THỬ PIN CUỐI" in w for w in result.warnings)


def test_protected_auth_path_no_host_pin() -> None:
    seen: list[bool] = []

    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        seen.append(protected_auth)
        if pin is None and not protected_auth:
            return {"certs": []}
        return {"certs": [_certdict(_leaf.der)]}

    pin_called = {"v": False}

    def pin_cb() -> bytearray:
        pin_called["v"] = True
        return bytearray(b"x")

    result = cert_reader.read_certificates(
        _token(protected_auth_path=True), pin_callback=pin_cb, reader=reader,
    )
    assert result.logged_in is True
    assert seen[-1] is True  # đã login qua pinpad
    assert pin_called["v"] is False  # KHÔNG hỏi PIN ở host (pinpad)


# --------------------------------------------------------------------------- #
# Lỗi CKR_* -> tiếng Việt                                                       #
# --------------------------------------------------------------------------- #
def test_ckr_pin_incorrect_vietnamese() -> None:
    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        if pin is None and not protected_auth:
            return {"certs": []}
        raise RuntimeError("CKR_PIN_INCORRECT (0xa0)")  # giả lập lỗi PKCS#11

    result = cert_reader.read_certificates(
        _token(login_required=True, final_try=True),
        pin_callback=lambda: bytearray(b"0000"), reader=reader,
    )
    assert result.error is not None and result.error.code is ErrorCode.LOGIN_REQUIRED
    assert "PIN không đúng" in result.error.message_vi
    assert "LẦN THỬ CUỐI" in result.error.message_vi  # vì final_try


def test_ckr_token_removed_vietnamese() -> None:
    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        raise RuntimeError("CKR_DEVICE_REMOVED")

    result = cert_reader.read_certificates(_token(), reader=reader)
    assert result.error is not None and result.error.code is ErrorCode.TOKEN_NOT_PRESENT
    assert "RÚT" in result.error.message_vi


# --------------------------------------------------------------------------- #
# ⭐ NHIỀU cert của NHIỀU CA trên một token                                    #
# --------------------------------------------------------------------------- #
def test_multiple_certs_multiple_cas() -> None:
    r1, i1, l1 = make_chain()
    r2, i2, l2 = make_chain()

    def reader(*, pin: Any = None, protected_auth: bool = False) -> dict[str, Any]:
        return {"certs": [_certdict(l1.der, id_hex="a1"), _certdict(l2.der, id_hex="b2")]}

    result = cert_reader.read_certificates(_token(), reader=reader)
    assert len(result.certificates) == 2  # ⭐ DUYỆT HẾT nhiều cert
    serials = {c.serial_number for c in result.certificates}
    assert len(serials) == 2  # hai chứng thư riêng biệt
    assert {c.key_id_hex for c in result.certificates} == {"a1", "b2"}
