"""Đọc chứng thư từ USB token — OS-agnostic (in-process hoặc qua bridge).

Luồng (theo PKCS#11):
    B1: openSession(CKF_SERIAL_SESSION) + findObjects(CKO_CERTIFICATE) KHÔNG login.
    B2: rỗng -> chứng thư là private object:
        * CKF_PROTECTED_AUTHENTICATION_PATH -> C_Login(CKU_USER, None) (pinpad).
        * ngược lại -> pin_callback() -> C_Login(CKU_USER, pin) -> enum LẠI.
    ⭐ DUYỆT HẾT: một token có thể chứa NHIỀU cert của NHIỀU CA.
    Khớp khoá private qua CKA_ID (SỢI CHỈ nối cert<->key).

AN TOÀN PIN (bắt buộc):
    * KHÔNG log, KHÔNG lưu đĩa, ZEROIZE sau dùng (bytearray ghi đè — KHÔNG dùng
      str bất biến ở phía host).
    * Trước login: CKF_USER_PIN_FINAL_TRY -> CẢNH BÁO ĐỎ; CKF_USER_PIN_LOCKED ->
      TỪ CHỐI login.
    * Bọc CKR_* thành ErrorInfo TIẾNG VIỆT (TT 15 yêu cầu thông báo tiếng Việt).

Token qua bridge: đọc cert qua RPC, API trả Y HỆT.

CLI: ``python -m core.cert_reader --dump``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from typing import Any, cast

from pydantic import BaseModel

from core import x509_parser
from core.models import CertInfo, ErrorCode, ErrorInfo, KeyInfo, TokenInfo
from core.platform import PlatformAdapter, get_adapter

# Kiểu callback trả PIN: nên trả bytearray để zeroize được.
PinCallback = Callable[[], "bytes | bytearray | str"]
# Kiểu reader nội bộ: (pin, protected_auth) -> dict {"certs": [...]}.
ReaderFn = Callable[..., dict[str, Any]]

_CKR_RE = re.compile(r"CKR_[A-Z0-9_]+")


class CertReadResult(BaseModel):
    """Kết quả đọc chứng thư (API GIỐNG HỆT dù in-process hay bridge)."""

    certificates: list[CertInfo] = []
    logged_in: bool = False
    warnings: list[str] = []
    error: ErrorInfo | None = None


def read_certificates(
    token: TokenInfo,
    pin_callback: PinCallback | None = None,
    *,
    adapter: PlatformAdapter | None = None,
    manager: Any = None,
    reader: ReaderFn | None = None,
) -> CertReadResult:
    """Đọc chứng thư trên ``token`` (2 bước, an toàn PIN, lỗi tiếng Việt)."""
    ad = adapter or get_adapter()
    own_manager = False
    mgr = manager
    if reader is None and token.via_bridge and mgr is None:
        from core.bridge import BridgeManager

        mgr = BridgeManager(ad)
        own_manager = True
    rdr = reader or _make_reader(token, ad, mgr)
    warnings: list[str] = []

    try:
        # -- B1: tìm KHÔNG login -------------------------------------------- #
        try:
            res1 = rdr(pin=None, protected_auth=False)
        except Exception as exc:  # noqa: BLE001
            return CertReadResult(error=_map_error(ad, exc, token), warnings=warnings)

        certs = res1.get("certs", [])
        if certs:
            return _build(certs, logged_in=False, warnings=warnings)

        # -- B2: chứng thư là private -> cần login -------------------------- #
        ps = token.pin_state
        if ps.locked:
            return CertReadResult(
                error=_err(ad, ErrorCode.LOGIN_REQUIRED,
                           "PIN của token ĐÃ BỊ KHOÁ — từ chối đăng nhập.",
                           remediation="Liên hệ nhà cung cấp CA để mở khoá/cấp lại PIN (PUK)."),
                warnings=warnings,
            )
        if ps.final_try:
            warnings.append(
                "⚠️ CẢNH BÁO ĐỎ: đây là LẦN THỬ PIN CUỐI CÙNG — nhập sai sẽ KHOÁ "
                "token VĨNH VIỄN."
            )

        pin_ba: bytearray | None = None
        try:
            if ps.protected_auth_path:
                res2 = rdr(pin=None, protected_auth=True)  # pinpad, không nhập PIN ở host
            else:
                if pin_callback is None:
                    return CertReadResult(
                        error=_err(ad, ErrorCode.LOGIN_REQUIRED,
                                   "Chứng thư ở dạng private, cần đăng nhập PIN nhưng "
                                   "không có pin_callback."),
                        warnings=warnings,
                    )
                pin_ba = _to_bytearray(pin_callback())
                # Truyền bản sao str tối thiểu cho tầng dưới; zeroize bản bytearray.
                res2 = rdr(pin=bytes(pin_ba), protected_auth=False)
        except Exception as exc:  # noqa: BLE001
            return CertReadResult(error=_map_error(ad, exc, token), warnings=warnings)
        finally:
            if pin_ba is not None:
                _zeroize(pin_ba)

        certs2 = res2.get("certs", [])
        if not certs2:
            warnings.append("Đăng nhập xong nhưng không thấy chứng thư nào trên token.")
        return _build(certs2, logged_in=True, warnings=warnings)
    finally:
        if own_manager and mgr is not None:
            mgr.close()


# --------------------------------------------------------------------------- #
# Reader mặc định (định tuyến in-process / bridge)                              #
# --------------------------------------------------------------------------- #
def _make_reader(token: TokenInfo, adapter: PlatformAdapter, manager: Any) -> ReaderFn:
    module = token.module_path
    slot = token.slot_id
    via_bridge = token.via_bridge

    def reader(*, pin: bytes | None = None, protected_auth: bool = False) -> dict[str, Any]:
        if via_bridge:
            params: dict[str, Any] = {"slot_id": slot, "protected_auth": protected_auth}
            if pin is not None:
                # Bridge phải serialize -> chuỗi (không zeroize được qua process;
                # đã đánh dấu sensitive, không log).
                params["pin"] = pin.decode("utf-8", "ignore")
            return cast("dict[str, Any]", manager.call(module, "read_certificates", params))
        from core import pkcs11_ops

        pin_str = pin.decode("utf-8", "ignore") if pin is not None else None
        return pkcs11_ops.read_certificates(module, slot, pin_str, protected_auth)

    return reader


# --------------------------------------------------------------------------- #
# Dựng kết quả + an toàn PIN                                                    #
# --------------------------------------------------------------------------- #
def _build(certs: list[dict[str, Any]], *, logged_in: bool, warnings: list[str]) -> CertReadResult:
    import base64

    out: list[CertInfo] = []
    for c in certs:
        der_b64 = c.get("der_b64", "")
        try:
            info = x509_parser.parse(base64.b64decode(der_b64)) if der_b64 else CertInfo()
        except Exception:  # noqa: BLE001
            info = CertInfo(der_b64=der_b64)
        info.key_id_hex = str(c.get("id_hex", ""))
        kd = c.get("key") or {}
        info.key = KeyInfo(
            has_private_key=bool(kd.get("has_private_key", False)),
            id_hex=str(kd.get("id_hex", "")),
            key_type=str(kd.get("key_type", "")),
            key_class="private" if kd.get("has_private_key") else "unknown",
            key_size=kd.get("key_size"),
            usable_for_signing=bool(kd.get("usable_for_signing", False)),
            allowed_mechanisms=list(kd.get("allowed_mechanisms", []) or []),
        )
        out.append(info)
    return CertReadResult(certificates=out, logged_in=logged_in, warnings=warnings)


def _to_bytearray(raw: bytes | bytearray | str) -> bytearray:
    if isinstance(raw, bytearray):
        return raw
    if isinstance(raw, bytes):
        return bytearray(raw)
    return bytearray(str(raw).encode("utf-8"))


def _zeroize(buf: bytearray) -> None:
    """Ghi đè 0 lên bộ nhớ PIN (không dùng str bất biến)."""
    for i in range(len(buf)):
        buf[i] = 0


# --------------------------------------------------------------------------- #
# Ánh xạ lỗi CKR_* -> ErrorInfo TIẾNG VIỆT                                      #
# --------------------------------------------------------------------------- #
_CKR_VI: dict[str, tuple[ErrorCode, str, str]] = {
    "CKR_PIN_INCORRECT": (ErrorCode.LOGIN_REQUIRED, "Mã PIN không đúng.",
                          "Nhập lại PIN cẩn thận; chú ý số lần thử còn lại để tránh khoá token."),
    "CKR_PIN_LOCKED": (ErrorCode.LOGIN_REQUIRED, "PIN đã bị KHOÁ (nhập sai quá số lần).",
                       "Liên hệ CA để mở khoá bằng PUK hoặc cấp lại token."),
    "CKR_PIN_EXPIRED": (ErrorCode.LOGIN_REQUIRED, "PIN đã hết hạn, cần đổi PIN.",
                        "Đổi PIN theo hướng dẫn của nhà cung cấp CA."),
    "CKR_PIN_INVALID": (ErrorCode.LOGIN_REQUIRED, "PIN không hợp lệ (sai định dạng/độ dài).", ""),
    "CKR_TOKEN_NOT_PRESENT": (ErrorCode.TOKEN_NOT_PRESENT, "Không thấy token (chưa cắm).",
                              "Cắm USB token vào máy rồi thử lại."),
    "CKR_DEVICE_REMOVED": (ErrorCode.TOKEN_NOT_PRESENT, "Token đã bị RÚT giữa chừng.",
                           "Cắm lại token và thực hiện lại thao tác."),
    "CKR_DEVICE_ERROR": (ErrorCode.INTERNAL_ERROR, "Lỗi thiết bị token.",
                         "Rút ra cắm lại; nếu vẫn lỗi, kiểm tra driver middleware."),
    "CKR_USER_ALREADY_LOGGED_IN": (ErrorCode.INTERNAL_ERROR, "Đã đăng nhập trước đó.", ""),
    "CKR_FUNCTION_CANCELED": (ErrorCode.LOGIN_REQUIRED, "Thao tác PIN bị huỷ.", ""),
}


def _map_error(adapter: PlatformAdapter, exc: Exception, token: TokenInfo) -> ErrorInfo:
    """Bọc lỗi PKCS#11 (in-process HOẶC chuỗi từ bridge) -> ErrorInfo tiếng Việt."""
    match = _CKR_RE.search(str(exc))
    ckr = match.group(0) if match else ""
    if ckr in _CKR_VI:
        code, message, remediation = _CKR_VI[ckr]
        if ckr == "CKR_PIN_INCORRECT" and token.pin_state.final_try:
            message += " ĐÂY LÀ LẦN THỬ CUỐI — nhập sai nữa sẽ KHOÁ token vĩnh viễn."
        return _err(adapter, code, message, remediation=remediation, detail=ckr)
    return _err(
        adapter, ErrorCode.INTERNAL_ERROR,
        "Lỗi khi đọc chứng thư trên token.",
        remediation="Kiểm tra token đã cắm, middleware đúng, và thử lại.",
        detail=(ckr or str(exc))[:200],
    )


def _err(
    adapter: PlatformAdapter, code: ErrorCode, message: str, *,
    remediation: str = "", detail: str = "",
) -> ErrorInfo:
    return ErrorInfo(
        code=code, message_vi=message, remediation=remediation,
        platform=adapter.name(), detail=detail,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# CLI: python -m core.cert_reader --dump                                       #
# --------------------------------------------------------------------------- #
def _dump() -> int:
    from core.pkcs11_engine import enumerate_tokens

    tokens = enumerate_tokens()
    if not tokens:
        print("Không thấy token nào (chưa cắm hoặc chưa cài middleware).")
        return 1

    def _ask_pin() -> bytearray:
        import getpass

        return bytearray(getpass.getpass("Nhập PIN token: ").encode("utf-8"))

    rc = 0
    for tok in tokens:
        print("=" * 72)
        print(f"Token: {tok.label or '(không nhãn)'} · CHIP THẬT={tok.manufacturer_id} "
              f"· slot {tok.slot_id} · {'via-bridge' if tok.via_bridge else 'in-process'}")
        result = read_certificates(tok, pin_callback=_ask_pin)
        for w in result.warnings:
            print(f"  ⚠ {w}")
        if result.error:
            print(f"  ✗ [{result.error.code.value}] {result.error.message_vi}")
            if result.error.remediation:
                print(f"     {result.error.remediation}")
            rc = 1
            continue
        print(f"  Đăng nhập: {'có' if result.logged_in else 'không'} · "
              f"chứng thư: {len(result.certificates)}")
        for c in result.certificates:
            has_key = c.key.has_private_key if c.key else False
            print(f"    • Subject: {c.subject_raw}")
            print(f"      Issuer : {c.issuer_raw}")
            print(f"      Serial={c.serial_number} · hết hạn={c.not_after} "
                  f"({'HẾT HẠN' if c.is_expired else f'{c.days_remaining} ngày'})")
            print(f"      Khoá private: {'CÓ' if has_key else 'không'} · "
                  f"{c.public_key_algo} {c.key_size or '?'}bit · CKA_ID={c.key_id_hex}")
            if c.vn_ids:
                print(f"      Định danh VN (ước lượng, {c.profile_confidence}): {c.vn_ids}")
    return rc


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m core.cert_reader")
    parser.add_argument("--dump", action="store_true", help="Đọc & in chứng thư trên mọi token.")
    parser.parse_args(argv)
    return _dump()


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["read_certificates", "CertReadResult", "PinCallback"]
