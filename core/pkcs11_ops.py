"""Thao tác PKCS#11 mức thấp — DÙNG CHUNG cho in-process VÀ bridge helper.

Đây là NGUỒN DUY NHẤT của các thao tác token: dù gọi trực tiếp trong daemon
(cùng arch) hay qua helper (khác arch, subprocess), kết quả trả về DẠNG DICT
JSON-friendly GIỐNG HỆT nhau. Nhờ đó tầng trên (``core/bridge/router.py``) map
sang TokenInfo/CertInfo Y HỆT bất kể tuyến.

Giữ tối thiểu phụ thuộc: chỉ ``PyKCS11`` (nạp lười) + thư viện chuẩn — để helper
chạy được cả khi là .exe 32-bit hoặc dưới Rosetta/qemu (không cần cryptography;
việc parse chứng thư làm ở HOST).

⚠️ Trường ``pin`` là NHẠY CẢM: KHÔNG bao giờ đưa vào giá trị trả về, thông báo
lỗi hay log.
"""

from __future__ import annotations

import base64
import threading
from typing import Any

# Khoá toàn cục: TUẦN TỰ HOÁ mọi thao tác PKCS#11 in-process. Daemon đa luồng +
# module thường KHÔNG thread-safe -> mỗi lần chỉ một module được nạp/thao tác
# trong tiến trình. (PyKCS11.load() gọi C_Initialize với CKF_OS_LOCKING_OK ở
# tầng C; khoá này là lớp phòng vệ thêm cho an toàn tuyệt đối.)
_PKCS11_LOCK = threading.RLock()

# Cờ CK_TOKEN_INFO (định nghĩa tại chỗ, không cần PyKCS11 để decode).
CKF_LOGIN_REQUIRED = 0x00000004
CKF_PROTECTED_AUTHENTICATION_PATH = 0x00000100
CKF_USER_PIN_COUNT_LOW = 0x00010000
CKF_USER_PIN_FINAL_TRY = 0x00020000
CKF_USER_PIN_LOCKED = 0x00040000

# Ánh xạ tên cơ chế ký -> hằng CKM_* (mở rộng khi cần).
_MECH_NAMES = (
    "RSA_PKCS", "SHA1_RSA_PKCS", "SHA256_RSA_PKCS", "SHA384_RSA_PKCS",
    "SHA512_RSA_PKCS", "RSA_PKCS_PSS", "SHA256_RSA_PKCS_PSS",
    "ECDSA", "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512",
)


class PyKCS11Unavailable(RuntimeError):
    """Không import được PyKCS11 trong tiến trình hiện tại."""


def _pykcs11() -> Any:
    try:
        import PyKCS11
    except Exception as exc:  # noqa: BLE001
        raise PyKCS11Unavailable(f"Không import được PyKCS11: {exc}") from exc
    return PyKCS11


def _clean(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "ignore")
    return str(value).replace("\x00", " ").strip()


def _decode_pin_state(flags: int) -> dict[str, bool]:
    return {
        "login_required": bool(flags & CKF_LOGIN_REQUIRED),
        "count_low": bool(flags & CKF_USER_PIN_COUNT_LOW),
        "final_try": bool(flags & CKF_USER_PIN_FINAL_TRY),
        "locked": bool(flags & CKF_USER_PIN_LOCKED),
        "protected_auth_path": bool(flags & CKF_PROTECTED_AUTHENTICATION_PATH),
    }


# --------------------------------------------------------------------------- #
# get_info — C_GetInfo (không cần token/PIN)                                    #
# --------------------------------------------------------------------------- #
def get_info(module_path: str) -> dict[str, Any]:
    """C_Initialize + C_GetInfo. Trả dict (ok, cryptoki_version, manufacturer...)."""
    result: dict[str, Any] = {
        "ok": False, "cryptoki_version": None, "manufacturer": "",
        "library_description": "", "error": "",
    }
    try:
        pk = _pykcs11()
    except PyKCS11Unavailable as exc:
        result["error"] = str(exc)
        return result
    lib = pk.PyKCS11Lib()
    _PKCS11_LOCK.acquire()
    try:
        try:
            lib.load(module_path)
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"load thất bại: {exc}"
            return result
        try:
            info = lib.getInfo()
            cver = getattr(info, "cryptokiVersion", None)
            if hasattr(cver, "major"):
                result["cryptoki_version"] = [int(cver.major), int(cver.minor)]
            elif isinstance(cver, (list, tuple)) and len(cver) >= 2:
                result["cryptoki_version"] = [int(cver[0]), int(cver[1])]
            result["manufacturer"] = _clean(getattr(info, "manufacturerID", ""))
            result["library_description"] = _clean(getattr(info, "libraryDescription", ""))
            result["ok"] = result["cryptoki_version"] is not None
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"C_GetInfo thất bại: {exc}"
        finally:
            _finalize(lib)
        return result
    finally:
        _PKCS11_LOCK.release()


# --------------------------------------------------------------------------- #
# enumerate_tokens — C_GetSlotList + C_GetTokenInfo (không cần PIN)             #
# --------------------------------------------------------------------------- #
def enumerate_tokens(module_path: str) -> list[dict[str, Any]]:
    """Liệt kê token đang cắm. Trả list dict token (JSON-friendly)."""
    pk = _pykcs11()
    lib = pk.PyKCS11Lib()
    _PKCS11_LOCK.acquire()
    try:
        lib.load(module_path)  # C_Initialize (CKF_OS_LOCKING_OK ở tầng C)
        tokens: list[dict[str, Any]] = []
        for slot in lib.getSlotList(tokenPresent=True):
            ti = lib.getTokenInfo(slot)
            flags = int(ti.flags)
            tokens.append({
                "slot_id": int(slot),
                "label": _clean(ti.label),
                "manufacturer_id": _clean(ti.manufacturerID),
                "model": _clean(ti.model),
                "serial": _clean(ti.serialNumber),
                "flags": flags,
                "pin_state": _decode_pin_state(flags),
            })
        return tokens
    finally:
        _finalize(lib)
        _PKCS11_LOCK.release()


# --------------------------------------------------------------------------- #
# read_certs — tìm CKO_CERTIFICATE (login nếu có PIN cho object private)        #
# --------------------------------------------------------------------------- #
def read_certs(module_path: str, slot_id: int, pin: str | None = None) -> list[dict[str, Any]]:
    """Đọc chứng thư trên token. Trả list {der_b64, id_hex, label}.

    ``pin`` (nhạy cảm) chỉ dùng để login, KHÔNG bao giờ trả ra/log.
    """
    pk = _pykcs11()
    lib = pk.PyKCS11Lib()
    session = None
    _PKCS11_LOCK.acquire()
    try:
        lib.load(module_path)
        session = lib.openSession(slot_id)
        if pin:
            session.login(pin)  # PIN chỉ ở đây, không đi đâu khác
        template = [(pk.CKA_CLASS, pk.CKO_CERTIFICATE)]
        certs: list[dict[str, Any]] = []
        for obj in session.findObjects(template):
            attrs = session.getAttributeValue(obj, [pk.CKA_VALUE, pk.CKA_ID, pk.CKA_LABEL])
            der = bytes(attrs[0]) if attrs[0] else b""
            if not der:
                continue
            certs.append({
                "der_b64": base64.b64encode(der).decode("ascii"),
                "id_hex": bytes(attrs[1]).hex() if attrs[1] else "",
                "label": _clean(attrs[2]) if attrs[2] else "",
            })
        return certs
    finally:
        _safe_logout(session)
        _finalize(lib)
        _PKCS11_LOCK.release()


# --------------------------------------------------------------------------- #
# read_certificates — bản đầy đủ: DUYỆT HẾT cert + khớp khoá qua CKA_ID         #
# --------------------------------------------------------------------------- #
_KEY_TYPE_NAMES = {0: "RSA", 1: "DSA", 2: "DH", 3: "EC", 0x40: "EC_EDWARDS"}


def read_certificates(
    module_path: str,
    slot_id: int,
    pin: str | None = None,
    protected_auth: bool = False,
) -> dict[str, Any]:
    """Đọc HẾT chứng thư trên token + khớp khoá private theo CKA_ID.

    KHÔNG tự quyết định login: caller (cert_reader) chạy 2 bước (không login ->
    login). Ở đây: nếu có ``pin`` hoặc ``protected_auth`` thì login rồi tìm;
    ngược lại tìm không login. ``pin`` chỉ để login, KHÔNG trả ra/log.
    """
    pk = _pykcs11()
    lib = pk.PyKCS11Lib()
    session = None
    _PKCS11_LOCK.acquire()
    try:
        lib.load(module_path)
        session = lib.openSession(slot_id, pk.CKF_SERIAL_SESSION)
        if pin:
            session.login(pin)
        elif protected_auth:
            try:
                session.login()  # đường xác thực bảo vệ (pinpad) — không truyền PIN
            except TypeError:
                session.login(None)

        certs: list[dict[str, Any]] = []
        # ⭐ DUYỆT HẾT: một token có thể chứa NHIỀU cert của NHIỀU CA.
        for obj in session.findObjects([(pk.CKA_CLASS, pk.CKO_CERTIFICATE)]):
            attrs = session.getAttributeValue(obj, [pk.CKA_VALUE, pk.CKA_ID, pk.CKA_LABEL])
            der = bytes(attrs[0]) if attrs[0] else b""
            if not der:
                continue
            cka_id = attrs[1]
            certs.append({
                "der_b64": base64.b64encode(der).decode("ascii"),
                "id_hex": bytes(cka_id).hex() if cka_id else "",
                "label": _clean(attrs[2]) if attrs[2] else "",
                "key": _match_key(pk, session, cka_id),
            })
        return {"certs": certs}
    finally:
        _safe_logout(session)
        _finalize(lib)
        _PKCS11_LOCK.release()


def _match_key(pk: Any, session: Any, cka_id: Any) -> dict[str, Any]:
    """SỢI CHỈ nối cert<->key: tìm CKO_PRIVATE_KEY cùng CKA_ID."""
    key: dict[str, Any] = {
        "has_private_key": False, "key_type": "", "key_size": None,
        "usable_for_signing": False, "allowed_mechanisms": [],
        "id_hex": bytes(cka_id).hex() if cka_id else "",
    }
    if not cka_id:
        return key
    try:
        objs = session.findObjects([(pk.CKA_CLASS, pk.CKO_PRIVATE_KEY), (pk.CKA_ID, cka_id)])
    except Exception:  # noqa: BLE001
        return key
    if not objs:
        return key
    key["has_private_key"] = True
    obj = objs[0]
    try:
        kt = session.getAttributeValue(obj, [pk.CKA_KEY_TYPE])[0]
        key["key_type"] = _KEY_TYPE_NAMES.get(int(kt), str(kt))
    except Exception:  # noqa: BLE001
        pass
    try:
        bits = session.getAttributeValue(obj, [pk.CKA_MODULUS_BITS])[0]
        if bits:
            key["key_size"] = int(bits)
    except Exception:  # noqa: BLE001
        pass
    try:
        key["usable_for_signing"] = bool(session.getAttributeValue(obj, [pk.CKA_SIGN])[0])
    except Exception:  # noqa: BLE001
        pass
    return key


# --------------------------------------------------------------------------- #
# sign — C_SignInit + C_Sign (login bằng PIN)                                   #
# --------------------------------------------------------------------------- #
def sign(
    module_path: str,
    slot_id: int,
    key_id: str,
    mechanism: str,
    data_b64: str,
    pin: str | None = None,
) -> dict[str, Any]:
    """Ký ``data`` bằng khoá private có CKA_ID = ``key_id`` (hex). Trả {signature_b64}."""
    pk = _pykcs11()
    mech_name = mechanism.upper().removeprefix("CKM_")
    if mech_name not in _MECH_NAMES:
        raise ValueError(f"Cơ chế ký không hỗ trợ: {mechanism!r}")
    ckm = getattr(pk, f"CKM_{mech_name}")

    lib = pk.PyKCS11Lib()
    session = None
    _PKCS11_LOCK.acquire()
    try:
        lib.load(module_path)
        session = lib.openSession(slot_id)
        if pin:
            session.login(pin)
        key_id_bytes = list(bytes.fromhex(key_id)) if key_id else []
        template = [(pk.CKA_CLASS, pk.CKO_PRIVATE_KEY)]
        if key_id_bytes:
            template.append((pk.CKA_ID, key_id_bytes))
        keys = session.findObjects(template)
        if not keys:
            raise ValueError("Không tìm thấy khoá private khớp CKA_ID trên token.")
        data = base64.b64decode(data_b64)
        signature = session.sign(keys[0], data, pk.Mechanism(ckm, None))
        return {"signature_b64": base64.b64encode(bytes(signature)).decode("ascii")}
    finally:
        _safe_logout(session)
        _finalize(lib)
        _PKCS11_LOCK.release()


# --------------------------------------------------------------------------- #
# Dọn dẹp                                                                       #
# --------------------------------------------------------------------------- #
def _safe_logout(session: Any) -> None:
    if session is None:
        return
    try:
        session.logout()
    except Exception:  # noqa: BLE001
        pass
    try:
        session.closeSession()
    except Exception:  # noqa: BLE001
        pass


def _finalize(lib: Any) -> None:
    try:
        lib.unload()
    except Exception:  # noqa: BLE001
        pass


__all__ = [
    "get_info",
    "enumerate_tokens",
    "read_certs",
    "read_certificates",
    "sign",
    "PyKCS11Unavailable",
]
