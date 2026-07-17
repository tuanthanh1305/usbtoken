"""Xác thực một module PKCS#11 bằng C_Initialize + C_GetInfo (mức thấp).

CHẠY TRONG TIẾN TRÌNH CON CÔ LẬP (qua bridge helper): module rác/hỏng có thể
segfault khi ``dlopen`` hoặc ``C_Initialize`` — nếu chạy trong daemon sẽ làm sập
cả tiến trình. Vì vậy Tầng 4 luôn gọi hàm này QUA subprocess.

Chỉ phụ thuộc ``PyKCS11`` (nạp lười) + thư viện chuẩn, để helper (kể cả dưới
Rosetta/qemu) import được mà không kéo theo pydantic/tầng khác.

Kết quả (dict JSON-friendly để đi qua IPC):
    ok                  : cryptokiVersion hợp lệ (module là PKCS#11 thật)
    cryptoki_version    : [major, minor] hoặc None
    manufacturer        : CK_INFO.manufacturerID
    library_description : CK_INFO.libraryDescription
    token_slots         : số slot ĐANG CÓ token (phục vụ tối ưu p11-kit-proxy)
    error               : mô tả lỗi (nếu có)
"""

from __future__ import annotations

from typing import Any


def _clean(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "ignore")
    return str(value).replace("\x00", " ").strip()


def _version_tuple(cver: Any) -> list[int] | None:
    """Chuẩn hoá cryptokiVersion về [major, minor] hoặc None."""
    if cver is None:
        return None
    if hasattr(cver, "major") and hasattr(cver, "minor"):
        try:
            return [int(cver.major), int(cver.minor)]
        except (TypeError, ValueError):
            return None
    if isinstance(cver, (tuple, list)) and len(cver) >= 2:
        try:
            return [int(cver[0]), int(cver[1])]
        except (TypeError, ValueError):
            return None
    return None


def probe_module(path: str) -> dict[str, Any]:
    """Nạp module PKCS#11 ``path`` và đọc C_GetInfo. Không ném — trả dict."""
    result: dict[str, Any] = {
        "ok": False,
        "cryptoki_version": None,
        "manufacturer": "",
        "library_description": "",
        "token_slots": 0,
        "error": "",
    }
    try:
        import PyKCS11
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Không import được PyKCS11: {exc}"
        return result

    lib = PyKCS11.PyKCS11Lib()
    try:
        lib.load(str(path))  # C_Initialize bên trong
    except Exception as exc:  # noqa: BLE001 - module không nạp được
        result["error"] = f"load thất bại: {exc}"
        return result

    try:
        info = lib.getInfo()  # C_GetInfo
        version = _version_tuple(getattr(info, "cryptokiVersion", None))
        result["cryptoki_version"] = version
        result["manufacturer"] = _clean(getattr(info, "manufacturerID", ""))
        result["library_description"] = _clean(getattr(info, "libraryDescription", ""))
        result["ok"] = version is not None
        try:
            result["token_slots"] = len(lib.getSlotList(tokenPresent=True))
        except Exception:  # noqa: BLE001 - đếm slot là phụ
            result["token_slots"] = 0
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"C_GetInfo thất bại: {exc}"
    finally:
        try:
            lib.unload()  # C_Finalize
        except Exception:  # noqa: BLE001
            pass
    return result


__all__ = ["probe_module"]
