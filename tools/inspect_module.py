"""Soi một module PKCS#11 (đặc biệt Track B) xem WRAP CHIP NÀO — chỉ đọc metadata.

Track B = module do CA phát hành riêng (vd. ``fptca_v4.so``). Bên trong thường là
lớp bọc quanh middleware của một hãng chip (Feitian/Watchdata/SafeNet...). Biết
chip thật giúp bổ sung ``data/vendor_intel.yaml`` và chọn đúng cầu nối arch.

MỤC ĐÍCH: CHỈ nhận diện & tương thích thiết bị HỢP PHÁP trên máy của CHÍNH người
dùng. ⛔ KHÔNG dịch ngược, KHÔNG bẻ khoá, KHÔNG can thiệp/patch module — chỉ đọc
METADATA CÔNG KHAI (C_GetInfo, symbol bảng động, chuỗi in được, dependency).

    python -m tools.inspect_module /usr/lib/fptca_v4.so [--json]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# Từ khoá hãng chip/middleware (đối chiếu chuỗi/ symbol công khai).
_VENDOR_KEYWORDS = {
    "feitian": "Feitian", "epass": "Feitian ePass", "watchdata": "Watchdata",
    "safenet": "SafeNet", "etoken": "SafeNet eToken", "gemalto": "Gemalto/Thales",
    "castle": "Feitian (libcastle)", "safesign": "SafeSign (A.E.T.)",
    "opensc": "OpenSC", "softhsm": "SoftHSM", "aladdin": "Aladdin/SafeNet",
    "hid": "HID Global", "idprime": "Gemalto IDPrime", "oberthur": "Oberthur/IDEMIA",
}


def _run(cmd: list[str], *, timeout: float = 20.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, text=True,
                              errors="ignore")
        return (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return ""


def _c_getinfo(path: str) -> dict[str, Any]:
    """C_GetInfo qua ModuleSession (in-process/bridge) — metadata thư viện."""
    try:
        from core.bridge.router import ModuleSession

        info = ModuleSession(path).get_info()
        return {
            "ok": info.get("ok", False),
            "manufacturerID": info.get("manufacturer", ""),
            "libraryDescription": info.get("library_description", ""),
            "cryptokiVersion": info.get("cryptoki_version"),
            "error": info.get("error", ""),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def _token_chip(path: str) -> list[dict[str, str]]:
    """C_GetTokenInfo().manufacturerID = CHIP THẬT (nếu có token cắm)."""
    try:
        from core.bridge.router import ModuleSession

        session = ModuleSession(path)
        chips = []
        for tok in session.enumerate_tokens():
            chips.append({"manufacturerID_chip": tok.manufacturer_id, "model": tok.model})
        return chips
    except Exception:  # noqa: BLE001
        return []


def _native_metadata(path: str, os_name: str) -> dict[str, Any]:
    """Symbol bảng động + dependency + chuỗi in được (chỉ đọc, theo OS)."""
    meta: dict[str, Any] = {}
    if os_name == "linux":
        meta["dynamic_symbols"] = _run(["nm", "-D", "--defined-only", path])[:4000]
        meta["dependencies"] = _run(["ldd", path])[:4000]
    elif os_name == "macos":
        meta["dependencies"] = _run(["otool", "-L", path])[:4000]
        meta["dynamic_symbols"] = _run(["nm", "-gU", path])[:4000]
    elif os_name == "windows":
        # pefile (nếu có) — import table/dependency. Không bắt buộc.
        try:
            import pefile  # type: ignore

            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories()
            deps = [e.dll.decode("ascii", "ignore") for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
            meta["dependencies"] = "\n".join(deps)
        except Exception as exc:  # noqa: BLE001
            meta["dependencies"] = f"(pefile không sẵn: {exc})"
    # strings (dùng chung nếu có lệnh; fallback tự đọc).
    meta["strings_sample"] = _extract_strings(path)
    return meta


def _extract_strings(path: str) -> str:
    out = _run(["strings", path])
    if out:
        return out[:8000]
    # Fallback: tự trích chuỗi in được từ bytes.
    try:
        data = Path(path).read_bytes()
    except OSError:
        return ""
    found = re.findall(rb"[\x20-\x7e]{5,}", data)
    return b"\n".join(found[:2000]).decode("ascii", "ignore")[:8000]


def _guess_vendors(*texts: str) -> list[str]:
    blob = "\n".join(texts).lower()
    hits: list[str] = []
    for kw, label in _VENDOR_KEYWORDS.items():
        if kw in blob and label not in hits:
            hits.append(label)
    return hits


def inspect(path: str) -> dict[str, Any]:
    from core.platform import get_adapter

    os_name = get_adapter().name()
    p = Path(path)
    result: dict[str, Any] = {"path": str(p), "exists": p.is_file(), "os": os_name}
    if not p.is_file():
        result["error"] = "Không tìm thấy file module."
        return result

    result["c_getinfo"] = _c_getinfo(path)
    result["token_chip"] = _token_chip(path)
    native = _native_metadata(path, os_name)
    # Không nhét toàn bộ dump vào kết luận — giữ để tham chiếu.
    result["native_metadata"] = native

    vendors = _guess_vendors(
        result["c_getinfo"].get("manufacturerID", ""),
        result["c_getinfo"].get("libraryDescription", ""),
        " ".join(c.get("manufacturerID_chip", "") for c in result["token_chip"]),
        native.get("dependencies", ""),
        native.get("dynamic_symbols", ""),
        native.get("strings_sample", ""),
    )
    result["wrapped_chip_guess"] = vendors
    result["conclusion_vi"] = _conclude(result, vendors)
    result["vendor_intel_suggestion"] = _suggest_intel(p, os_name, result, vendors)
    return result


def _conclude(result: dict[str, Any], vendors: list[str]) -> str:
    chip = ", ".join(c.get("manufacturerID_chip", "") for c in result["token_chip"] if c.get("manufacturerID_chip"))
    if chip:
        return (f"CHIP THẬT (C_GetTokenInfo.manufacturerID) = '{chip}'. "
                + (f"Dấu hiệu wrap: {', '.join(vendors)}." if vendors else "Không thấy dấu hiệu hãng khác."))
    if vendors:
        return ("Chưa có token để đọc chip thật; nhưng metadata gợi ý module wrap: "
                + ", ".join(vendors) + " (cần cắm token để xác nhận qua C_GetTokenInfo).")
    return "Chưa đủ dấu hiệu để kết luận wrap chip nào (cắm token + kiểm lại)."


def _suggest_intel(p: Path, os_name: str, result: dict[str, Any], vendors: list[str]) -> dict[str, Any]:
    """Gợi ý một entry vendor_intel.yaml (người vận hành rà rồi thêm thủ công)."""
    return {
        "track": "B",
        "os": os_name,
        "filenames": [p.name],
        "chip_vendor": vendors[0] if vendors else "(cần xác nhận)",
        "confidence": "documented" if result["token_chip"] else "hypothesis",
        "note": "Do tools/inspect_module gợi ý — RÀ SOÁT trước khi thêm vào data/vendor_intel.yaml.",
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(prog="python -m tools.inspect_module")
    parser.add_argument("module", help="Đường dẫn module PKCS#11 (.so/.dylib/.dll).")
    parser.add_argument("--json", action="store_true", help="Xuất JSON đầy đủ.")
    args = parser.parse_args(argv)

    result = inspect(args.module)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("exists") else 1

    print(f"Module: {result['path']}  (OS: {result['os']})")
    if not result.get("exists"):
        print("  ✗ Không tìm thấy file.")
        return 1
    ci = result["c_getinfo"]
    print(f"  C_GetInfo: manufacturerID='{ci.get('manufacturerID','')}' · "
          f"lib='{ci.get('libraryDescription','')}' · v{ci.get('cryptokiVersion')}")
    for c in result["token_chip"]:
        print(f"  CHIP THẬT (token): manufacturerID='{c.get('manufacturerID_chip','')}' · {c.get('model','')}")
    print(f"  Dấu hiệu wrap: {', '.join(result['wrapped_chip_guess']) or '(chưa rõ)'}")
    print(f"  → {result['conclusion_vi']}")
    print("  Gợi ý vendor_intel (rà trước khi thêm):")
    print("   " + json.dumps(result["vendor_intel_suggestion"], ensure_ascii=False))
    print("\n⛔ Chỉ đọc metadata công khai — KHÔNG dịch ngược/bẻ khoá/patch module.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
