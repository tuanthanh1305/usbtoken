"""CLI chẩn đoán tầng platform: ``python -m core.platform --diagnose``.

In: OS, kiến trúc host (kèm cờ Rosetta), module phát hiện (Track A/B + arch từng
file), cảnh báo lệch kiến trúc, trạng thái PC/SC và gợi ý khắc phục ĐÚNG OS.

Đây là công cụ khám phá môi trường — chưa nạp/đọc token thật.
"""

from __future__ import annotations

import sys

from core.engine import get_platform_info, list_modules
from core.platform import get_adapter


def _indent(text: str, pad: int = 6) -> str:
    return "\n".join(" " * pad + line for line in text.splitlines())


def diagnose() -> int:
    """Chạy chẩn đoán, in ra stdout. Trả 0 nếu PC/SC sẵn sàng, 1 nếu chưa."""
    adapter = get_adapter()
    info = get_platform_info(adapter)

    print("=" * 70)
    print(" vn-esign-suite — CHẨN ĐOÁN TẦNG PLATFORM")
    print("=" * 70)
    print(f" Hệ điều hành : {info.name}")
    arch = f"{info.machine} · {info.bits}-bit"
    if info.rosetta:
        arch += " · DƯỚI Rosetta 2"
    print(f" Host arch    : {arch}")
    print(f" Python       : {info.python_version}")
    print(f" PC/SC        : {'✅ sẵn sàng' if info.pcsc_ready else '⚠️  CHƯA sẵn sàng'}")

    if info.pcsc_remediation:
        print("\n--- Ghi chú/Khắc phục PC/SC ---")
        print(_indent(info.pcsc_remediation))

    notes = adapter.platform_notes()
    if notes:
        print("\n--- Ghi chú nền tảng ---")
        for note in notes:
            print(_indent(f"• {note}"))

    modules = list_modules(adapter)
    print(f"\n--- Module PKCS#11 (Track A/B): {len(modules)} ---")
    if not modules:
        print("  (chưa thấy module nào — cài middleware token / gói CA)")
    mismatched = 0
    for m in modules:
        flag = ""
        if m.needs_arch_bridge:
            flag = "  ⚠️ LỆCH ARCH (cần cầu nối)"
            mismatched += 1
        print(f"  • [Track {m.track.value}] {m.chip_hint or '(chưa rõ)'} · {m.arch}{flag}")
        print(f"      {m.path}  (nguồn={m.source}, tin cậy={m.confidence:.2f})")
        for w in m.warnings:
            print(_indent(f"⚠ {w}", 8))

    if mismatched:
        print(
            f"\n⚠️  {mismatched} module lệch kiến trúc với host ({info.machine}); "
            "cần helper cầu nối để nạp."
        )
        print(_indent(adapter.arch_bridge_hint()))

    print("\n--- Cách chạy nền ---")
    print(_indent(info.service_install_hint))
    print("=" * 70)
    return 0 if info.pcsc_ready else 1


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m core.platform")
    parser.add_argument("--diagnose", action="store_true", help="In chẩn đoán (mặc định).")
    parser.parse_args(argv)
    return diagnose()


if __name__ == "__main__":
    sys.exit(main())
