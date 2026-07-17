"""CLI chẩn đoán: ``python -m tools.diagnose``.

In: OS + kiến trúc host (bits/machine/rosetta), module phát hiện (Track A/B kèm
arch & cảnh báo lệch kiến trúc), trạng thái PC/SC, kho neo tin cậy, tình trạng
Phụ lục I/II, và ghi chú khắc phục theo OS.
"""

from __future__ import annotations

import sys

from core.engine import get_platform_info, list_modules, trust_store_summary
from core.platform import get_adapter
from core.trust.policy import CompliancePolicy


def _indent(text: str, pad: int = 6) -> str:
    return "\n".join(" " * pad + line for line in text.splitlines())


def diagnose() -> int:
    adapter = get_adapter()
    info = get_platform_info(adapter)

    print("=" * 70)
    print(" vn-esign-suite — CHẨN ĐOÁN MÔI TRƯỜNG")
    print("=" * 70)
    print(f" Hệ điều hành : {info.name}")
    print(f" Host arch    : {info.machine} · {info.bits}-bit"
          + (" · Rosetta 2" if info.rosetta else ""))
    print(f" Python       : {info.python_version}")
    print(f" PC/SC        : {'✅ sẵn sàng' if info.pcsc_ready else '⚠️  CHƯA sẵn sàng'}")
    print(f" config_dir   : {info.config_dir}")
    print(f" log_dir      : {info.log_dir}")

    if not info.pcsc_ready and info.pcsc_remediation:
        print("\n--- Khắc phục PC/SC ---")
        print(_indent(info.pcsc_remediation))

    for note in adapter.platform_notes():
        print("\n--- Ghi chú nền tảng ---")
        print(_indent(f"• {note}"))

    modules = list_modules(adapter)
    print(f"\n--- Module PKCS#11 (Track A/B): {len(modules)} ---")
    if not modules:
        print("  (chưa thấy module nào — cài middleware token hoặc gói CA)")
    for m in modules:
        flag = "  ⚠️ LỆCH ARCH" if m.needs_arch_bridge else ""
        print(f"  • [Track {m.track.value}] {m.chip_hint or '(chưa rõ)'} · {m.arch}{flag}")
        print(f"      {m.path}  (nguồn={m.source}, tin cậy={m.confidence:.2f})")
        for w in m.warnings:
            print(_indent(f"⚠ {w}", 8))

    ts = trust_store_summary()
    print("\n--- Kho neo tin cậy ---")
    print(f"  Chứng thư: {ts['total_certificates']} · Neo gốc: {ts['trust_anchors']}")
    if ts["total_certificates"] == 0:
        print("  ⚠️ Kho TRỐNG — chưa nạp chứng thư gốc NEAC + CA (xem data/trust_store/README.md)")

    pol = CompliancePolicy().status()
    print("\n--- Tuân thủ TT 15/2025 ---")
    print(f"  Phụ lục I  (tiêu chuẩn kỹ thuật)     : {'ĐÃ điền' if pol.appendix_i_filled else '⚠️ CHƯA điền'}")
    print(f"  Phụ lục II (yêu cầu hợp lệ chứng thư): {'ĐÃ điền' if pol.appendix_ii_filled else '⚠️ CHƯA điền'}")
    if not pol.fully_configured:
        print("  → Kiểm tra hợp lệ theo Phụ lục bị TỪ CHỐI (fail-safe) cho tới khi điền đủ.")

    print("=" * 70)
    return 0 if (info.pcsc_ready and ts["total_certificates"] > 0) else 1


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m tools.diagnose")
    parser.add_argument("--diagnose", action="store_true", help="In chẩn đoán (mặc định).")
    parser.parse_args(argv)
    return diagnose()


if __name__ == "__main__":
    sys.exit(main())
