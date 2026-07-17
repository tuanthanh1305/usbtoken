"""Nhập bảng ATR từ smartcard_list.txt (Ludovic Rousseau / pcsc-tools).

    python -m tools.import_smartcard_list <smartcard_list.txt> [--output PATH]
                                          [--filter-vendors] [--limit N]

Tải file nguồn tại: https://pcsc-tools.apdu.fr/smartcard_list.txt

Định dạng smartcard_list.txt:
    <dòng ATR ở cột 0: hex + '.' wildcard>
    <TAB/space + dòng mô tả (một hoặc nhiều)>
    # dòng comment

⚠️ Dữ liệu nhập vào có ``verified: false`` — ATR chỉ để TỐI ƯU thứ tự dò, KHÔNG
kết luận CA. Cần đối chiếu token THẬT của VN trước khi đặt verified: true.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from core.config import atr_table_path

_SOURCE = "https://pcsc-tools.apdu.fr/smartcard_list.txt"


def parse_smartcard_list(text: str) -> list[dict[str, str]]:
    """Parse nội dung smartcard_list.txt -> [{atr, description}]."""
    entries: list[dict[str, str]] = []
    cur_atr: str | None = None
    cur_desc: list[str] = []

    def _flush() -> None:
        if cur_atr and cur_desc:
            entries.append({"atr": cur_atr, "description": cur_desc[0]})

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0] in " \t":  # dòng mô tả (thụt lề)
            cur_desc.append(raw.strip())
        else:  # dòng ATR (cột 0)
            _flush()
            cur_atr = raw.strip()
            cur_desc = []
    _flush()
    return entries


def _vendor_keywords() -> set[str]:
    """Từ khoá chip từ vendor_intel.yaml (để lọc entry liên quan VN)."""
    from core.intel import load_intel

    kws: set[str] = set()
    for e in load_intel().filter(track="A"):
        import re as _re

        for tok in _re.split(r"[/\s]+", e.chip_vendor.lower()):
            if len(tok) >= 3:
                kws.add(tok)
    return kws


def build_table(
    entries: list[dict[str, str]], *, filter_vendors: bool = False, limit: int | None = None
) -> dict[str, Any]:
    if filter_vendors:
        kws = _vendor_keywords()
        entries = [e for e in entries if any(k in e["description"].lower() for k in kws)]
    if limit is not None:
        entries = entries[:limit]
    return {
        "source": _SOURCE,
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "entries": [
            {"atr": e["atr"], "description": e["description"], "verified": False}
            for e in entries
        ],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m tools.import_smartcard_list")
    parser.add_argument("source", help="Đường dẫn smartcard_list.txt")
    parser.add_argument("--output", default="", help="File YAML đích (mặc định data/atr_table.yaml).")
    parser.add_argument("--filter-vendors", action="store_true",
                        help="Chỉ giữ entry khớp chip trong vendor_intel.yaml.")
    parser.add_argument("--limit", type=int, default=None, help="Giới hạn số entry.")
    args = parser.parse_args(argv)

    src = Path(args.source)
    if not src.is_file():
        print(f"Không thấy file nguồn: {src}")
        return 1

    entries = parse_smartcard_list(src.read_text(encoding="utf-8", errors="ignore"))
    table = build_table(entries, filter_vendors=args.filter_vendors, limit=args.limit)
    out = Path(args.output) if args.output else atr_table_path()
    out.write_text(yaml.safe_dump(table, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"Đã ghi {len(table['entries'])} entry ATR -> {out}")
    print("⚠️ verified=false — cần đối chiếu token THẬT trước khi tin. ATR chỉ tối ưu, không kết luận CA.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
