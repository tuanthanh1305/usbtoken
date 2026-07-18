"""Kiểm & chuẩn bị kho neo tin cậy để ĐÓNG GÓI SẴN vào bộ cài.

⭐ Máy mới KHÔNG được phải ra mạng mới có kho hợp lệ. Bộ cài kèm sẵn kho ĐÃ KÝ.
Script này chạy TRƯỚC khi build; kho thiếu/chưa ký/verify thất bại -> THOÁT KHÁC 0
(fail-closed) để CI không phát hành bộ cài không có gốc tin cậy.

    python -m packaging.common.bundle_trust_store --check
    python -m packaging.common.bundle_trust_store --check --require-signed

Chạy từ thư mục gốc repo.
"""

from __future__ import annotations

import sys


def _check(require_signed: bool) -> int:
    from core.config import current_trust_store_dir, trust_signing_pub_path
    from core.trust.store import load as load_store

    pub = trust_signing_pub_path()
    store_dir = current_trust_store_dir()

    print(f"Kho tin cậy   : {store_dir}")
    print(f"Khoá công khai: {pub}")

    have_pub = pub.is_file()
    store = load_store(store_dir, verify_signature=have_pub)
    print(f"  Chứng thư: {len(store.entries)} · CRL: {len(store.crls)}")
    print(f"  Đồng bộ  : {store.synced_at.isoformat() if store.synced_at else '(không rõ)'}")
    print(f"  Verify   : {'✅ hợp lệ' if store.verified else '⚠️ KHÔNG hợp lệ'} — {store.verification_reason}")

    problems: list[str] = []
    if not have_pub:
        problems.append("Thiếu khoá công khai ghim sẵn (data/trust_signing_pub.pem).")
    if store.is_empty:
        problems.append("Kho RỖNG — chưa sync từ rootca.gov.vn (tools/sync_trust_store).")
    if have_pub and not store.verified:
        problems.append("Kho CHƯA được ký/verify (chống sửa).")
    if have_pub and not store.is_usable:
        problems.append("Kho không ở trạng thái DÙNG ĐƯỢC (thiếu neo gốc hoặc chưa verify).")

    if not problems:
        print("✅ Kho neo tin cậy sẵn sàng để đóng gói kèm bộ cài.")
        return 0

    if require_signed:
        print("❌ TỪ CHỐI đóng gói bản phát hành (fail-closed):")
        for p in problems:
            print(f"   • {p}")
        print("   Sync + ký kho bằng khoá vận hành rồi thử lại.")
        return 1

    # Bản DEV/CI (không --require-signed): cho phép build nhưng CẢNH BÁO rõ.
    print("⚠️ Build DEV: kho chưa đạt chuẩn phát hành —")
    for p in problems:
        print(f"   • {p}")
    print("   (Bản phát hành PHẢI dùng --require-signed.)")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="python -m packaging.common.bundle_trust_store")
    p.add_argument("--check", action="store_true", help="Kiểm kho trước khi build.")
    p.add_argument("--require-signed", action="store_true",
                   help="Bắt buộc kho đã ký + verify (khuyến nghị cho bản phát hành).")
    args = p.parse_args(argv)
    if not args.check:
        p.print_help()
        return 2
    return _check(require_signed=args.require_signed)


if __name__ == "__main__":
    sys.exit(main())
