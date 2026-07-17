"""CLI hỗ trợ nạp kho neo tin cậy: ``python -m tools.fetch_trust_store``.

⚠️ CÔNG CỤ NÀY KHÔNG TỰ ĐỘNG TẢI-VÀ-TIN chứng thư. Tin cậy chứng thư gốc là
quyết định bảo mật: phải tải từ nguồn CHÍNH THỨC (rootca.gov.vn / NEAC) và
XÁC MINH VÂN TAY thủ công trước khi đưa vào ``data/trust_store/``.

Công cụ chỉ:
  * in hướng dẫn quy trình nạp đúng cách;
  * liệt kê chứng thư hiện có trong kho (kèm vân tay SHA-256) để đối chiếu;
  * (nếu đã cấu hình Cổng eSign) kiểm tra kết nối — việc tải danh sách tin cậy
    thực tế chờ tài liệu tích hợp chính thức.
"""

from __future__ import annotations

import sys

from cryptography.hazmat.primitives import hashes

from core.config import trust_store_dir
from core.trust.anchors import TrustAnchorStore


def _list_store() -> None:
    store = TrustAnchorStore()
    print(f"Kho: {trust_store_dir()}")
    if store.is_empty:
        print("  (TRỐNG — chưa có chứng thư nào)")
        return
    for cert in store.certificates:
        fp = cert.fingerprint(hashes.SHA256()).hex()
        anchor = " [NEO GỐC]" if store.is_trust_anchor(cert) else ""
        print(f"  • {cert.subject.rfc4514_string()}{anchor}")
        print(f"      SHA-256: {fp}")


def _print_guidance() -> None:
    print(
        "\nQUY TRÌNH NẠP KHO TIN CẬY (thủ công, đúng chuẩn):\n"
        "  1. Tải chứng thư gốc NEAC (Vietnam National Root CA) và chứng thư 26 CA\n"
        "     công cộng từ nguồn CHÍNH THỨC: https://rootca.gov.vn\n"
        "  2. XÁC MINH vân tay SHA-256 với công bố chính thức của NEAC.\n"
        "  3. Chép file (.der/.pem/.crt) vào data/trust_store/ (đặt tên rõ ràng).\n"
        "  4. Chạy lại công cụ này để đối chiếu vân tay.\n"
        "  5. Cập nhật định kỳ danh sách CA qua Cổng eSign (core/esign/) — danh sách\n"
        "     26 CA công cộng BIẾN ĐỘNG."
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m tools.fetch_trust_store")
    parser.add_argument("--list", action="store_true", help="Liệt kê chứng thư hiện có.")
    parser.add_argument("--check-gateway", action="store_true", help="Kiểm tra kết nối Cổng eSign.")
    args = parser.parse_args(argv)

    _list_store()

    if args.check_gateway:
        from core.esign import ESignGatewayClient
        from core.errors import ESignGatewayError

        try:
            ok = ESignGatewayClient().health()
            print(f"\nCổng eSign: {'kết nối được' if ok else 'không phản hồi'}")
        except ESignGatewayError as exc:
            print(f"\nCổng eSign: {exc.message}")
            if exc.detail:
                print(f"  {exc.detail}")

    _print_guidance()
    return 0


if __name__ == "__main__":
    sys.exit(main())
