"""TRỌNG TÂM PHÁP LÝ — kho neo tin cậy + chain building + CRL/OCSP.

Đây là nơi hiện thực các yêu cầu BẮT BUỘC của Điều 5/6 TT 15/2025:
    * Kiểm tra hiệu lực qua ĐƯỜNG DẪN TIN CẬY tới chứng thư gốc do NEAC phát hành.
    * Nhận diện CA bằng CHAIN BUILDING mật mã — TUYỆT ĐỐI KHÔNG bằng regex trên
      chuỗi Issuer (Việt Nam có 26 CA công cộng, danh sách biến động).
    * Kiểm tra trạng thái thu hồi (CRL/OCSP) và lưu ảnh chụp làm bằng chứng.

⚠️ Các tham số thuật toán/độ dài khoá/định dạng (Phụ lục I) và điều kiện hợp lệ
chứng thư (Phụ lục II) KHÔNG được suy đoán trong code — chúng nạp từ
``data/compliance/appendix_I.yaml`` / ``appendix_II.yaml`` (phải điền từ bản gốc
TT 15/2025 trước khi bật kiểm tra chặt).
"""

from __future__ import annotations

from .anchors import TrustAnchorStore
from .chain import ChainBuilder
from .validator import CertificateValidator

# Lưu ý: KHÔNG import ``.store`` ở đây để tránh RuntimeWarning khi chạy trực tiếp
# ``python -m core.trust.store``. Dùng: ``from core.trust.store import load``.

__all__ = ["TrustAnchorStore", "ChainBuilder", "CertificateValidator"]
