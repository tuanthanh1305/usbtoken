# data/trust_store/ — Kho NEO TIN CẬY

Thư mục này chứa **chứng thư gốc NEAC (Vietnam National Root CA)** và **chứng
thư của 26 CA công cộng** (cùng chứng thư trung gian) dùng để **dựng đường dẫn
tin cậy** khi kiểm tra hiệu lực (Điều 5/6 TT 15/2025).

## Nguyên tắc BẮT BUỘC

1. **Chỉ nạp chứng thư từ nguồn chính thức** — NEAC / https://rootca.gov.vn —
   và **xác minh vân tay (SHA-256) thủ công** trước khi đưa vào đây. KHÔNG tải
   tự động rồi tin ngay (điều đó phá vỡ mô hình tin cậy).
2. **Không nhận diện CA bằng regex** trên chuỗi Issuer. CA được nhận diện bằng
   **chain building mật mã** tới neo gốc trong thư mục này (`core/trust/chain.py`).
3. Danh sách 26 CA công cộng **biến động** — cập nhật qua Cổng eSign
   (`core/esign/`) hoặc thủ công, kèm ghi chú nguồn + ngày.

## Định dạng file

- `.der`, `.cer` (DER nhị phân) hoặc `.pem`, `.crt` (PEM). Bộ nạp tự nhận cả hai.
- Chứng thư **tự phát hành** (subject == issuer) được coi là **neo gốc**.

## Trạng thái hiện tại

**TRỐNG** (chỉ có `.gitkeep`). Chưa nạp chứng thư nào. Khi kho trống,
`ValidationResult.status = UNTRUSTED` và không thể nhận diện CA — đúng như thiết
kế fail-safe.

## Quy ước đặt tên gợi ý

```
neac_root_ca.der                 # Vietnam National Root CA (neo gốc)
public_ca_<ten>_<năm>.der        # chứng thư CA công cộng
intermediate_<ten>.der           # chứng thư trung gian (nếu có)
```

> Không commit chứng thư tải tự động vào git (xem `.gitignore`). Chỉ commit
> chứng thư đã xác minh thủ công kèm nguồn gốc rõ ràng.
