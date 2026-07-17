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

## Bố cục thư mục

```
data/trust_store/
  sources.yaml        # danh mục URL nguồn chính thức (điền từ rootca.gov.vn)
  ca_registry.yaml    # 26 CA công cộng — MỐC ĐỐI SOÁT (không dùng nhận diện)
  current/            # KHO ĐANG DÙNG (đã áp dụng & ký) — do sync tạo, gitignore
    manifest.json     # provenance từng file (sha256 + url + thời điểm tải)
    manifest.sig      # chữ ký Ed25519 của manifest (anti-tamper)
    root/ · ca/ · crl/ · foreign/
  internal/           # neo tin cậy nội bộ do người vận hành thêm (có audit)
  _staging/           # sync ghi tạm ở đây trước khi xác nhận (gitignore)
  audit.log           # nhật ký thay đổi kho (JSONL)
```

## Quy trình cập nhật (bắt buộc có chủ đích)

```bash
# 1) Điền URL chính thức vào sources.yaml (từ https://rootca.gov.vn)
# 2) Xem trước thay đổi (KHÔNG áp dụng):
python -m tools.sync_trust_store --dry-run
# 3) Áp dụng (yêu cầu xác nhận + ký kho):
python -m tools.sync_trust_store --apply
# 4) Kiểm tra kho đã ký hợp lệ:
python -m core.trust.store --list --verify
```

## Anti-tamper (chống sửa kho cục bộ)

Kho `current/` được **ký Ed25519**; runtime (`core/trust/store.py::load`) verify
chữ ký + sha256 từng file bằng khoá công khai **ghim sẵn** `data/trust_signing_pub.pem`.
Sửa nội dung kho mà không có khoá bí mật → `verified=False` → `is_usable=False`
→ hệ thống **fail-closed** (từ chối ký / từ chối báo "hợp lệ").

- PRODUCTION: khoá bí mật do người vận hành/build giữ (`VN_ESIGN_TRUST_SIGNING_KEY`),
  khoá công khai ghim ở chế độ **chỉ-đọc**.

## Trạng thái hiện tại

`current/` **TRỐNG** (chưa sync). Khi kho trống/không ký, `is_usable=False` và
`ValidationResult.status = UNTRUSTED` — đúng thiết kế fail-closed.

> Không commit chứng thư/khoá tải tự động (xem `.gitignore`). Chỉ commit chứng
> thư đã xác minh thủ công kèm nguồn gốc rõ ràng.
