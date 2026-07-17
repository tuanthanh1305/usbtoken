# Đối chiếu tuân thủ — TT 15/2025/TT-BKHCN (Điều 5 & 6)

Tài liệu này ánh xạ **từng yêu cầu chức năng** của phần mềm ký số / kiểm tra chữ
ký số (Điều 17 NĐ 23/2025/NĐ-CP và Điều 5, Điều 6 TT 15/2025/TT-BKHCN) tới
**module code** hiện thực nó. Dùng để đối chiếu khi **kiểm toán kỹ thuật**
(TT 19/2025).

> ⚠️ **Số Điều/Khoản chính xác phải được ĐỐI CHIẾU với bản gốc** trước khi ký
> nghiệm thu:
> https://rootca.gov.vn/VanBan/Thongtu_So15_2025_TT_BKHCN.pdf
> Cột "Điều/Khoản" dưới đây để trạng thái *cần xác nhận* — không suy đoán.

## Bảng ánh xạ yêu cầu → module

| # | Yêu cầu chức năng (theo NĐ 23/2025 Đ.17 & TT 15/2025 Đ.5–6) | Module code | Trạng thái | Điều/Khoản (đối chiếu bản gốc) |
|---|---|---|---|---|
| 1 | Kiểm tra thông tin chủ thể ký + hiệu lực chứng thư **TRƯỚC KHI** ký | `core/trust/validator.py` (`CertificateValidator.validate`) | Khung xong; logic ký chờ giai đoạn sau | *cần xác nhận* |
| 2 | Khóa bí mật lưu trong thiết bị chuyên dụng (USB token) | `core/platform/*` + `core/bridge/*` (nạp PKCS#11) | Khung nạp module xong; đọc token giai đoạn sau | *cần xác nhận* |
| 3 | Gắn chữ ký + chứng thư + thời gian ký vào thông điệp ngay sau khi ký | (giai đoạn ký — chờ Phụ lục I: định dạng CAdES/PAdES/XAdES) | Chưa hiện thực (chặn bởi Phụ lục I) | *cần xác nhận* |
| 4 | Cài đặt/tích hợp/cập nhật chứng thư NEAC + CA công cộng + DS nước ngoài | `core/trust/store.py`, `tools/sync_trust_store.py`, `core/trust/signing.py`, `data/trust_store/` | **Hiện thực** (sync từ rootca.gov.vn có provenance + ký kho + fail-closed); URL nguồn điền vào `sources.yaml` | *cần xác nhận* |
| 5 | Gắn dấu thời gian khi pháp luật yêu cầu | `core/esign/gateway.py` (`request_timestamp`) | Khung; thuật toán băm + TSA chờ Phụ lục I | *cần xác nhận* |
| 6 | Kiểm tra hiệu lực qua **ĐƯỜNG DẪN TIN CẬY** tới chứng thư gốc NEAC | `core/trust/chain.py` (`ChainBuilder`) | **Hiện thực** (chain building mật mã) | *cần xác nhận* |
| 7 | Kết nối Cổng eSign công cộng | `core/esign/gateway.py` | Khung client; endpoint chờ tài liệu tích hợp NEAC | *cần xác nhận* |
| 8 | Lưu chứng thư đã ký + **CRL tại thời điểm ký** + kết quả kiểm tra trạng thái | `core/models.py::ValidationResult`, `core/trust/validator.py::persist_validation`, `core/trust/revocation.py` | **Hiện thực** (lưu bằng chứng + ảnh chụp CRL) | *cần xác nhận* |
| 9 | Thông báo **BẰNG TIẾNG VIỆT** kết quả ký thành công/không thành công | `ValidationResult.reasons_vi`, `ErrorInfo.message_vi` | **Hiện thực** (mọi thông điệp tiếng Việt) | *cần xác nhận* |
| 10 | Tuân thủ **Phụ lục I** (tiêu chuẩn kỹ thuật) | `core/trust/policy.py` + `data/compliance/appendix_I.yaml` | Guard fail-safe; **phải điền Phụ lục I** | *cần xác nhận* |
| 11 | Tuân thủ **Phụ lục II** (yêu cầu hợp lệ chứng thư) | `core/trust/policy.py` + `data/compliance/appendix_II.yaml` | Guard fail-safe; **phải điền Phụ lục II** | *cần xác nhận* |

## Ba trục độc lập (nguyên lý gốc)

| Trục | Ý nghĩa | Nguồn dữ liệu | Module |
|------|---------|---------------|--------|
| 1 — MODULE | File ta nạp (dlopen/LoadLibrary) — *cách nạp* | tên file / vendor_intel | `core/platform`, `core/discovery`, `core/bridge` |
| 2 — CHIP | Phần cứng thật trong token | `C_GetTokenInfo().manufacturerID` | (đọc token — giai đoạn sau) |
| 3 — CA | Bên phát hành chứng thư | **chain building** tới NEAC Root | `core/trust` |

> Ba trục **không suy ra được nhau**. Nhận diện CA = chain building bằng mật mã,
> **KHÔNG** bằng regex trên chuỗi Issuer (Việt Nam có 26 CA công cộng, danh sách
> biến động → regex sai về nguyên tắc, không có giá trị pháp lý).

## Cơ chế fail-safe pháp lý

- Kho tin cậy rỗng → `ValidationResult.status = UNTRUSTED` (không đoán CA).
- Chưa điền Phụ lục I/II → `POLICY_NOT_CONFIGURED`, mọi kiểm tra "chặt" bị từ
  chối (`core/trust/policy.py::require_configured`). Cố ý — để không tạo kết luận
  sai về pháp lý.
