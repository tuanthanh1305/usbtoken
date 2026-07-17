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
| 5 | Gắn dấu thời gian khi pháp luật yêu cầu | `core/signer.py::Signer.timestamp` (RFC 3161) | Khung; thuật toán băm + danh sách TSA chờ Phụ lục I / rootca.gov.vn | *cần xác nhận* |
| 6 | Kiểm tra hiệu lực qua **ĐƯỜNG DẪN TIN CẬY** tới chứng thư gốc NEAC | `core/trust/chain.py` (`ChainBuilder`), `core/trust/validator.py` | **Hiện thực** (chain building mật mã) | *cần xác nhận* |
| 7 | Kết nối Cổng eSign công cộng (Điều 7/8 TT 15) | `core/esign/*` (`make_gateway`, `NullEsignGateway`, `HttpEsignGateway`) | 🚧 **PENDING** — chỉ có KHUNG; chờ Hướng dẫn kỹ thuật Bộ KH&CN (xem mục dưới) | **KHÔNG tuyên bố tuân thủ** |
| 8 | Lưu chứng thư đã ký + **CRL tại thời điểm ký** + kết quả kiểm tra trạng thái | `core/models.py::ValidationResult`, `core/trust/validator.py::persist_validation`, `core/trust/revocation.py` | **Hiện thực** (lưu bằng chứng + ảnh chụp CRL) | *cần xác nhận* |
| 12 | Ký số (C_Sign) + trình tự Điều 5 (validate TRƯỚC khi ký) | `core/signer.py::Signer`, `service/api/gateway.py` (`/sign`) | **Hiện thực** (gate `assert_signable`; cơ chế/tham số từ Phụ lục I) | *cần xác nhận* |
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

## 🚧 Điều 7 & Điều 8 TT 15/2025 — Kết nối Cổng eSign: **PENDING**

> **Trạng thái tuân thủ: CHƯA — CHỜ HƯỚNG DẪN KỸ THUẬT CỦA BỘ KH&CN.**
> Trung thực về trạng thái tuân thủ quan trọng hơn báo cáo đẹp.

**Căn cứ:** Điều 44 NĐ 23/2025/NĐ-CP; Điều 7 và Điều 8 TT 15/2025/TT-BKHCN — phần
mềm ký số phải kết nối trực tiếp Cổng kết nối dịch vụ chứng thực chữ ký số công
cộng, **tuân thủ "Hướng dẫn kỹ thuật về kết nối" do Bộ KH&CN ban hành** (Điều 8).

**Điều kiện tiên quyết chưa đáp ứng:** Văn bản Hướng dẫn kỹ thuật quy định giao
thức, endpoint, định dạng bản tin và cơ chế xác thực. **Chưa có nó thì không thể
hiện thực đúng**; hiện thực theo phỏng đoán là rủi ro không chấp nhận được.

**Đã làm (an toàn để viết trước, KHÔNG phụ thuộc giao thức):**
- Interface `EsignGateway` (`register` / `submit_signature` / `query_status` /
  `health`) — `core/esign/gateway.py`.
- `NullEsignGateway`: mặc định **TỪ CHỐI** mọi thao tác (fail-closed) kèm hướng dẫn.
- `HttpEsignGateway` + `core/esign/spec.py` đọc `data/compliance/esign_gateway_spec.yaml`:
  allowlist domain, **bắt buộc HTTPS + TLS verify**, retry/backoff, circuit breaker,
  audit log **không lộ dữ liệu nhạy cảm**. Test dùng Transport giả (mock server CI).

**Cần làm để tuyên bố tuân thủ Điều 7/8:**
1. Lấy Hướng dẫn kỹ thuật chính thức từ **NEAC** (Trung tâm Chứng thực điện tử
   quốc gia, Bộ KH&CN, 115 Trần Duy Hưng, Hà Nội — rootca.gov.vn).
2. Điền `data/compliance/esign_gateway_spec.yaml` (endpoint, `message_format`,
   `auth`, `allowed_domains`, `operations`…) và đặt `status: filled`.
3. Bổ sung encoder bản tin nếu định dạng ≠ `json`; rà soát xác thực (mTLS/OAuth2…).
4. Kiểm thử đối chiếu với môi trường sandbox của Cổng; cập nhật lại bảng trên.

## Cơ chế fail-safe pháp lý

- Kho tin cậy rỗng → `ValidationResult.status = INVALID` (không đoán CA).
- Chưa điền Phụ lục I/II → mọi kiểm tra "chặt" bị từ chối (validator không trả
  `VALID`, signer từ chối ký). Cố ý — để không tạo kết luận/chữ ký sai về pháp lý.
- Chưa có Hướng dẫn kỹ thuật eSign → `NullEsignGateway` từ chối kết nối (Điều 7/8).
