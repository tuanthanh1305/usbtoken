# Hồ sơ tuân thủ — TT 15/2025/TT-BKHCN + NĐ 23/2025/NĐ-CP

Ánh xạ **từng yêu cầu** của phần mềm ký số / kiểm tra chữ ký số tới **module code**
hiện thực + **test case chứng minh** + **trạng thái**. Phục vụ **kiểm toán kỹ thuật**
(TT 19/2025/TT-BKHCN, hiệu lực 1/1/2026 — hậu kiểm định kỳ).

> ⚠️ **TRUNG THỰC TUYỆT ĐỐI.** Báo cáo đẹp mà sai sẽ vỡ khi kiểm toán. Các mục
> chưa đạt được ghi rõ, kèm lý do. Số Điều/Khoản chính xác **phải đối chiếu bản
> gốc** trước khi nghiệm thu:
> https://rootca.gov.vn/VanBan/Thongtu_So15_2025_TT_BKHCN.pdf

**Chú thích trạng thái:**
`✅ ĐÁP ỨNG` (hiện thực + có test) · `🟡 MỘT PHẦN` (lõi xong, phần còn lại chờ) ·
`❌ CHƯA` (chưa hiện thực) · `⏳ CHỜ VĂN BẢN` (chặn bởi văn bản chính thức chưa có).

---

## A. Điều 17 NĐ 23/2025/NĐ-CP — chức năng phần mềm ký số

| # | Yêu cầu | Module | Test case | Trạng thái |
|---|---|---|---|---|
| 17.1 | Ký số trên thông điệp dữ liệu bằng khoá trong thiết bị chuyên dụng (USB token) | `core/signer.py`, `core/pkcs11_ops.py`, `core/bridge/*` | `test_signer.py::test_softhsm_full_cms_flow` | ✅ ĐÁP ỨNG |
| 17.2 | Kiểm tra hiệu lực chứng thư **TRƯỚC** khi ký | `core/trust/validator.py::assert_signable`, `core/signer.py` (gọi đầu tiên) | `test_signer.py::test_refuse_signing_expired_certificate`, `test_regression_matrix.py::test_invalid_cert_refuses_signing` | ✅ ĐÁP ỨNG |
| 17.3 | Kết nối Cổng eSign công cộng | `core/esign/*` | `test_esign_gateway.py` (khung) | ⏳ CHỜ VĂN BẢN |

---

## B. Điều 5 TT 15/2025 — chức năng phần mềm ký số

| # | Yêu cầu (chức năng) | Module | Test case | Trạng thái |
|---|---|---|---|---|
| 5.a | Kiểm thông tin chủ thể + **hiệu lực chứng thư trước khi ký** (trình tự không đảo) | `validator.assert_signable` → rồi mới `C_Sign` (`signer.py`) | `test_signer.py::test_refuse_signing_{expired,revoked}_certificate` (khẳng định `C_Sign` KHÔNG chạy) | ✅ ĐÁP ỨNG |
| 5.b | Chọn thuật toán/cơ chế ký đúng **Phụ lục I** | `signer.select_mechanism` (token ∩ Phụ lục I) | `test_signer.py::test_refuse_when_appendix_i_not_filled`, `test_no_common_mechanism_refused` | 🟡 MỘT PHẦN (fail-closed đúng; **giá trị hợp lệ chờ Phụ lục I**) |
| 5.c | Gắn chữ ký + **chứng thư** + **thời điểm ký** vào thông điệp ngay (toàn vẹn) | `signer._build_cms` (CMS detached + cert + chain + signingTime) | `test_signer.py::test_cms_detached_signature_verifies` | ✅ ĐÁP ỨNG (CMS/CAdES); PAdES/XAdES 🟡 chờ profile Phụ lục I |
| 5.d | Gắn **dấu thời gian** khi pháp luật yêu cầu (TSA) | `signer.timestamp` (RFC 3161) | `test_signer.py::test_cms_timestamp_attached_when_tsa_returns_token` | 🟡 MỘT PHẦN (RFC3161 xong; **danh sách TSA + điều kiện bắt buộc** chờ Phụ lục I / QCVN 138:2025) |
| 5.e | **Lưu trữ**: chứng thư đã dùng để ký + **CRL/OCSP tại thời điểm ký** + **kết quả kiểm tra** | `core/evidence.py::EvidenceStore.store_evidence` | `test_evidence.py::test_store_writes_all_artifacts`, `::test_store_flags_missing_revocation` | ✅ ĐÁP ỨNG |
| 5.f | Bảo đảm **toàn vẹn** kho lưu trữ (chống sửa) | `evidence.py` (append-only + hash chain + head anchor) | `test_evidence.py::test_detects_tampered_{ledger_record,blob}`, `::test_detects_tail_truncation` | ✅ ĐÁP ỨNG |
| 5.g | **Hiển thị rõ ràng** trạng thái ký, chứng thư, **chuỗi đường dẫn tin cậy** | `web/src/components/{CertDetail,TrustPath,RevocationInfo}.tsx` | (UI — `npm run build`/typecheck ở CI) | ✅ ĐÁP ỨNG |
| 5.h | Thông báo **BẰNG TIẾNG VIỆT** kết quả (thành công/không) | `ValidationResult.reasons_vi`, `ErrorInfo.message_vi`, toàn bộ UI | rải khắp test (mọi `reasons_vi`) | ✅ ĐÁP ỨNG |
| 5.i | **Cập nhật** chứng thư NEAC + CA công cộng + DS nước ngoài | `core/trust/store.py`, `tools/sync_trust_store.py`, `core/trust/signing.py` | `test_trust_store.py`, `test_sync_trust_store.py` | ✅ ĐÁP ỨNG (chỉ nạp từ rootca.gov.vn, ký kho, fail-closed) |
| 5.j | KHÔNG cho ký khi chứng thư không hợp lệ (từ chối + lý do) | `signer.assert_signable` ném `SigningNotAllowedError`; `/sign` trả 422 | `test_service_app.py::test_sign_refused_when_cert_invalid` | ✅ ĐÁP ỨNG |

---

## C. Điều 6 TT 15/2025 — kiểm tra hiệu lực (phần mềm kiểm tra chữ ký số)

| # | Yêu cầu | Module | Test case | Trạng thái |
|---|---|---|---|---|
| 6.a | Kiểm hiệu lực qua **ĐƯỜNG DẪN TIN CẬY** tới chứng thư gốc NEAC (chain building, **không regex**) | `core/trust/chain.py`, `validator._build_chain` | `test_trust_chain.py`, `test_regression_matrix.py::test_regex_ca_identification_is_wrong` | ✅ ĐÁP ỨNG |
| 6.b | Kiểm **thu hồi** ở mọi bậc (CRL/OCSP); **mất mạng → UNKNOWN, không VALID** | `core/trust/revocation.py`, `validator` (fail-closed) | `test_validator.py::test_offline_revocation_gives_unknown_not_valid`, `test_regression_matrix.py::test_offline_revocation_is_unknown_never_valid` | ✅ ĐÁP ỨNG |
| 6.c | Kiểm **thời gian hiệu lực** (chưa hiệu lực / hết hạn) | `validator.validate` | `test_validator.py::test_expired_certificate` | ✅ ĐÁP ỨNG |
| 6.d | Đáp ứng tiêu chí hợp lệ chứng thư **Phụ lục II** | `validator._check_appendix_ii`, `core/trust/policy.py` | `test_validator.py::test_valid_requires_configured_policy` | 🟡 MỘT PHẦN (cơ chế xong; **tiêu chí chờ Phụ lục II**) |
| 6.e | Kiểm **toàn vẹn chữ ký** trên thông điệp (báo nếu dữ liệu bị đổi) | `core/signature_verify.py`, `/validate` | `test_service_app.py::test_validate_with_signature_{valid,tampered}` | ✅ ĐÁP ỨNG |
| 6.f | Lưu **kết quả kiểm tra** làm bằng chứng | `ValidationResult`, `validator.persist_validation`, `evidence.py` | `test_evidence.py` | ✅ ĐÁP ỨNG |

---

## D. Điều 7 & Điều 8 TT 15/2025 — kết nối Cổng eSign

| # | Yêu cầu | Module | Test case | Trạng thái |
|---|---|---|---|---|
| 7 | Kết nối trực tiếp Cổng kết nối dịch vụ chứng thực chữ ký số công cộng | `core/esign/gateway.py` (interface + adapter) | `test_esign_gateway.py` (khung + hạ tầng) | ⏳ CHỜ VĂN BẢN |
| 8 | Tuân thủ **Hướng dẫn kỹ thuật về kết nối** do Bộ KH&CN ban hành | `core/esign/spec.py` (đọc spec) + `data/compliance/esign_gateway_spec.yaml` (`status: not_filled`) | — | ⏳ CHỜ VĂN BẢN |

> **KHÔNG tuyên bố tuân thủ Điều 7/8.** Giao thức/endpoint/định dạng/xác thực chỉ
> biết qua Hướng dẫn kỹ thuật (chưa có). `make_gateway()` trả `NullEsignGateway`
> **từ chối** mọi thao tác (fail-closed). Hạ tầng an-toàn-để-viết-trước (allowlist
> domain, bắt buộc TLS, retry/backoff, circuit breaker, audit) đã xong + có test.

---

## E. Hạng mục ĐANG CHỜ VĂN BẢN (điều kiện tiên quyết chưa đáp ứng)

| Hạng mục | File dữ liệu | Chặn chức năng nào | Hành vi khi chưa có |
|---|---|---|---|
| **Phụ lục I** (tiêu chuẩn kỹ thuật: thuật toán/khoá/băm/định dạng) | `data/compliance/appendix_I.yaml` (`not_filled`) | Chọn cơ chế ký (5.b), định dạng (5.c), TSA (5.d) | Signer **từ chối ký** (fail-closed) |
| **Phụ lục II** (tiêu chí hợp lệ chứng thư) | `data/compliance/appendix_II.yaml` (`not_filled`) | Kiểm hợp lệ chặt (6.d) | Validator **không trả VALID** (fail-closed) |
| **Hướng dẫn kỹ thuật Cổng eSign** | `data/compliance/esign_gateway_spec.yaml` (`not_filled`) | Kết nối Cổng (Đ.7/8) | Gateway **từ chối kết nối** (fail-closed) |
| **Danh sách TSA** | (từ rootca.gov.vn — mục THÔNG TIN CÁC TSA) | Dấu thời gian (5.d) | `timestamp()` cần `tsa_url` do vận hành cấp |

Lấy Phụ lục I/II từ bản gốc TT 15/2025; Hướng dẫn kỹ thuật + danh sách TSA từ
**NEAC** (115 Trần Duy Hưng, Hà Nội — rootca.gov.vn).

---

## F. Ba trục độc lập (nguyên lý gốc — chống nhận diện sai)

| Trục | Ý nghĩa | Nguồn dữ liệu | Module |
|------|---------|---------------|--------|
| 1 — MODULE | File ta nạp (dlopen/LoadLibrary) | tên file / `vendor_intel.yaml` | `core/platform`, `core/discovery`, `core/bridge` |
| 2 — CHIP | Phần cứng thật trong token | `C_GetTokenInfo().manufacturerID` | `core/pkcs11_ops`, `core/pkcs11_engine` |
| 3 — CA | Bên phát hành chứng thư | **chain building** tới NEAC Root | `core/trust` |

Ba trục **không suy ra được nhau**. Chứng minh:
- `test_regression_matrix.py::test_track_a_only_cannot_identify_fptca` — bảng vàng
  chỉ Track A **không** nhận ra FPT-CA → Track B (CA rebrand) là cần thiết.
- `test_regression_matrix.py::test_regex_ca_identification_is_wrong` — regex
  `nacencomm→I-CA` **sai** (Nacencomm vận hành **CA2**) → vì sao dùng chain building.
- `tools/inspect_module.py` — chứng minh module Track B (`fptca_v4.so`) chỉ là lớp
  bọc; **CHIP THẬT** đọc từ `C_GetTokenInfo` (khác tên CA).

---

## G. Quyền riêng tư & thu thập thực địa

- `tools/harvest_intel.py` — thu thập **ẩn danh** (không Subject DN/MST/CCCD/serial/
  DER/PIN), chỉ ghi file local, **hỏi xác nhận** trước khi ghi.
- Đánh giá tác động quyền riêng tư: [`DPIA.md`](DPIA.md).
- Ma trận kiểm thử đầy đủ: [`test_matrix.md`](test_matrix.md).

## H. Cơ chế fail-safe pháp lý (tóm tắt)

- Kho tin cậy rỗng → `INVALID` (không đoán CA).
- Chưa điền Phụ lục I/II → validator không `VALID`, signer từ chối ký.
- Chưa có Hướng dẫn kỹ thuật eSign → gateway từ chối kết nối.
- Mất mạng khi kiểm thu hồi → `UNKNOWN` (không bao giờ `VALID`).

> Mọi cơ chế trên là **cố ý** — thà từ chối còn hơn khẳng định/ký sai về pháp lý.
