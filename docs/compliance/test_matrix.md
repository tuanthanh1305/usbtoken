# Ma trận kiểm thử

Bao phủ tổ hợp: **Track × Chip × OS × Arch × PIN × Trạng thái cert × CA**. CI dùng
**SoftHSM2** chạy toàn bộ luồng **không cần phần cứng** trên cả 3 OS; các tổ hợp
phần cứng thật đánh dấu **thực địa** (chạy trên máy có token tương ứng).

## 1. Các chiều

| Chiều | Giá trị |
|---|---|
| Track | A (theo chip) · B (CA rebrand) |
| Chip | SafeNet · Feitian · Watchdata · SafeSign · OpenSC · **SoftHSM2** (ảo, CI) |
| OS | Win10/11 · macOS Intel · macOS Apple Silicon · Ubuntu · Fedora |
| Arch | khớp · lệch → **bridge** |
| PIN | không cần · bắt buộc · pinpad (protected auth path) |
| Trạng thái cert | VALID · EXPIRED · REVOKED · chain đứt · CRL hết hạn · mất mạng |
| CA | mẫu từ 26 CA công cộng (ưu tiên thị phần lớn) |

## 2. Tự động (CI, SoftHSM2 — không cần phần cứng)

| Kịch bản | Test |
|---|---|
| Luồng ký CMS đầy đủ trên token ảo | `test_signer.py::test_softhsm_full_cms_flow` |
| Chọn cơ chế token ∩ Phụ lục I | `test_signer.py::test_select_mechanism_prefers_hash_in_token`, `::test_no_common_mechanism_refused` |
| Băm-ngoài dựng DigestInfo chuẩn | `test_signer.py::test_hash_outside_builds_correct_digestinfo` |
| VALID / EXPIRED / REVOKED / UNKNOWN / FOREIGN | `test_validator.py::test_*` |
| Chain đứt → INVALID | `test_validator.py::test_chain_broken_missing_root` |
| Chữ ký sai → INVALID | `test_validator.py::test_chain_bad_signature` |
| CRL hết hạn → UNKNOWN | `test_validator.py::test_crl_expired_gives_unknown` |
| Mất mạng → UNKNOWN (không VALID) | `test_validator.py::test_offline_revocation_gives_unknown_not_valid` |
| Bridge (lệch arch) đọc token/ký | `test_bridge*.py`, `test_pkcs11_engine.py` (ops giả lập bridge) |
| PIN: final_try cảnh báo / locked chặn | `test_cert_reader.py`, UI `PinLogin.tsx` |

## 3. TEST HỒI QUY BẮT BUỘC (`tests/test_regression_matrix.py`)

| # | Bài học được "khoá" | Test | Kỳ vọng |
|---|---|---|---|
| 1 | Track B là cần thiết | `test_track_a_only_cannot_identify_fptca` | Bảng vàng chỉ Track A **KHÔNG** nhận ra FPT-CA |
| 2 | Vì sao bỏ regex nhận diện CA | `test_regex_ca_identification_is_wrong` | `nacencomm→I-CA` **SAI** (Nacencomm là **CA2**) |
| 3 | Fail-closed khi mất mạng | `test_offline_revocation_is_unknown_never_valid` | `UNKNOWN`, **không bao giờ** `VALID` |
| 4 | Yêu cầu luật định trước khi ký | `test_invalid_cert_refuses_signing[EXPIRED\|REVOKED]` | Ném lỗi, `C_Sign` **không** chạy |

## 4. THỰC ĐỊA BẮT BUỘC — FPT-CA thật trên Ubuntu

`tests/test_regression_matrix.py::test_fptca_field_end_to_end`
(**skipif** khi không có `/usr/lib/fptca_v4.so`). Chạy trên máy Ubuntu đã cài
`fptca-4.0`. Bốn điểm kiểm (chứng minh **ba trục tách bạch**):

1. **Dò ra qua Tầng 1:** `dpkg -L fptca-4.0` → discovery thấy `fptca_v4.so`.
2. **Arch đúng:** ELF32 trên host 64-bit → `needs_arch_bridge=True` → **qua bridge
   VẪN đọc được cert**.
3. **Chain building:** → Vietnam National Root CA → `ca_name = "FPT-CA"`
   (**từ chain, KHÔNG regex**).
4. **Chip thật:** `C_GetTokenInfo().manufacturerID` = CHIP THẬT (hãng chip, **khác**
   "FPT") → chứng minh TRỤC 2 độc lập TRỤC 3.

Công cụ hỗ trợ thực địa:
- `python -m tools.inspect_module /usr/lib/fptca_v4.so` — module wrap chip nào.
- `python -m tools.harvest_intel` — báo cáo ẩn danh (xem `DPIA.md`).

## 5. Bảng tổ hợp (đánh dấu độ ưu tiên)

| Track | Chip | OS | Arch | PIN | Cert | Cách chạy |
|---|---|---|---|---|---|---|
| — | SoftHSM2 | 3 OS (CI) | khớp | bắt buộc | VALID/EXPIRED/REVOKED/UNKNOWN | ✅ tự động |
| B | (FPT wrap) | Ubuntu | ELF32/host64 → bridge | bắt buộc | VALID | ⭐ thực địa (test #4) |
| A | Feitian/SafeNet | Win/mac/Linux | khớp & lệch | các loại | các loại | thực địa |
| A | Watchdata/SafeSign | Win/mac | khớp | pinpad | VALID | thực địa |
| A | OpenSC | Linux | khớp | bắt buộc | VALID | bán tự động (OpenSC + SoftHSM) |

> Ô "thực địa" cần token vật lý của CA/chip tương ứng; ghi lại kết quả (ẩn danh,
> qua `harvest_intel`) để bổ sung `vendor_intel.yaml`.
