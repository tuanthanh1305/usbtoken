# Đánh giá tác động quyền riêng tư (DPIA) — thu thập intel thực địa

Áp dụng cho `tools/harvest_intel.py` (và `tools/inspect_module.py`). Đây là dự án
cấp quốc gia xử lý dữ liệu liên quan công dân → quyền riêng tư là **ràng buộc cứng**.

## 1. Mục đích & cơ sở

- **Mục đích:** hoàn thiện bảng vàng tương thích thiết bị (`vendor_intel.yaml`) và
  **xác minh PROFILE định dạng định danh** (Subject DN) mà mục 1.8 chưa chốt — để
  phần mềm nhận diện đúng token/chip/CA trên thực địa.
- **Phạm vi:** chạy trên **máy của chính người dùng**, do người dùng khởi động.
- **Cơ sở:** người dùng chủ động chạy + **xác nhận rõ ràng** trước khi ghi.

## 2. Nguyên tắc tối thiểu hoá dữ liệu (data minimisation)

**KHÔNG BAO GIỜ thu thập:**

| Trường | Lý do loại trừ |
|---|---|
| Subject DN nguyên văn | Chứa tên chủ thể (cá nhân/tổ chức) |
| MST / CCCD / CMND / số định danh (giá trị) | Định danh trực tiếp cá nhân/doanh nghiệp |
| Serial chứng thư | Định danh duy nhất một chứng thư → truy ngược chủ thể |
| DER chứng thư | Chứa toàn bộ thông tin trên |
| Serial token | Định danh **thiết bị** (và gián tiếp người dùng) |
| PIN | Bí mật xác thực — tuyệt đối không |

**CHỈ thu thập (đã ẩn danh / không định danh):**

- Host: OS, phiên bản, kiến trúc (+Rosetta) — thông tin môi trường.
- Module: đường dẫn **đã xoá tên người dùng** (`<HOME>`, `/home/<user>/`), sha256
  (của binary công khai), track, arch, tầng phát hiện, `C_GetInfo` (metadata thư viện).
- Token: `manufacturerID` (**chip** — hạng thiết bị), model, cờ PIN đã giải mã, nhãn
  (do người dùng đặt — có gate xác nhận để tự rà).
- Chứng thư: **Issuer DN** (là CA, không phải cá nhân), **tên CA từ chain**, thuật
  toán + độ dài khoá, và **CẤU TRÚC Subject DN đã ẩn danh** — mỗi RDN chỉ giữ
  OID/tên + **"hình dạng"** (chữ→`a`, số→`X`) + độ dài; **loại** định danh VN có mặt
  (không giá trị). Ví dụ `MST:0101234567` → `aaa:XXXXXXXXXX`.
- ATR: định danh **loại thẻ**, không định danh người dùng.

> "Hình dạng" đủ để suy ra ĐỊNH DẠNG profile (vd. MST 10 số) nhưng **không lộ nội
> dung**. Tên trong CN chỉ hiện độ dài các từ (chuỗi `a`), không lộ ký tự.

## 3. Kiểm soát kỹ thuật

- **Local-only:** công cụ **KHÔNG** gửi báo cáo đi đâu — chỉ ghi 1 file JSON.
- **Xác nhận bắt buộc:** in ra **toàn bộ** nội dung sắp ghi + checklist quyền riêng
  tư, rồi **hỏi y/N**. `--yes` chỉ để tự động hoá (người chạy tự chịu trách nhiệm).
- **Phân quyền:** file báo cáo `chmod 600` (chỉ chủ sở hữu).
- **Rà soát sau:** người dùng tự xem lại file trước khi (tuỳ ý) chia sẻ.

## 4. Rủi ro còn lại & giảm thiểu

| Rủi ro | Giảm thiểu |
|---|---|
| Nhãn token chứa tên người | Hiển thị trong gate xác nhận để người dùng tự xoá/không ghi |
| Độ dài từ trong CN (qua "hình dạng") | Chỉ độ dài, không ký tự; chấp nhận được cho mục đích profile |
| File local bị lộ | `chmod 600`; công cụ không tự truyền |
| Lạm dụng `inspect_module` | Chỉ đọc **metadata công khai**; KHÔNG dịch ngược/bẻ khoá/patch |

## 5. Quyền của chủ thể dữ liệu

Vì công cụ **không tập trung hoá** và **không truyền** dữ liệu, không hình thành
kho dữ liệu cá nhân phía máy chủ. File nằm trên máy người dùng, do người dùng
toàn quyền xoá.

## 6. Kết luận

Với tối thiểu hoá + ẩn danh + xác nhận + local-only, rủi ro quyền riêng tư ở mức
**thấp và có kiểm soát**. Bất kỳ thay đổi nào mở rộng trường thu thập **phải cập
nhật lại DPIA này** trước khi phát hành.
