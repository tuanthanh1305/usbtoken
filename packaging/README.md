# Đóng gói vn-esign-suite — Windows · macOS · Linux

Ba OS **ngang hàng**. Mỗi thư mục con có script build + đóng gói + README triển
khai cho người dùng cuối.

```
packaging/
  common/    secure_fetch.sh · bundle_trust_store.py   (dùng chung)
  windows/   PyInstaller (daemon x64 + helper x86) · signtool · Inno Setup · Service
  macos/     universal2 + helper x86_64 · entitlements · codesign+notarytool · .dmg/.pkg · LaunchAgent
  linux/     PyInstaller · .deb/.rpm (fpm) · AppImage · udev · systemd --user
```

## ⭐ NGUYÊN TẮC AN TOÀN CỦA INSTALLER (bắt buộc)

Bộ cài của một số CA Việt Nam có **phản ví dụ nguy hiểm**: tải qua HTTP không
chữ ký, `chmod 777` file trong `/tmp` rồi chạy bằng root → **bất kỳ user local
nào cũng ghi đè được trước khi root thực thi** (race condition leo thang đặc
quyền). **Chúng ta TUYỆT ĐỐI KHÔNG lặp lại pattern đó.**

Mọi script cài/tải trong thư mục này PHẢI:

1. **HTTPS + TLS** — `curl --fail --proto '=https' --tlsv1.2` (từ chối redirect
   sang http). Không bao giờ `curl | sh` từ nguồn chưa kiểm.
2. **Verify checksum/chữ ký** trước khi dùng bất cứ file tải về (SHA-256 ghim
   sẵn; verify chữ ký nếu có).
3. **`chmod 700`/`600` — KHÔNG BAO GIỜ `777`.** File thực thi 700, dữ liệu 600.
4. **`mktemp -d`** thư mục tạm CHỦ SỞ HỮU-ONLY (không dùng đường dẫn `/tmp/cố-định`
   đoán được → tránh race/symlink attack).
5. **`set -euo pipefail`** + kiểm mã thoát MỌI lệnh tải/giải nén.
6. **Không chạy bằng root khi không cần.** Cài user-scope (`systemd --user`,
   LaunchAgent, per-user) là mặc định; chỉ cần root cho phụ thuộc hệ thống
   (pcscd, udev) và có xác nhận rõ ràng.

`packaging/common/secure_fetch.sh` là hàm tải-và-verify tham chiếu — dùng lại,
đừng viết lại kiểu thiếu an toàn.

## ⭐ Kho neo tin cậy đóng gói SẴN (đã ký)

Bộ cài **kèm sẵn** kho neo tin cậy đã ký (`data/trust_store/current/` +
`manifest.json` + `manifest.sig`, và khoá công khai ghim `data/trust_signing_pub.pem`).
Máy mới **KHÔNG phải ra mạng** mới có kho hợp lệ để kiểm tra/ký.

`packaging/common/bundle_trust_store.py` **kiểm tra kho đã ký hợp lệ TRƯỚC khi
build**; thiếu/chưa ký → **từ chối đóng gói** (fail-closed — không phát hành bộ
cài không có gốc tin cậy).

## Chữ ký mã (code signing) — vì sao bắt buộc

- **Windows:** Authenticode (`signtool`) cho **cả hai** exe (daemon x64 + helper
  x86) → tránh SmartScreen chặn.
- **macOS:** `codesign --options runtime` + **entitlements** (xem
  `macos/entitlements.plist` — thiếu `disable-library-validation` thì **không
  dlopen được middleware CA**) + **notarization** (thiếu → Gatekeeper chặn).
- **Linux:** ký gói `.deb`/`.rpm` bằng GPG của kho phát hành; AppImage kèm chữ ký.

## CI

`.github/workflows/build.yml` — matrix `windows-latest · macos-14 (arm64) ·
macos-13 (x86_64) · ubuntu-latest`: chạy test rồi build artefact từng OS.
Bí mật ký (chứng thư/khoá) đưa qua **GitHub Secrets**, KHÔNG commit.
