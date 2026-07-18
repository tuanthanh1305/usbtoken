# Triển khai trên macOS (Intel & Apple Silicon — NGANG HÀNG)

## Thành phần

| Thành phần | Kiến trúc | Vai trò |
|---|---|---|
| `vn-esign-service.app` | **universal2** (arm64 + x86_64) | Daemon chính |
| `vn-esign-bridge-x86_64` | **x86_64** | Helper nạp middleware chỉ-có-x86_64 dưới Rosetta 2 |

Nhiều middleware token chỉ có `.dylib` **x86_64**. Trên Apple Silicon,
`needs_arch_bridge()` = True → daemon chạy helper bằng `arch -x86_64` (Rosetta 2).
Quarantine dylib tải về: `xattr -d com.apple.quarantine <dylib>`.

## Build

```bash
packaging/macos/build.sh        # cần Python universal2 (python.org)
```
Sinh `dist/vn-esign-service.app` (universal2) + `dist/bridge_x86_64/…` (x86_64).

## ⭐⭐ Ký & Entitlements — ĐỌC KỸ (lỗi khó đoán nhất)

```bash
APP="dist/vn-esign-service.app" \
SIGN_ID="Developer ID Application: TÊN TỔ CHỨC (TEAMID)" \
NOTARY_PROFILE="vn-esign-notary" \
packaging/macos/sign_notarize.sh
```

- Ký với **hardened runtime** (`--options runtime`) **BẮT BUỘC kèm**
  `packaging/macos/entitlements.plist`.
- Entitlement **`com.apple.security.cs.disable-library-validation`** là **BẮT
  BUỘC**: thiếu nó, **Library Validation của Apple chặn dlopen** mọi `.dylib`
  ký bởi **Team ID khác** (middleware CA ký bằng Team ID của họ). Triệu chứng:
  app chạy nhưng **"không thấy token"**, log báo *code signature invalid* /
  *library load disallowed* — rất khó đoán. Đây là lỗi số 1 trên macOS.
- **Notarization** (`notarytool`) + **staple** (`stapler`): thiếu → **Gatekeeper
  chặn** ("Apple không kiểm tra được…"). `sign_notarize.sh` làm cả hai.
- Bí mật notary lưu trong **keychain profile** (`xcrun notarytool
  store-credentials`), KHÔNG nhét Apple ID/mật khẩu vào script/CI plaintext.

## Rosetta 2 (Apple Silicon)

```bash
packaging/macos/check_rosetta.sh                    # kiểm, hướng dẫn cài
AUTO_INSTALL=1 packaging/macos/check_rosetta.sh     # tự cài (có đồng ý)
# Thủ công: softwareupdate --install-rosetta --agree-to-license
```

## Chạy nền — LaunchAgent (KHÔNG LaunchDaemon)

`com.vn-esign.service.plist` → `~/Library/LaunchAgents/`.

> **Vì sao Agent chứ không Daemon?** LaunchDaemon chạy ở ngữ cảnh hệ thống,
> ngoài phiên đăng nhập → **không thấy USB reader/token** gắn theo phiên user.
> LaunchAgent chạy trong phiên user → thấy token, và không cần root.

## Đóng gói

```bash
packaging/macos/make_dmg.sh     # .dmg (kéo-thả vào Applications)
# .pkg: productbuild + productsign "Developer ID Installer: ..."
```

## Kho fallback

`certstore_fallback()` đọc login + System keychain qua `security find-certificate`.

## An toàn (nhắc lại)

- Không tải gì từ mạng lúc cài; **kho neo tin cậy đã ký nằm sẵn** trong `.app`.
- Thư mục tạm dùng `mktemp -d` (chủ-sở-hữu-only), không `/tmp` cố định; không `777`.
