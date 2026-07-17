# Đóng gói cho macOS (Intel & Apple Silicon — NGANG HÀNG)

## universal2
Đóng gói một binary chạy cả hai kiến trúc (lipo x86_64 + arm64). Dùng Python
universal2 (python.org).

```bash
pip install -r requirements-dev.txt
pyinstaller --onefile --name vn-esign-service --target-arch universal2 \
    --collect-all PyKCS11 --collect-all smartcard \
    --add-data "data:data" -p . service/main.py
```

## Middleware chỉ có x86_64
Nhiều middleware token chỉ có `.dylib` x86_64. Trên Apple Silicon:
`needs_arch_bridge()` = True → bridge helper chạy `arch -x86_64` dưới Rosetta 2
(`softwareupdate --install-rosetta`). Kiểm quarantine:
`xattr -d com.apple.quarantine <dylib>`.

## Chạy nền
launchd agent: `com.vn-esign.service.plist`.

## Ký & công chứng
`codesign --deep --sign "Developer ID Application: ..."` + `notarytool`.
