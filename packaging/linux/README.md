# Đóng gói cho Linux

## Phụ thuộc hệ thống
- `pcscd` + `libccid` (PC/SC); `p11-kit`, `opensc` (khuyến nghị).
- Với FPT-CA (Track B): gói `fptca-4.0` cài `/usr/lib/fptca_v4.so`.

## Build native (PyInstaller)
```bash
pip install -r requirements-dev.txt
pyinstaller --onefile --name vn-esign-service \
    --collect-all PyKCS11 --collect-all smartcard \
    --add-data "data:data" -p . service/main.py
```
Build **riêng** cho từng kiến trúc (x86_64 / arm64), không cross-compile lẫn lộn.

## Chạy nền
`vn-esign.service` (systemd user unit) trong thư mục này.

## Kho fallback
`certstore_fallback()` đọc NSS DB `~/.pki/nssdb` qua `certutil` (gói `libnss3-tools`).
