# Triển khai trên Linux

## Phụ thuộc hệ thống
- `pcscd` + `libccid` (PC/SC) — **bắt buộc**; `p11-kit`, `opensc`, `libnss3-tools`
  (khuyến nghị; `.deb`/`.rpm` khai báo depends).
- Với FPT-CA (Track B): gói `fptca-4.0` cài `/usr/lib/fptca_v4.so`.

## Build

```bash
packaging/linux/build.sh                        # ELF theo kiến trúc host
REQUIRE_SIGNED_STORE=1 packaging/linux/build.sh # buộc kho đã ký (bản phát hành)
```
Build **riêng** cho từng kiến trúc (x86_64 / aarch64) — không cross-compile lẫn lộn.

## Đóng gói

```bash
packaging/linux/package.sh          # .deb + .rpm (fpm) + AppImage
```
- **.deb/.rpm**: cài vào `/opt/vn-esign-suite`, symlink `/usr/bin/vn-esign-service`.
  Maintainer scripts:
  - `postinstall.sh`: `systemctl enable --now pcscd`; cài
    `/etc/udev/rules.d/99-vn-token.rules`; `udevadm control --reload-rules &&
    udevadm trigger`; nhắc `usermod -aG plugdev`.
  - `preremove.sh`: gỡ udev rule (không tắt pcscd — dịch vụ dùng chung).
- **AppImage**: portable, chạy không cần cài (`AppRun` chmod 0755, **không 777**).

## Chạy nền — systemd `--user` (least-privilege, KHÔNG root)

```bash
mkdir -p ~/.config/systemd/user
cp /usr/share/vn-esign-suite/vn-esign.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now vn-esign.service
sudo loginctl enable-linger "$USER"   # để daemon chạy cả khi chưa mở phiên đồ hoạ
```
Chạy trong phiên user → thấy reader/token của user (giống LaunchAgent trên macOS,
Task Scheduler at-logon trên Windows). Daemon **chỉ nghe 127.0.0.1**.

## udev / quyền truy cập token

```bash
sudo usermod -aG plugdev "$USER"      # rồi ĐĂNG NHẬP LẠI
```
Nếu vẫn không thấy token: kiểm `pcscd` đang chạy, cắm lại token, xem tab "Chẩn
đoán" của web (nút sao chép nội dung udev rule).

## Kho fallback

`certstore_fallback()` đọc NSS DB `~/.pki/nssdb` qua `certutil` (`libnss3-tools`);
`modutil -list` để xem module; `enroll_module_to_nss()` chỉ **in ra** lệnh
`modutil -add` (không tự chạy).

## An toàn (nhắc lại)

- Cài vào `/opt` (root sở hữu); `chmod -R go-w` — group/other không ghi được.
- Không tải gì từ mạng lúc cài; **kho neo tin cậy đã ký nằm sẵn** trong gói.
- Maintainer scripts `set -euo pipefail`, không `chmod 777`, không `curl | sh`.
