# Triển khai trên Windows

## Kiến trúc: cần HAI exe (rủi ro bitness)

Nhiều middleware token của CA Việt Nam chỉ có **DLL PKCS#11 32-bit** (nằm ở
`SysWOW64`). Daemon 64-bit **không dlopen được DLL 32-bit**. Vì vậy đóng gói:

| Thành phần | Bitness | Vai trò |
|---|---|---|
| `vn-esign-service.exe` | **x64** | Daemon chính (REST loopback + WS) |
| `vn-esign-bridge32.exe` | **x86** | Helper nạp module 32-bit (JSON-RPC qua stdio) |

Daemon tự gọi helper khi `needs_arch_bridge()` = True; đường dẫn helper đặt qua
biến môi trường `VN_ESIGN_BRIDGE_HELPER` (installer đã `setx`).

## Build (từ thư mục gốc repo)

Cần **hai** Python từ python.org: x64 và x86.

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 `
    -Python64 "C:\Python312\python.exe" `
    -Python32 "C:\Python312-32\python.exe" -RequireSignedStore
```
Sinh `dist\vn-esign-service.exe` (x64) + `dist\bridge32\vn-esign-bridge32.exe` (x86).
`-RequireSignedStore` buộc kho neo tin cậy đã ký mới cho build (khuyến nghị bản phát hành).

## Ký Authenticode — CẢ HAI exe (tránh SmartScreen)

```powershell
powershell -File packaging\windows\sign.ps1 -Thumbprint "<cert-thumbprint>"
```
⚠️ Phải ký **cả helper 32-bit**. Chỉ ký daemon → helper chưa ký vẫn bị cảnh báo.
Dùng chứng thư **OV/EV Code Signing**; EV giảm mạnh cảnh báo SmartScreen. `.pfx`
+ mật khẩu **không commit** — nhập lúc chạy.

## Đóng gói Installer

- **Inno Setup:** `iscc packaging\windows\installer.iss` → `vn-esign-suite-setup.exe`.
  (Ký cả `setup.exe` bằng signtool ở bước CI.)
- **WiX (MSI):** dùng khi cần triển khai qua GPO/SCCM. Cấu trúc file giống
  `[Files]` trong `installer.iss`; đóng service bằng `ServiceInstall/ServiceControl`.

## Chạy nền — chọn một

- **Windows Service** (mặc định): `install-service.ps1` (sc.exe) hoặc NSSM.
  Chạy kể cả khi chưa đăng nhập; phù hợp máy dùng chung.
- **Task Scheduler at-logon**: `install-task-atlogon.ps1` — chạy trong **phiên
  của user** (least-privilege, thấy reader/USB của user rõ hơn).

Cả hai đều để daemon **chỉ nghe 127.0.0.1**.

## PC/SC

Cần dịch vụ **Smart Card** (`SCardSvr`) đang chạy (installer đã bật). Kiểm:
```powershell
sc query SCardSvr
```

## An toàn (nhắc lại)

- Cài vào `Program Files` (chỉ Admin ghi) — không thư mục ghi-được-bởi-mọi-user.
- Không tải gì từ mạng lúc cài; **kho neo tin cậy đã ký nằm sẵn** trong bộ cài.
- Không mở rộng ACL; giữ quyền mặc định của Program Files.

## Kho fallback

`certstore_fallback()` liệt kê CertStore "MY" qua `crypt32.dll` (ctypes) — đọc
được cert cả khi chưa dò ra DLL.

## Chẩn đoán thường gặp

- *"Middleware 32-bit, đang dùng cầu nối 32-bit"* — bình thường; đảm bảo
  `vn-esign-bridge32.exe` tồn tại + `VN_ESIGN_BRIDGE_HELPER` trỏ đúng.
- *Không thấy token* — bật `SCardSvr`; cắm lại token; kiểm middleware CA đã cài.
