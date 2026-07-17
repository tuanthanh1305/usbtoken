# Đóng gói cho Windows

## Bitness
Rủi ro: Python host 64-bit nhưng DLL middleware 32-bit (ở SysWOW64) — hoặc
ngược lại. `needs_arch_bridge()` = True → bridge helper cùng bitness (đặt
`VN_ESIGN_BRIDGE_PYTHON` = python 32-bit, hoặc `VN_ESIGN_BRIDGE_HELPER` = exe
helper 32-bit).

## Build native (PyInstaller)
```powershell
pip install -r requirements-dev.txt
pyinstaller --onefile --name vn-esign-service `
    --collect-all PyKCS11 --collect-all smartcard `
    --add-data "data;data" -p . service/main.py
```
Build riêng cho x64 và (nếu cần) arm64.

## Chạy nền
`install-service.ps1` (sc.exe) hoặc NSSM.

## PC/SC
WinSCard có sẵn; cần dịch vụ **Smart Card** (`SCardSvr`) đang chạy.

## Kho fallback
`certstore_fallback()` liệt kê CertStore "MY" qua `crypt32.dll` (ctypes).
