; installer.iss — Inno Setup script cho vn-esign-suite (Windows).
; Đóng gói: daemon x64 + helper x86 (ĐÃ KÝ) + kho neo tin cậy ĐÃ KÝ (data\).
; Build: iscc packaging\windows\installer.iss  (chạy từ gốc repo)
;
; ⭐ AN TOÀN: cài vào Program Files (chỉ Admin ghi được), KHÔNG chmod 777, KHÔNG
;   tải gì từ mạng lúc cài. Kho tin cậy đã ký nằm sẵn trong bộ cài.
; ⭐ Đăng ký service chỉ nghe 127.0.0.1 (xem install-service.ps1). SignTool ký cả
;   file setup.exe qua SignedUninstaller/SignTool (cấu hình ở CI, không ở đây).

#define AppName "vn-esign-suite"
#define AppVersion "0.1.0"
#define AppPublisher "vn-esign-suite"
#define SvcExe "vn-esign-service.exe"

[Setup]
AppId={{7E5B4C10-9A21-4A21-9F00-A1B2C3D4E5F6}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Cần quyền Admin để ghi Program Files + đăng ký service (loopback).
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=vn-esign-suite-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
; Daemon x64 (đã ký Authenticode).
Source: "..\..\dist\vn-esign-service.exe"; DestDir: "{app}"; Flags: ignoreversion
; Helper bridge x86 (đã ký) — nạp middleware 32-bit.
Source: "..\..\dist\bridge32\vn-esign-bridge32.exe"; DestDir: "{app}\bridge32"; Flags: ignoreversion
; Script đăng ký service + kho tin cậy đã ký (đóng gói sẵn).
Source: "install-service.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\vn-esign-suite (daemon)"; Filename: "{app}\{#SvcExe}"

[Run]
; Chỉ báo helper 32-bit cho daemon (biến môi trường máy).
Filename: "{cmd}"; Parameters: "/c setx /M VN_ESIGN_BRIDGE_HELPER ""{app}\bridge32\vn-esign-bridge32.exe"""; Flags: runhidden
; Đăng ký Windows Service (chỉ nghe 127.0.0.1). Tuỳ chọn (checkbox).
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -File ""{app}\install-service.ps1"" -ExePath ""{app}\{#SvcExe}"""; \
  Flags: runhidden; StatusMsg: "Đăng ký dịch vụ (loopback)..."; Tasks: installservice
; Nhắc bật dịch vụ Smart Card (SCardSvr) — cần cho PC/SC.
Filename: "{cmd}"; Parameters: "/c sc config SCardSvr start= auto & sc start SCardSvr"; Flags: runhidden

[Tasks]
Name: "installservice"; Description: "Chạy nền như Windows Service (chỉ 127.0.0.1)"; GodMode: False

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c sc.exe stop VNeSign & sc.exe delete VNeSign"; Flags: runhidden; RunOnceId: "DelVNeSignSvc"

[Messages]
WelcomeLabel2=Cài đặt {#AppName} — phần mềm ký số & kiểm tra chữ ký số trên USB token.%n%nDaemon chỉ lắng nghe 127.0.0.1. Kho neo tin cậy (NEAC) đã được ký và đóng gói sẵn.
