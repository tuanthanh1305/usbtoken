# install-service.ps1 — đăng ký daemon vn-esign làm Windows Service (chạy Admin).
#   powershell -ExecutionPolicy Bypass -File install-service.ps1 `
#       -ExePath "C:\Program Files\vn-esign-suite\vn-esign-service.exe"
# Gỡ:  sc.exe delete VNeSign

param(
    [Parameter(Mandatory = $true)] [string]$ExePath,
    [string]$ServiceName = "VNeSign",
    [string]$DisplayName = "vn-esign-suite service"
)

if (-not (Test-Path $ExePath)) { Write-Error "Không tìm thấy: $ExePath"; exit 1 }

Write-Host "Đăng ký dịch vụ $ServiceName ..."
sc.exe create $ServiceName binPath= "`"$ExePath`"" start= auto DisplayName= "$DisplayName"
sc.exe description $ServiceName "Daemon ky so & kiem tra chu ky so tren USB token (localhost)."
sc.exe start $ServiceName
Write-Host "Hoàn tất. Dịch vụ chỉ lắng nghe 127.0.0.1."
