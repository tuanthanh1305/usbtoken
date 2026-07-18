<#
  build.ps1 — Build daemon x64 + helper x86 bằng PyInstaller (Windows).

  ⭐ Cần HAI môi trường Python: x64 (daemon) và x86 (helper 32-bit).
     Cài Python x64 và x86 từ python.org; truyền đường dẫn qua tham số.

  Ví dụ:
    powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 `
        -Python64 "C:\Python312\python.exe" -Python32 "C:\Python312-32\python.exe"

  KHÔNG tải gì từ mạng ở đây. Chạy từ THƯ MỤC GỐC repo.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string]$Python64,
  [Parameter(Mandatory = $true)] [string]$Python32,
  [switch]$RequireSignedStore
)
$ErrorActionPreference = "Stop"   # dừng ngay khi có lỗi

$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $RepoRoot

foreach ($py in @($Python64, $Python32)) {
  if (-not (Test-Path $py)) { throw "Không tìm thấy Python: $py" }
}

Write-Host "== Kiểm kho neo tin cậy (đóng gói sẵn, đã ký) =="
$storeArgs = @("-m", "packaging.common.bundle_trust_store", "--check")
if ($RequireSignedStore) { $storeArgs += "--require-signed" }
& $Python64 @storeArgs
if ($LASTEXITCODE -ne 0) { throw "Kho neo tin cậy chưa sẵn sàng — từ chối build." }

Write-Host "== Cài phụ thuộc (x64) =="
& $Python64 -m pip install -r requirements.txt pyinstaller==6.11.1
Write-Host "== Build DAEMON x64 =="
& $Python64 -m PyInstaller --noconfirm --clean packaging\windows\vn-esign-service.spec
if ($LASTEXITCODE -ne 0) { throw "Build daemon x64 thất bại." }

Write-Host "== Cài phụ thuộc (x86) =="
& $Python32 -m pip install PyKCS11==1.5.17 pyinstaller==6.11.1
Write-Host "== Build BRIDGE HELPER x86 =="
& $Python32 -m PyInstaller --noconfirm --clean --distpath dist\bridge32 `
    packaging\windows\vn-esign-bridge32.spec
if ($LASTEXITCODE -ne 0) { throw "Build helper x86 thất bại." }

Write-Host "✅ Xong. dist\vn-esign-service.exe (x64) + dist\bridge32\vn-esign-bridge32.exe (x86)."
Write-Host "   Bước tiếp: sign.ps1 (Authenticode) rồi installer.iss (Inno Setup)."
