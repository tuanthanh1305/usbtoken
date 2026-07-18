<#
  sign.ps1 — Ký Authenticode CẢ HAI exe (daemon x64 + helper x86) để tránh
  SmartScreen chặn. Dùng signtool (Windows SDK).

  ⭐ Ký CẢ helper 32-bit: nếu chỉ ký daemon, helper chưa ký vẫn bị cảnh báo/chặn.

  Chứng thư ký: dùng chứng thư EV/OV Code Signing của tổ chức (trong kho chứng
  thư máy hoặc file .pfx). KHÔNG commit .pfx/mật khẩu — truyền lúc chạy.

  Ví dụ (dùng chứng thư trong Windows cert store theo thumbprint):
    powershell -File packaging\windows\sign.ps1 -Thumbprint "AB12...CD"

  Ví dụ (dùng .pfx — mật khẩu nhập tương tác, KHÔNG ghi ra đâu):
    powershell -File packaging\windows\sign.ps1 -PfxPath "C:\secure\cs.pfx"
#>
[CmdletBinding()]
param(
  [string]$Thumbprint,
  [string]$PfxPath,
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [string[]]$Targets = @("dist\vn-esign-service.exe", "dist\bridge32\vn-esign-bridge32.exe")
)
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $RepoRoot

$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)?.Source
if (-not $signtool) { throw "Không tìm thấy signtool.exe — cài Windows SDK." }

if (-not $Thumbprint -and -not $PfxPath) {
  throw "Cần -Thumbprint (cert store) HOẶC -PfxPath (.pfx)."
}

foreach ($t in $Targets) {
  if (-not (Test-Path $t)) { throw "Chưa build: $t (chạy build.ps1 trước)." }
  Write-Host "== Ký $t =="
  if ($Thumbprint) {
    & $signtool sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $t
  } else {
    if (-not (Test-Path $PfxPath)) { throw "Không thấy .pfx: $PfxPath" }
    $pw = Read-Host "Mật khẩu .pfx" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
    & $signtool sign /f $PfxPath /p $plain /fd SHA256 /tr $TimestampUrl /td SHA256 $t
    $plain = $null   # xoá tham chiếu mật khẩu khỏi bộ nhớ script sớm nhất
  }
  if ($LASTEXITCODE -ne 0) { throw "Ký thất bại: $t" }
  & $signtool verify /pa /v $t
}
Write-Host "✅ Đã ký + verify Authenticode cả hai exe."
