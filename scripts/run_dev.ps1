<#
  Chạy daemon vn-esign ở chế độ DEV trên Windows (bind CHỈ 127.0.0.1).

  Cách dùng:
    powershell -ExecutionPolicy Bypass -File scripts\run_dev.ps1
    $env:VN_ESIGN_PORT=9000; scripts\run_dev.ps1

  ⭐ KHÔNG tải/chạy installer bên thứ ba. Chỉ khởi động daemon cục bộ.
#>
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$Port = if ($env:VN_ESIGN_PORT) { $env:VN_ESIGN_PORT } else { "8787" }
$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "-> vn-esign daemon (dev) - loopback 127.0.0.1:$Port"
Write-Host "   Swagger: http://127.0.0.1:$Port/docs"

& $Python -m uvicorn service.app:app --host 127.0.0.1 --port $Port --reload --log-level info
