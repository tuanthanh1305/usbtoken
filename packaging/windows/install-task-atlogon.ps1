<#
  install-task-atlogon.ps1 — Chạy daemon vn-esign khi NGƯỜI DÙNG ĐĂNG NHẬP
  (Task Scheduler, at-logon). Thay thế cho Windows Service khi muốn daemon chạy
  trong PHIÊN của user (nhìn thấy reader/USB của user rõ hơn, giống LaunchAgent
  trên macOS).

    powershell -ExecutionPolicy Bypass -File install-task-atlogon.ps1 `
        -ExePath "C:\Program Files\vn-esign-suite\vn-esign-service.exe"
  Gỡ:  schtasks /Delete /TN "vn-esign-service" /F
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string]$ExePath,
  [string]$TaskName = "vn-esign-service"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $ExePath)) { throw "Không tìm thấy: $ExePath" }

# Chạy at-logon trong ngữ cảnh user hiện tại (KHÔNG SYSTEM — daemon loopback,
# không cần đặc quyền cao; nguyên tắc least-privilege).
$action  = New-ScheduledTaskAction -Execute $ExePath
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Settings $settings -Principal $principal -Force | Out-Null
Write-Host "✅ Đã tạo tác vụ '$TaskName' (at-logon, quyền hạn chế). Daemon chỉ nghe 127.0.0.1."
