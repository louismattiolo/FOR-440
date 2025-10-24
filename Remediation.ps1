# ================================================
# Manual Hunt and Remediation Script
# FOR440 – Baseline Artifact Investigation
# ================================================

Write-Host "=== Starting Remediation ==="

# --- Users and Groups ---
Remove-LocalUser -Name "svc_backup" -ErrorAction SilentlyContinue
Remove-LocalUser -Name "admin_temp" -ErrorAction SilentlyContinue
Remove-LocalUser -Name "webadmin" -ErrorAction SilentlyContinue
Remove-LocalGroup -Name "RemoteAdmins" -ErrorAction SilentlyContinue
Remove-LocalGroup -Name "BackupOperators_Custom" -ErrorAction SilentlyContinue

# --- Network Connections ---
foreach ($port in 4444,8888,31337) {
    $proc = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($proc -and $proc.OwningProcess -ne $PID) {
        Stop-Process -Id $proc.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

# --- Services ---
Stop-Service -Name "WindowsUpdateService_Custom" -Force -ErrorAction SilentlyContinue
sc.exe delete WindowsUpdateService_Custom

# --- Scheduled Tasks ---
Unregister-ScheduledTask -TaskName "SystemMaintenanceTask" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "DataBackupTask_Custom" -Confirm:$false -ErrorAction SilentlyContinue

# --- Processes / Scripts ---
# Only stop other PowerShell processes, not the current one
Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\Updater\suspicious_updater.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\Collector\data_collector.ps1" -Force -ErrorAction SilentlyContinue

# --- Files ---
Remove-Item "C:\Users\Public\system_config.txt" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\ProgramData\credentials.txt" -Force -ErrorAction SilentlyContinue

Write-Host "=== Remediation Complete ==="
