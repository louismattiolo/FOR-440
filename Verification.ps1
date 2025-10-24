# ================================================
# Remediation Verification Script
# FOR440 – Baseline Artifact Investigation
# ================================================

Write-Host "=== Starting Verification ==="

$issuesFound = $false

# --- Verify Users and Groups ---
Write-Host "`n=== Verifying Users and Groups ==="
if (Get-LocalUser -Name "svc_backup" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: svc_backup user still exists" -ForegroundColor Red
    $issuesFound = $true
}
if (Get-LocalUser -Name "admin_temp" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: admin_temp user still exists" -ForegroundColor Red
    $issuesFound = $true
}
if (Get-LocalUser -Name "webadmin" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: webadmin user still exists" -ForegroundColor Red
    $issuesFound = $true
}
if (Get-LocalGroup -Name "RemoteAdmins" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: RemoteAdmins group still exists" -ForegroundColor Red
    $issuesFound = $true
}
if (Get-LocalGroup -Name "BackupOperators_Custom" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: BackupOperators_Custom group still exists" -ForegroundColor Red
    $issuesFound = $true
}

# --- Verify Network Connections ---
Write-Host "`n=== Verifying Network Connections ==="
foreach ($port in 4444,8888,31337) {
    $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($conn) {
        Write-Host "ISSUE: Port $port is still listening" -ForegroundColor Red
        $issuesFound = $true
    }
}

# --- Verify Services ---
Write-Host "`n=== Verifying Services ==="
if (Get-Service -Name "WindowsUpdateService_Custom" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: WindowsUpdateService_Custom service still exists" -ForegroundColor Red
    $issuesFound = $true
}

# --- Verify Scheduled Tasks ---
Write-Host "`n=== Verifying Scheduled Tasks ==="
if (Get-ScheduledTask -TaskName "SystemMaintenanceTask" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: SystemMaintenanceTask still exists" -ForegroundColor Red
    $issuesFound = $true
}
if (Get-ScheduledTask -TaskName "DataBackupTask_Custom" -ErrorAction SilentlyContinue) {
    Write-Host "ISSUE: DataBackupTask_Custom still exists" -ForegroundColor Red
    $issuesFound = $true
}

# --- Verify Files ---
Write-Host "`n=== Verifying Files ==="
$suspiciousFiles = @(
    "C:\ProgramData\Updater\suspicious_updater.ps1",
    "C:\ProgramData\Collector\data_collector.ps1", 
    "C:\Users\Public\system_config.txt",
    "C:\ProgramData\credentials.txt"
)

foreach ($file in $suspiciousFiles) {
    if (Test-Path $file) {
        Write-Host "ISSUE: $file still exists" -ForegroundColor Red
        $issuesFound = $true
    }
}

# --- Final Result ---
if (-not $issuesFound) {
    Write-Host "`n=== SUCCESS: All artifacts successfully removed ===" -ForegroundColor Green
} else {
    Write-Host "`n=== WARNING: Some artifacts still exist ===" -ForegroundColor Yellow
}
