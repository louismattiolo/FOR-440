<#
Windows 11 Threat Hunting Baseline (Clean CSV Version)
Outputs all major artifacts in structured CSV files with descriptive headers.
#>

# Check admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run PowerShell as Administrator!"
    exit 1
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$prefix = "$env:COMPUTERNAME`_baseline_$timestamp"
$OutputDir = ".\BaselineOutput"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Collecting system baseline data...`n"

# Helper function to add a header comment
function Write-Header {
    param($file, $headerText)
    Add-Content -Path $file -Value "# $headerText"
}

# --- SYSTEM INFO ---
$file = "$OutputDir\$prefix-systeminfo.csv"
Write-Header $file "Columns: CsName, WindowsVersion, OsBuildNumber, OsArchitecture, Manufacturer, Model"
Get-ComputerInfo | 
    Select-Object CsName, WindowsVersion, OsBuildNumber, OsArchitecture, CsManufacturer, CsModel |
    Export-Csv $file -NoTypeInformation

# --- PROCESSES ---
$file = "$OutputDir\$prefix-processes.csv"
Write-Header $file "Columns: Name, Id, Path, CPU, WS (WorkingSet), StartTime"
Get-Process | 
    Select-Object Name, Id, Path, CPU, WS, StartTime |
    Export-Csv $file -NoTypeInformation

# --- SERVICES ---
$file = "$OutputDir\$prefix-services.csv"
Write-Header $file "Columns: Name, DisplayName, State, StartMode, PathName"
Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName |
    Export-Csv $file -NoTypeInformation

# --- NETWORK CONNECTIONS ---
$file = "$OutputDir\$prefix-netconnections.csv"
Write-Header $file "Columns: Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess"
Get-NetTCPConnection |
    Select-Object Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Export-Csv $file -NoTypeInformation

# --- USERS ---
$file = "$OutputDir\$prefix-users.csv"
Write-Header $file "Columns: Name, Enabled, LastLogon, PasswordChangeable, PasswordExpires, PasswordRequired"
Get-LocalUser |
    Select-Object Name, Enabled, LastLogon, PasswordChangeable, PasswordExpires, PasswordRequired |
    Export-Csv $file -NoTypeInformation

# --- GROUPS ---
$file = "$OutputDir\$prefix-groups.csv"
Write-Header $file "Columns: Name, Description"
Get-LocalGroup | 
    Select-Object Name, Description |
    Export-Csv $file -NoTypeInformation

# --- GROUP MEMBERS ---
$file = "$OutputDir\$prefix-groupmemberships.csv"
Write-Header $file "Columns: Group, Members"
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    $members = (Get-LocalGroupMember -Group $group | Select-Object -ExpandProperty Name) -join "; "
    [PSCustomObject]@{ Group = $group; Members = $members }
} | Export-Csv $file -NoTypeInformation

# --- TASKS ---
$file = "$OutputDir\$prefix-tasks.csv"
Write-Header $file "Columns: TaskName, State, LastRunTime, NextRunTime, Author, TaskPath"
Get-ScheduledTask | ForEach-Object {
    $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TaskName    = $_.TaskName
        State       = $info.State
        LastRunTime = $info.LastRunTime
        NextRunTime = $info.NextRunTime
        Author      = $_.Author
        TaskPath    = $_.TaskPath
    }
} | Export-Csv $file -NoTypeInformation

# --- SOFTWARE ---
$file = "$OutputDir\$prefix-software.csv"
Write-Header $file "Columns: Name, Version, Vendor, InstallDate"
Get-CimInstance Win32_Product |
    Select-Object Name, Version, Vendor, InstallDate |
    Export-Csv $file -NoTypeInformation

# --- ADAPTERS ---
$file = "$OutputDir\$prefix-adapters.csv"
Write-Header $file "Columns: InterfaceAlias, InterfaceDescription, Status, MacAddress, LinkSpeed"
Get-NetAdapter |
    Select-Object InterfaceAlias, InterfaceDescription, Status, MacAddress, LinkSpeed |
    Export-Csv $file -NoTypeInformation

# --- LISTENING PORTS ---
$file = "$OutputDir\$prefix-listeningports.csv"
Write-Header $file "Columns: Protocol, LocalAddress, LocalPort, OwningProcess"
Get-NetTCPConnection -State Listen |
    Select-Object Protocol, LocalAddress, LocalPort, OwningProcess |
    Export-Csv $file -NoTypeInformation

# --- SUSPICIOUS FILES ---
$file = "$OutputDir\$prefix-suspiciousfiles.csv"
Write-Header $file "Columns: FilePath, LastWriteTime, FileSize, Owner, Permissions, DetectionReason"

Write-Host "Searching for suspicious files..."

# Define suspicious locations to search
$suspiciousLocations = @(
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\Temp",
    "$env:TEMP"
)

# Define suspicious filename patterns
$suspiciousPatterns = @(
    "*config*",
    "*credential*",
    "*password*",
    "*secret*",
    "*key*"
)

$results = @()

foreach ($location in $suspiciousLocations) {
    if (Test-Path -Path $location) {
        Write-Host "  Scanning $location..."
        
        Get-ChildItem -Path $location -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $currentFile = $_
            $isInSensitiveLocation = $true  # All locations in our list are considered sensitive
            $hasSuspiciousName = $false
            $hasSuspiciousPermissions = $false
            $reasons = @()
            $permissionDetails = ""
            
            # Check if filename matches suspicious patterns
            foreach ($pattern in $suspiciousPatterns) {
                if ($currentFile.Name -like $pattern) {
                    $hasSuspiciousName = $true
                    $reasons += "SuspiciousName"
                    break
                }
            }
            
            try {
                $acl = Get-Acl -Path $currentFile.FullName -ErrorAction Stop
                
                # Check for Everyone permissions
                $everyoneAccess = $acl.Access | Where-Object { 
                    $_.IdentityReference.ToString() -like "*Everyone*"
                }
                
                if ($everyoneAccess) {
                    $hasSuspiciousPermissions = $true
                    $reasons += "SuspiciousPermissions"
                    $permissionDetails = ($everyoneAccess | ForEach-Object { 
                        "$($_.IdentityReference): $($_.FileSystemRights)" 
                    }) -join "; "
                } else {
                    # Include all permissions for suspicious files even without Everyone access
                    $permissionDetails = ($acl.Access | Select-Object -First 3 | ForEach-Object { 
                        "$($_.IdentityReference): $($_.FileSystemRights)" 
                    }) -join "; "
                }
                
                # Flag file if it has suspicious name OR suspicious permissions
                if ($hasSuspiciousName -or $hasSuspiciousPermissions) {
                    $results += [PSCustomObject]@{
                        FilePath = $currentFile.FullName
                        LastWriteTime = $currentFile.LastWriteTime
                        FileSize = $currentFile.Length
                        Owner = $acl.Owner
                        Permissions = $permissionDetails
                        DetectionReason = ($reasons -join ", ")
                    }
                }
            } catch {
                # Skip files we can't access
                # Using Write-Verbose with proper string formatting
                Write-Verbose ("Error accessing {0}: {1}" -f $currentFile.FullName, $_.Exception.Message)
            }
        }
    }
}

if ($results.Count -gt 0) {
    $results | Export-Csv $file -NoTypeInformation
    Write-Host "  Found $($results.Count) suspicious files. Results saved to: $file"
} else {
    Write-Host "  No suspicious files found."
    "# No suspicious files found" | Out-File $file
}
Write-Host "`nBaseline collection complete! CSV files saved to: $OutputDir"
