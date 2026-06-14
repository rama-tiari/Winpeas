<#
.SYNOPSIS
  System Diagnostic Tool
.DESCRIPTION
  System enumeration for authorized security testing
.EXAMPLE
  .\diag.ps1
  .\diag.ps1 -FullCheck
  .\diag.ps1 -TimeStamp
.NOTES
  Version: 1.0
#>

[CmdletBinding()]
param(
  [switch]$TimeStamp,
  [switch]$FullCheck,
  [switch]$Excel
)

$stopwatch = [system.diagnostics.stopwatch]::StartNew()

function Get-Timestamp {
  if ($TimeStamp) {
    Write-Host "[$($stopwatch.Elapsed.Minutes):$($stopwatch.Elapsed.Seconds)]"
  }
}

function Test-PathPermissions {
  param($Target, $ServiceName)
  if ($null -ne $Target) {
    try {
      $acl = Get-Acl $Target -ErrorAction SilentlyContinue
    }
    catch { $null }
    if ($acl) {
      $identities = @()
      $identities += "$env:COMPUTERNAME\$env:USERNAME"
      $groups = whoami.exe /groups /fo csv 2>$null | Select-Object -Skip 2 | ConvertFrom-Csv -Header 'name' 2>$null
      if ($groups) {
        $identities += $groups.name
      }
      foreach ($id in $identities) {
        $perms = $acl.Access | Where-Object { $_.IdentityReference -like $id }
        foreach ($p in $perms) {
          if ($p.FileSystemRights -match "FullControl|Write|Modify") {
            if ($ServiceName) { Write-Host "[!] $ServiceName" -ForegroundColor Red }
            Write-Host "[!] $($p.IdentityReference) has $($p.FileSystemRights) on $Target" -ForegroundColor Red
          }
        }
      }
    }
  }
}

Write-Host ""
Get-Timestamp
Write-Host "====================================|| SYSTEM INFO ||===================================="

Write-Host ""
Get-Timestamp
Write-Host "[*] Basic System Information" -ForegroundColor Cyan
systeminfo.exe 2>$null

Write-Host ""
Get-Timestamp
Write-Host "[*] Hotfixes" -ForegroundColor Cyan
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 | Format-Table HotFixID, InstalledOn -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] Drive Information" -ForegroundColor Cyan
Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | ForEach-Object {
  Write-Host "$($_.Name): $([math]::Round($_.Used/1GB,2))GB used / $([math]::Round($_.Free/1GB,2))GB free"
}

Write-Host ""
Get-Timestamp
Write-Host "[*] Current User" -ForegroundColor Cyan
whoami.exe /all 2>$null

Write-Host ""
Get-Timestamp
Write-Host "[*] Local Users" -ForegroundColor Cyan
Get-LocalUser | Where-Object { $_.Enabled -eq $true } | Select-Object Name | Format-Table -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] Local Groups" -ForegroundColor Cyan
Get-LocalGroup | Select-Object -First 30 Name | Format-Table -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] Administrators Group" -ForegroundColor Cyan
Get-LocalGroupMember -Name "Administrators" -ErrorAction SilentlyContinue | Select-Object Name

Write-Host ""
Get-Timestamp
Write-Host "[*] Running Processes" -ForegroundColor Cyan
Get-Process | Select-Object -First 30 Name, CPU, WorkingSet | Format-Table -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] Services (Auto Start)" -ForegroundColor Cyan
Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -eq "Running" } | Select-Object -First 20 Name, DisplayName | Format-Table -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] Network Configuration" -ForegroundColor Cyan
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.IPAddress -notlike "169.*" } | Select-Object InterfaceAlias, IPAddress

Write-Host ""
Get-Timestamp
Write-Host "[*] Listening Ports" -ForegroundColor Cyan
Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort

Write-Host ""
Get-Timestamp
Write-Host "[*] Installed Applications" -ForegroundColor Cyan
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Select-Object -First 30 | Format-Table -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] Environment PATH" -ForegroundColor Cyan
($env:Path -split ';') | Select-Object -First 20

Write-Host ""
Get-Timestamp
Write-Host "[*] Scheduled Tasks (non-Microsoft)" -ForegroundColor Cyan
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*Microsoft*" -and $_.State -ne "Disabled" } | Select-Object -First 15 TaskName, State | Format-Table -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] Startup Items" -ForegroundColor Cyan
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command | Format-Table -AutoSize

Write-Host ""
Get-Timestamp
Write-Host "[*] AlwaysInstallElevated Check" -ForegroundColor Cyan
$hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
$hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
if ($hkcu.AlwaysInstallElevated -eq 1 -or $hklm.AlwaysInstallElevated -eq 1) {
  Write-Host "[!] WARNING: AlwaysInstallElevated is enabled!" -ForegroundColor Red
} else {
  Write-Host "[-] AlwaysInstallElevated is disabled" -ForegroundColor Green
}

Write-Host ""
Get-Timestamp
Write-Host "[*] LSA Protection Status" -ForegroundColor Cyan
$runAsPPL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -ErrorAction SilentlyContinue).RunAsPPL
if ($runAsPPL -eq 0 -or $null -eq $runAsPPL) {
  Write-Host "[!] LSA Protection is DISABLED" -ForegroundColor Red
} else {
  Write-Host "[-] LSA Protection is enabled" -ForegroundColor Green
}

Write-Host ""
Get-Timestamp
Write-Host "[*] UAC Status" -ForegroundColor Cyan
$uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
if ($uac -eq 1) {
  Write-Host "[-] UAC is enabled" -ForegroundColor Green
} else {
  Write-Host "[!] UAC is DISABLED" -ForegroundColor Red
}

Write-Host ""
Get-Timestamp
Write-Host "[*] PowerShell Version" -ForegroundColor Cyan
Write-Host $PSVersionTable.PSVersion

Write-Host ""
Get-Timestamp
Write-Host "[*] Windows Defender Status" -ForegroundColor Cyan
Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled, RealTimeProtectionEnabled

Write-Host ""
Get-Timestamp
Write-Host "[*] Network Shares" -ForegroundColor Cyan
Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path

Write-Host ""
Get-Timestamp
Write-Host "[*] Firewall Status" -ForegroundColor Cyan
Get-NetFirewallProfile | Select-Object Name, Enabled

Write-Host ""
Get-Timestamp
Write-Host "[*] Cached Credentials" -ForegroundColor Cyan
cmdkey.exe /list 2>$null

Write-Host ""
Get-Timestamp
Write-Host "[*] WDigest Status" -ForegroundColor Cyan
$wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential
if ($wdigest -eq 1) {
  Write-Host "[!] WARNING: WDigest is enabled (plaintext passwords in memory)" -ForegroundColor Red
} else {
  Write-Host "[-] WDigest is disabled" -ForegroundColor Green
}

Write-Host ""
Get-Timestamp
Write-Host "[*] Unquoted Service Paths" -ForegroundColor Cyan
$services = Get-CimInstance Win32_Service | Where-Object { 
  $_.PathName -notlike '"*"' -and $_.PathName -like "* *.exe*" -and $_.StartMode -ne "Disabled"
}
if ($services) {
  $services | ForEach-Object { Write-Host "[!] $($_.Name): $($_.PathName)" -ForegroundColor Red }
} else {
  Write-Host "[-] No unquoted service paths found"
}

Write-Host ""
Get-Timestamp
Write-Host "[*] Weak Service Permissions Check" -ForegroundColor Cyan
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -like "*.exe*" } | ForEach-Object {
  $path = ($_.PathName -split '\.exe')[0] + '.exe'
  if (Test-Path $path) {
    try {
      $acl = Get-Acl $path -ErrorAction SilentlyContinue
      if ($acl.Access | Where-Object { $_.IdentityReference -like "*$env:USERNAME*" -and $_.FileSystemRights -match "Write|Modify" }) {
        Write-Host "[!] $($_.Name) - $path" -ForegroundColor Red
      }
    } catch {}
  }
}

Write-Host ""
Get-Timestamp
Write-Host "[*] User Directory Access" -ForegroundColor Cyan
Get-ChildItem "C:\Users" -ErrorAction SilentlyContinue | ForEach-Object {
  $test = Get-ChildItem $_.FullName -ErrorAction SilentlyContinue
  if ($test) { Write-Host "[!] Read access to: $($_.FullName)" -ForegroundColor Red }
}

Write-Host ""
Get-Timestamp
Write-Host "[*] Unattend Files" -ForegroundColor Cyan
$files = @(
  "$env:windir\Panther\Unattend.xml",
  "$env:windir\Panther\Unattended.xml",
  "$env:windir\System32\Sysprep\unattend.xml"
)
foreach ($f in $files) {
  if (Test-Path $f) { Write-Host "[!] Found: $f" -ForegroundColor Yellow }
}

Write-Host ""
Get-Timestamp
Write-Host "[*] SAM Backup Check" -ForegroundColor Cyan
$samPaths = @(
  "$env:windir\repair\SAM",
  "$env:windir\System32\config\RegBack\SAM"
)
foreach ($p in $samPaths) {
  if (Test-Path $p) { Write-Host "[!] Found: $p" -ForegroundColor Yellow }
}

Write-Host ""
Get-Timestamp
Write-Host "[*] DNS Cache" -ForegroundColor Cyan
ipconfig /displaydns 2>$null | Select-String "Record Name" | Select-Object -First 10

Write-Host ""
Get-Timestamp
Write-Host "[*] ARP Table" -ForegroundColor Cyan
arp -a 2>$null | Select-Object -First 20

Write-Host ""
Get-Timestamp
Write-Host "[*] WiFi Profiles" -ForegroundColor Cyan
netsh wlan show profiles 2>$null | Select-String ":" | ForEach-Object { $_.ToString().Split(':')[1].Trim() }

Write-Host ""
Get-Timestamp
Write-Host "[*] Hosts File" -ForegroundColor Cyan
Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Select-String -NotMatch "^#|^$"

Write-Host ""
Get-Timestamp
Write-Host "[*] Running Time: $($stopwatch.Elapsed.Minutes):$($stopwatch.Elapsed.Seconds)"
Write-Host "[*] Scan Complete" -ForegroundColor Green