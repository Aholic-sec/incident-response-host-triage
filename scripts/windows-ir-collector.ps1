$ErrorActionPreference = "Continue"
$ScriptVersion = "2026.06.27"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
& $env:ComSpec /d /c "chcp 65001 >nul" 2>$null

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$HostSafe = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "UNKNOWNHOST" }
$OutDir = Join-Path (Get-Location) "IR-Logs-Windows-$HostSafe-$Timestamp"

$Dirs = @(
  "system", "accounts", "process", "network", "persistence",
  "events", "files", "security", "errors"
)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
foreach ($Dir in $Dirs) {
  New-Item -ItemType Directory -Force -Path (Join-Path $OutDir $Dir) | Out-Null
}

$CommandIndex = Join-Path $OutDir "command-index.tsv"
$Failures = Join-Path $OutDir "errors\command-failures.tsv"
"file`tcommand`texit_code" | Set-Content -Encoding UTF8 -LiteralPath $CommandIndex
"" | Set-Content -Encoding UTF8 -LiteralPath $Failures
"encoding=utf-8`r`ncodepage=65001`r`npowershell_output_encoding=$($OutputEncoding.WebName)" | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutDir "system\encoding.txt")

Write-Host "[*] Windows IR collector $ScriptVersion"
Write-Host "[*] Output: `"$OutDir`""
Write-Host "[*] Read-only collection. No cleanup, kill, quarantine, upload, or configuration change is performed."

function Add-Index {
  param(
    [string]$Rel,
    [string]$Command,
    [int]$ExitCode
  )
  "$Rel`t$Command`t$ExitCode" | Add-Content -Encoding UTF8 -LiteralPath $CommandIndex
  if ($ExitCode -ne 0) {
    "$Rel`t$Command`t$ExitCode" | Add-Content -Encoding UTF8 -LiteralPath $Failures
  }
}

function Invoke-NativeCollect {
  param(
    [string]$Rel,
    [string]$Command
  )
  $Dest = Join-Path $OutDir $Rel
  "[$((Get-Date).ToUniversalTime().ToString('o'))] $ $Command" | Set-Content -Encoding UTF8 -LiteralPath $Dest
  try {
    $Text = & $env:ComSpec /d /u /c $Command 2>&1 | Out-String -Width 4096
    $Text | Add-Content -Encoding UTF8 -LiteralPath $Dest
    $Rc = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
  } catch {
    $_ | Out-String | Add-Content -Encoding UTF8 -LiteralPath $Dest
    $Rc = 1
  }
  Add-Index -Rel $Rel -Command $Command -ExitCode $Rc
}

function Invoke-ScriptCollect {
  param(
    [string]$Rel,
    [string]$Name,
    [scriptblock]$Script
  )
  $Dest = Join-Path $OutDir $Rel
  "[$((Get-Date).ToUniversalTime().ToString('o'))] PS> $Name" | Set-Content -Encoding UTF8 -LiteralPath $Dest
  try {
    $Text = & $Script 2>&1 | Out-String -Width 4096
    $Text | Add-Content -Encoding UTF8 -LiteralPath $Dest
    $Rc = if ($?) { 0 } else { 1 }
  } catch {
    $_ | Out-String | Add-Content -Encoding UTF8 -LiteralPath $Dest
    $Rc = 1
  }
  Add-Index -Rel $Rel -Command "powershell:$Name" -ExitCode $Rc
}

Invoke-NativeCollect "system\systeminfo.txt" "systeminfo"
Invoke-NativeCollect "system\hostname.txt" "hostname"
Invoke-NativeCollect "system\ver.txt" "ver"
Invoke-NativeCollect "system\whoami_all.txt" "whoami /all"
Invoke-NativeCollect "system\environment.txt" "set"
Invoke-NativeCollect "system\hotfixes.txt" "wmic qfe list full /format:list"
Invoke-NativeCollect "system\logical_disks.txt" "wmic logicaldisk get Caption,Description,FileSystem,FreeSpace,Size,VolumeName /format:list"
Invoke-NativeCollect "system\shares.txt" "net share"
Invoke-NativeCollect "system\sessions.txt" "net session"

Invoke-NativeCollect "accounts\users.txt" "net user"
Invoke-NativeCollect "accounts\local_groups.txt" "net localgroup"
Invoke-NativeCollect "accounts\administrators.txt" "net localgroup administrators"
Invoke-NativeCollect "accounts\remote_desktop_users.txt" 'net localgroup "Remote Desktop Users"'
Invoke-NativeCollect "accounts\password_policy.txt" "net accounts"
Invoke-NativeCollect "accounts\logon_sessions.txt" "qwinsta"

Invoke-NativeCollect "process\tasklist_verbose.csv" "tasklist /v /fo csv"
Invoke-NativeCollect "process\tasklist_modules.txt" "tasklist /m"
Invoke-NativeCollect "process\wmic_process.txt" "wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate /format:list"
Invoke-ScriptCollect "process\process_cim.txt" "Win32_Process command lines" {
  Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
    Format-List *
}
Invoke-ScriptCollect "process\process_signatures.txt" "process image signatures" {
  Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $Sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      Id = $_.Id
      Name = $_.ProcessName
      Path = $_.Path
      Signer = if ($Sig.SignerCertificate) { $Sig.SignerCertificate.Subject } else { "" }
      Status = $Sig.Status
    }
  } | Format-Table -AutoSize
}
Invoke-ScriptCollect "process\high_resource_processes.txt" "high resource processes" {
  Get-Process | Sort-Object CPU -Descending |
    Select-Object -First 60 Id, ProcessName, CPU, WorkingSet, Path |
    Format-Table -AutoSize
}

Invoke-NativeCollect "network\ipconfig_all.txt" "ipconfig /all"
Invoke-NativeCollect "network\netstat_ano.txt" "netstat -ano"
Invoke-NativeCollect "network\netstat_anob.txt" "netstat -anob"
Invoke-NativeCollect "network\route_print.txt" "route print"
Invoke-NativeCollect "network\arp.txt" "arp -a"
Invoke-NativeCollect "network\dns_cache.txt" "ipconfig /displaydns"
Invoke-NativeCollect "network\firewall_profiles.txt" "netsh advfirewall show allprofiles"
Invoke-NativeCollect "network\winhttp_proxy.txt" "netsh winhttp show proxy"

Invoke-NativeCollect "persistence\services.txt" "sc queryex type= service state= all"
Invoke-NativeCollect "persistence\drivers.txt" "sc query type= driver state= all"
Invoke-NativeCollect "persistence\scheduled_tasks.txt" "schtasks /query /fo LIST /v"
Invoke-NativeCollect "persistence\startup_wmic.txt" "wmic startup get Caption,Command,Location,User /format:list"
Invoke-NativeCollect "persistence\run_hklm.txt" 'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s'
Invoke-NativeCollect "persistence\run_hkcu.txt" 'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s'
Invoke-NativeCollect "persistence\runonce_hklm.txt" 'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s'
Invoke-NativeCollect "persistence\runonce_hkcu.txt" 'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s'
Invoke-NativeCollect "persistence\winlogon.txt" 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s'
Invoke-NativeCollect "persistence\ifeo.txt" 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s'
Invoke-NativeCollect "persistence\appinit_dlls.txt" 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs'
Invoke-NativeCollect "persistence\lsa.txt" 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /s'
Invoke-NativeCollect "persistence\wmic_event_filters.txt" "wmic /namespace:\\root\subscription PATH __EventFilter get /format:list"
Invoke-NativeCollect "persistence\wmic_event_consumers.txt" "wmic /namespace:\\root\subscription PATH CommandLineEventConsumer get /format:list"
Invoke-ScriptCollect "persistence\startup_folders.txt" "startup folders" {
  $Paths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  )
  Get-ChildItem $Paths -Force -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, CreationTime, LastWriteTime |
    Format-List *
}

Invoke-ScriptCollect "events\security_logon_recent.txt" "recent logon events" {
  Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624,4625,4634,4648,4672; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 800 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Format-List *
}
Invoke-ScriptCollect "events\account_changes_recent.txt" "recent account changes" {
  Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4720,4722,4723,4724,4725,4726,4732,4733,4756; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 800 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Format-List *
}
Invoke-ScriptCollect "events\service_task_powershell_recent.txt" "recent service events" {
  Get-WinEvent -FilterHashtable @{LogName="System"; Id=7036,7040,7045; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 800 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Format-List *
}
Invoke-ScriptCollect "events\powershell_operational_recent.txt" "PowerShell operational events" {
  Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 800 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Format-List *
}
Invoke-ScriptCollect "events\rdp_recent.txt" "RDP local session manager events" {
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 500 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Format-List *
}
Invoke-ScriptCollect "events\defender_recent.txt" "Defender operational events" {
  Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 500 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message |
    Format-List *
}

Invoke-ScriptCollect "files\recent_executables_user_temp.txt" "recent risky files" {
  $Roots = @(
    $env:TEMP,
    $env:TMP,
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:LOCALAPPDATA\Temp",
    "C:\ProgramData",
    "C:\Users\Public"
  ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
  $Ext = "\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jar|lnk|zip|rar|7z)$"
  foreach ($Root in $Roots) {
    "### ROOT: $Root"
    Get-ChildItem $Root -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer -and $_.Name -match $Ext -and $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 250 FullName, Length, CreationTime, LastWriteTime |
      Format-List *
  }
}
Invoke-ScriptCollect "files\suspicious_names.txt" "suspicious filenames" {
  $Roots = @(
    $env:TEMP,
    $env:TMP,
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu",
    "$env:APPDATA\Microsoft\Windows\Templates",
    "$env:LOCALAPPDATA\Temp",
    "C:\ProgramData",
    "C:\Users\Public"
  ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
  $Pattern = "xmrig|xmr|miner|mimikatz|procdump|lazagne|frpc|frps|nps|npc|ngrok|chisel|ew_for|earthworm|mshta|rundll32|svhost|svch0st|chromeupdate|officeupdate|wechat|dingtalk|invoice|resume|salary|lockbit|blackcat|wannacry|readme"
  foreach ($Root in $Roots) {
    "### ROOT: $Root"
    Get-ChildItem $Root -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer -and $_.FullName -match $Pattern } |
      Select-Object -First 250 FullName, Length, CreationTime, LastWriteTime |
      Format-List *
  }
}

Invoke-ScriptCollect "security\defender_status.txt" "Defender status" {
  Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List *
}
Invoke-ScriptCollect "security\defender_preferences.txt" "Defender preferences" {
  Get-MpPreference -ErrorAction SilentlyContinue | Format-List *
}
Invoke-ScriptCollect "security\defender_threats.txt" "Defender threat detections" {
  Get-MpThreatDetection -ErrorAction SilentlyContinue | Format-List *
}
Invoke-ScriptCollect "security\common_security_services.txt" "common security services" {
  Get-Service |
    Where-Object { $_.Name -match "defend|sense|crowd|carbon|sophos|kaspersky|avast|avp|mcafee|trend|sentinel|edr|xdr|secure|fireeye|eset" } |
    Select-Object Name, DisplayName, Status, StartType |
    Format-Table -AutoSize
}

function Get-Sha256Hex {
  param([string]$Path)
  $Stream = [IO.File]::OpenRead($Path)
  try {
    $Sha = [Security.Cryptography.SHA256]::Create()
    ([BitConverter]::ToString($Sha.ComputeHash($Stream))).Replace("-", "")
  } finally {
    $Stream.Dispose()
    if ($Sha) { $Sha.Dispose() }
  }
}

$Files = Get-ChildItem -Path $OutDir -File -Recurse |
  Where-Object { $_.Name -ne "manifest.json" } |
  ForEach-Object {
    [ordered]@{
      path = $_.FullName.Substring($OutDir.Length + 1).Replace("\", "/")
      size = $_.Length
      sha256 = Get-Sha256Hex $_.FullName
    }
  }

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$FailureLines = @()
if (Test-Path $Failures) {
  $FailureLines = Get-Content -LiteralPath $Failures | Where-Object { $_.Trim() }
}

$Manifest = [ordered]@{
  schema = "ir-log-manifest/v1"
  script_name = "windows-ir-collector.bat"
  script_version = $ScriptVersion
  os_type = "windows"
  hostname = $env:COMPUTERNAME
  collected_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  output_directory = $OutDir
  privilege = if ($IsAdmin) { "administrator" } else { "standard-user" }
  collector_user = "$env:USERDOMAIN\$env:USERNAME"
  read_only = $true
  network_upload_performed = $false
  encoding = "utf-8"
  codepage = 65001
  command_failures = $FailureLines
  files = @($Files)
}

$Manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutDir "manifest.json")
Write-Host "[*] Done. Review `"$OutDir\manifest.json`""
