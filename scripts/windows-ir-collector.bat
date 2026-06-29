@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_VERSION=2026.06.29"
set "SCRIPT_DIR=%~dp0"
set "NO_PAUSE=0"
if /I "%~1"=="--no-pause" set "NO_PAUSE=1"

pushd "%SCRIPT_DIR%" >nul 2>&1

set "MODE=legacy-bat"
set "RC=0"
set "PS_MAJOR=0"

if exist "%SCRIPT_DIR%windows-ir-collector.ps1" (
    for /f "usebackq delims=" %%V in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$PSVersionTable.PSVersion.Major" 2^>nul`) do set "PS_MAJOR=%%V"
    if defined PS_MAJOR (
        if !PS_MAJOR! GEQ 3 set "MODE=modern-powershell"
    )
)

if /I "%MODE%"=="modern-powershell" (
    echo [*] Modern Windows detected. Using PowerShell collector.
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%windows-ir-collector.ps1"
    set "RC=%ERRORLEVEL%"
    goto :finish
)

echo [*] Legacy Windows or unsupported PowerShell detected. Using built-in BAT collector.
call :legacy_collect
set "RC=%ERRORLEVEL%"
goto :finish

:finish
popd >nul 2>&1
if not "%NO_PAUSE%"=="1" (
    echo.
    echo ============================================================
    if "%RC%"=="0" (
        echo [IR COLLECTOR] Collection finished.
        echo Mode: %MODE%
        echo Check the newest IR-Logs-Windows-* folder next to this script.
    ) else (
        echo [IR COLLECTOR] Collection ended with errors.
        echo Mode: %MODE%
        echo Check command-index.tsv and errors\command-failures.tsv in the output folder.
    )
    echo Exit code: %RC%
    echo Press any key to close this window.
    echo ============================================================
    pause >nul
)
exit /b %RC%

:legacy_collect
set "LDT="
for /f "tokens=2 delims==" %%I in ('wmic os get LocalDateTime /value 2^>nul ^| find "="') do set "LDT=%%I"
if defined LDT (
    set "TS=%LDT:~0,8%-%LDT:~8,6%"
    set "COLLECTED_UTC=%LDT:~0,4%-%LDT:~4,2%-%LDT:~6,2%T%LDT:~8,2%:%LDT:~10,2%:%LDT:~12,2%Z"
) else (
    set "TS=%DATE%-%TIME%"
    set "TS=%TS:/=%"
    set "TS=%TS::=%"
    set "TS=%TS:.=%"
    set "TS=%TS: =0%"
    set "COLLECTED_UTC=unknown"
)

set "HOST_SAFE=%COMPUTERNAME%"
if "%HOST_SAFE%"=="" set "HOST_SAFE=UNKNOWNHOST"
set "OUTDIR=%CD%\IR-Logs-Windows-%HOST_SAFE%-%TS%-legacy"

mkdir "%OUTDIR%" "%OUTDIR%\system" "%OUTDIR%\accounts" "%OUTDIR%\process" "%OUTDIR%\network" "%OUTDIR%\persistence" "%OUTDIR%\events" "%OUTDIR%\files" "%OUTDIR%\security" "%OUTDIR%\errors" 2>nul
> "%OUTDIR%\command-index.tsv" echo file	command	exit_code	status
> "%OUTDIR%\errors\command-failures.tsv" echo.

echo [*] Windows BAT compatibility collector %SCRIPT_VERSION%
echo [*] Output: "%OUTDIR%"
echo [*] Read-only collection. No cleanup, kill, quarantine, upload, or configuration change is performed.
chcp > "%OUTDIR%\system\original_codepage.txt" 2>&1
chcp 65001 >nul 2>&1
chcp > "%OUTDIR%\system\active_codepage.txt" 2>&1
> "%OUTDIR%\system\encoding.txt" echo encoding=utf-8-best-effort
>> "%OUTDIR%\system\encoding.txt" echo codepage=65001
>> "%OUTDIR%\system\encoding.txt" echo note=Legacy BAT mode attempts to switch to UTF-8 with chcp 65001. If old Windows still produces garbled localized command output, decode affected logs using the original OEM code page recorded in system\original_codepage.txt.

set "CMD_FILE=%OUTDIR%\legacy-command-list.tsv"
> "%CMD_FILE%" echo system\systeminfo.txt^|systeminfo
>> "%CMD_FILE%" echo system\hostname.txt^|hostname
>> "%CMD_FILE%" echo system\ver.txt^|ver
>> "%CMD_FILE%" echo system\whoami.txt^|whoami
>> "%CMD_FILE%" echo system\whoami_all.txt^|whoami /all
>> "%CMD_FILE%" echo system\environment.txt^|set
>> "%CMD_FILE%" echo system\hotfixes.txt^|wmic qfe list full /format:list
>> "%CMD_FILE%" echo system\logical_disks.txt^|wmic logicaldisk get Caption,Description,FileSystem,FreeSpace,Size,VolumeName /format:list
>> "%CMD_FILE%" echo system\shares.txt^|net share
>> "%CMD_FILE%" echo system\sessions.txt^|net session
>> "%CMD_FILE%" echo accounts\users.txt^|net user
>> "%CMD_FILE%" echo accounts\local_groups.txt^|net localgroup
>> "%CMD_FILE%" echo accounts\administrators.txt^|net localgroup administrators
>> "%CMD_FILE%" echo accounts\remote_desktop_users.txt^|net localgroup "Remote Desktop Users"
>> "%CMD_FILE%" echo accounts\password_policy.txt^|net accounts
>> "%CMD_FILE%" echo process\tasklist_verbose.csv^|tasklist /v /fo csv
>> "%CMD_FILE%" echo process\tasklist_services.txt^|tasklist /svc
>> "%CMD_FILE%" echo process\tasklist_modules.txt^|tasklist /m
>> "%CMD_FILE%" echo process\wmic_process.txt^|wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate /format:list
>> "%CMD_FILE%" echo network\ipconfig_all.txt^|ipconfig /all
>> "%CMD_FILE%" echo network\netstat_ano.txt^|netstat -ano
>> "%CMD_FILE%" echo network\route_print.txt^|route print
>> "%CMD_FILE%" echo network\arp.txt^|arp -a
>> "%CMD_FILE%" echo network\nbtstat_cache.txt^|nbtstat -c
>> "%CMD_FILE%" echo network\firewall_legacy.txt^|netsh firewall show state
>> "%CMD_FILE%" echo network\firewall_config_legacy.txt^|netsh firewall show config
>> "%CMD_FILE%" echo network\winhttp_proxy.txt^|proxycfg
>> "%CMD_FILE%" echo persistence\services.txt^|sc queryex type= service state= all
>> "%CMD_FILE%" echo persistence\drivers.txt^|sc query type= driver state= all
>> "%CMD_FILE%" echo persistence\scheduled_tasks.txt^|schtasks /query /fo LIST /v
>> "%CMD_FILE%" echo persistence\startup_wmic.txt^|wmic startup get Caption,Command,Location,User /format:list
>> "%CMD_FILE%" echo persistence\run_hklm.txt^|reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s
>> "%CMD_FILE%" echo persistence\run_hkcu.txt^|reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s
>> "%CMD_FILE%" echo persistence\runonce_hklm.txt^|reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s
>> "%CMD_FILE%" echo persistence\runonce_hkcu.txt^|reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s
>> "%CMD_FILE%" echo persistence\winlogon.txt^|reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s
>> "%CMD_FILE%" echo persistence\ifeo.txt^|reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s
>> "%CMD_FILE%" echo persistence\appinit_dlls.txt^|reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
>> "%CMD_FILE%" echo persistence\lsa.txt^|reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /s
>> "%CMD_FILE%" echo events\system_events_wevtutil.txt^|wevtutil qe System /c:500 /f:text /rd:true
>> "%CMD_FILE%" echo events\security_events_wevtutil.txt^|wevtutil qe Security /c:500 /f:text /rd:true
>> "%CMD_FILE%" echo events\application_events_wevtutil.txt^|wevtutil qe Application /c:500 /f:text /rd:true
>> "%CMD_FILE%" echo events\system_events_eventquery.txt^|eventquery.vbs /L System /V
>> "%CMD_FILE%" echo events\security_events_eventquery.txt^|eventquery.vbs /L Security /V
>> "%CMD_FILE%" echo files\temp_listing.txt^|dir /a /s /t:w "%TEMP%"
>> "%CMD_FILE%" echo files\downloads_listing.txt^|dir /a /s /t:w "%USERPROFILE%\Downloads"
>> "%CMD_FILE%" echo files\desktop_listing.txt^|dir /a /s /t:w "%USERPROFILE%\Desktop"
>> "%CMD_FILE%" echo files\allusersprofile_listing.txt^|dir /a /s /t:w "%ALLUSERSPROFILE%"
>> "%CMD_FILE%" echo files\startup_dirs.txt^|dir /a /s "%USERPROFILE%\Start Menu\Programs\Startup" "%ALLUSERSPROFILE%\Start Menu\Programs\Startup"
>> "%CMD_FILE%" echo security\security_center_wmic.txt^|wmic /namespace:\\root\SecurityCenter Path AntiVirusProduct Get displayName,productUptoDate,onAccessScanningEnabled /format:list

for /f "usebackq tokens=1,* delims=|" %%A in ("%CMD_FILE%") do (
    set "REL=%%A"
    set "CMDLINE=%%B"
    set "DEST=%OUTDIR%\!REL!"
    > "!DEST!" echo [!DATE! !TIME!] $ !CMDLINE!
    cmd /d /c "!CMDLINE!" >> "!DEST!" 2>&1
    set "CMD_RC=!ERRORLEVEL!"
    if "!CMD_RC!"=="0" (set "CMD_STATUS=ok") else (set "CMD_STATUS=failed")
    >> "%OUTDIR%\command-index.tsv" echo !REL!	!CMDLINE!	!CMD_RC!	!CMD_STATUS!
    if not "!CMD_RC!"=="0" >> "%OUTDIR%\errors\command-failures.tsv" echo !REL!	!CMDLINE!	!CMD_RC!
)

> "%OUTDIR%\manifest.json" echo {
>> "%OUTDIR%\manifest.json" echo   "schema": "ir-log-manifest/v1",
>> "%OUTDIR%\manifest.json" echo   "script_name": "windows-ir-collector.bat",
>> "%OUTDIR%\manifest.json" echo   "script_version": "%SCRIPT_VERSION%",
>> "%OUTDIR%\manifest.json" echo   "schema_version": 2,
>> "%OUTDIR%\manifest.json" echo   "collector_mode": "legacy-bat",
>> "%OUTDIR%\manifest.json" echo   "os_type": "windows",
>> "%OUTDIR%\manifest.json" echo   "hostname": "%COMPUTERNAME%",
>> "%OUTDIR%\manifest.json" echo   "collected_at_utc": "%COLLECTED_UTC%",
>> "%OUTDIR%\manifest.json" echo   "collection_started_utc": "%COLLECTED_UTC%",
>> "%OUTDIR%\manifest.json" echo   "collection_finished_utc": "%COLLECTED_UTC%",
>> "%OUTDIR%\manifest.json" echo   "collection_profile": "legacy-standard",
>> "%OUTDIR%\manifest.json" echo   "output_directory": "%OUTDIR:\=\\%",
>> "%OUTDIR%\manifest.json" echo   "privilege": "unknown",
>> "%OUTDIR%\manifest.json" echo   "read_only": true,
>> "%OUTDIR%\manifest.json" echo   "network_upload_performed": false,
>> "%OUTDIR%\manifest.json" echo   "encoding": "utf-8-best-effort",
>> "%OUTDIR%\manifest.json" echo   "codepage": 65001,
>> "%OUTDIR%\manifest.json" echo   "sensitive_data_warning": true,
>> "%OUTDIR%\manifest.json" echo   "coverage": {
>> "%OUTDIR%\manifest.json" echo     "system": "partial",
>> "%OUTDIR%\manifest.json" echo     "accounts": "partial",
>> "%OUTDIR%\manifest.json" echo     "process": "partial",
>> "%OUTDIR%\manifest.json" echo     "network": "partial",
>> "%OUTDIR%\manifest.json" echo     "persistence": "partial",
>> "%OUTDIR%\manifest.json" echo     "events": "partial",
>> "%OUTDIR%\manifest.json" echo     "files": "partial",
>> "%OUTDIR%\manifest.json" echo     "security_products": "partial"
>> "%OUTDIR%\manifest.json" echo   },
>> "%OUTDIR%\manifest.json" echo   "critical_gaps": ["Legacy BAT fallback mode has reduced event, hash, and protected artifact coverage."],
>> "%OUTDIR%\manifest.json" echo   "files_index_file": "command-index.tsv",
>> "%OUTDIR%\manifest.json" echo   "command_failures_file": "errors/command-failures.tsv",
>> "%OUTDIR%\manifest.json" echo   "files": [],
>> "%OUTDIR%\manifest.json" echo   "hash_unavailable": true,
>> "%OUTDIR%\manifest.json" echo   "compatibility_note": "BAT fallback mode for Windows Server 2003/2008 class systems or hosts without PowerShell 3+. Some commands may be missing depending on installed components."
>> "%OUTDIR%\manifest.json" echo }

echo [*] Done. Review "%OUTDIR%\manifest.json"
exit /b 0
