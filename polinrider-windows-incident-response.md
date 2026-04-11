# PolinRider Windows Incident Response Guide - Provided by OpenSourceMalware.com

---

## ⚠️ CRITICAL ALERT

This incident response guide covers Windows-specific persistence mechanisms and data theft techniques used by the PolinRider Stage 4 Python credential stealer. This malware specifically targets:

- Browser stored credentials
- Windows Credential Manager
- Cryptocurrency wallets
- System environment variables
- SSH keys and certificates

---

## Background

The OpenSourceMalware team was approached by several people who had been compromised by the PolinRider DPRK campaign.  We realized that we hadn't done a good job of explaining to people who had been compromised how to do incident response on their local machines.  This blog post aims to fix that.

## Windows Persistence Mechanisms

### 1. File System Persistence Locations

**Primary Working Directory:**
- `%USERPROFILE%\.npm\` - Main storage directory for stolen data and malware operations
- Creates timestamped subdirectories like: `{username}${computername}_{timestamp}`

**Temporary Files:**
- `%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp` - Lock file to prevent multiple instances
- `%LOCALAPPDATA%\Temp\{h}` - Additional temp files (where `h` is a dynamic value)

**Directory Structure Created:**
```
%USERPROFILE%\.npm\{username}${computername}_{timestamp}\
├── ext\                    # Browser extensions data
├── login\                  # Credential dumps
│   ├── _sysenv.json       # Environment variables
│   ├── _sysenv.env        # Environment as .env file
│   └── _credentials.json   # Windows Credential Manager dump
├── login-db\              # Browser password databases
├── spf\                   # Browser profiles/cookies
└── firefox\               # Firefox-specific data
```

### 2. Process-Based Persistence & Evasion

**Process Termination (Anti-Forensics):**
```python
# Malware uses this command to kill target processes
taskkill /f /im {process_name}.exe
```

**Target processes typically killed:**
- Browser processes (chrome.exe, firefox.exe, msedge.exe, opera.exe, brave.exe)
- Password manager processes (1password.exe, bitwarden.exe, dashlane.exe, nordpass.exe)
- Cryptocurrency wallet applications
- Any process locking database files the malware needs to access

**Mutex/Lock-Based Prevention:**
- Uses `portalocker` Python library to create exclusive file locks
- Prevents multiple malware instances from running simultaneously
- Lock file: `%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp`
- If lock exists, malware exits with message: "Already running!"

### 3. Data Exfiltration Staging Areas

**Primary Data Collection Structure:**
```
%USERPROFILE%\.npm\{username}${computername}_{YYMMDD_HHMMSS}\
├── _info.json             # System metadata and timestamps
├── ext\                   # Browser extension data
├── login\                 # Credential dumps
│   ├── _sysenv.json      # Complete environment variables
│   ├── _sysenv.env       # Environment in .env format
│   └── _credentials.json  # Windows Credential Manager contents
├── login-db\             # Browser password databases
├── spf\                  # Browser cookies and session data
└── firefox\              # Firefox-specific profiles
```

**Archive Naming Convention:**
- Primary archive: `{username}${computername}_{YYMMDD_HHMMSS}#{hash}.zip`
- Secondary archive: `{username}${computername}_{YYMMDD_HHMMSS}_2#{hash}.zip`

### 4. Windows-Specific Credential Targeting

**Windows Credential Manager Access:**
```python
# Uses WMIC to extract user SIDs
wmic useraccount where name='{username}' get sid
wmic useraccount get sid  # Fallback if specific user fails
```

**Browser Data Locations Targeted:**
```
# Chrome-based browsers
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Google\Chrome\User Data\Profile *\Login Data
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data

# Firefox-based browsers
%LOCALAPPDATA%\*\Profiles\*\logins.json
%LOCALAPPDATA%\*\*\Profiles\*\logins.json
%APPDATA%\*\Profiles\*\logins.json
%APPDATA%\*\*\Profiles\*\logins.json

# Cookies
%LOCALAPPDATA%\*\User Data\*\Cookies
%LOCALAPPDATA%\*\User Data\*\Network\Cookies
```

**System Information Gathering:**
- Complete environment variable collection
- Hardware UUID extraction via WMIC: `wmic path win32_computersystemproduct get uuid`
- User account information collection
- Network adapter information
- System platform and version details

---

## Incident Detection & Analysis

### 1. File System IOCs

**Check for malware directories:**
```cmd
# Primary malware directory
dir "%USERPROFILE%\.npm" /s /a

# Lock file indicating active infection
dir "%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp"

# Look for suspicious zip archives with hash suffixes
dir "%USERPROFILE%\.npm\*#*.zip" /s

# Check for credential dumps
dir "%USERPROFILE%\.npm\*\login\_credentials.json" /s
dir "%USERPROFILE%\.npm\*\login\_sysenv.json" /s
dir "%USERPROFILE%\.npm\*\_info.json" /s
```

**PowerShell Investigation:**
```powershell
# Find all .npm directories under user profiles
Get-ChildItem -Path "C:\Users\*\.npm" -Recurse -Force

# Look for files with timestamp patterns in filenames
Get-ChildItem -Path "C:\Users" -Filter "*_??????_??????*" -Recurse -Force

# Search for files containing credential dumps
Get-ChildItem -Path "C:\Users" -Filter "*credentials.json" -Recurse -Force
Get-ChildItem -Path "C:\Users" -Filter "*sysenv.json" -Recurse -Force
```

### 2. Process IOCs

**Suspicious Process Detection:**
```cmd
# Look for python.exe processes
wmic process where "name='python.exe'" get ProcessId,CommandLine,CreationDate,ParentProcessId

# Check for taskkill usage (malware kills browser processes)
wmic process where "name='taskkill.exe'" get ProcessId,CommandLine,CreationDate

# Look for wmic usage (malware queries system info)
wmic process where "commandline like '%wmic%useraccount%'" get ProcessId,CommandLine,CreationDate
```

**Event Log Analysis:**
```cmd
# Recent process creation events for python.exe
wevtutil qe Security /q:"*[System[(EventID=4688)] and EventData[Data[@Name='NewProcessName'] and (contains(.,'python.exe'))]]" /f:text /rd:true /c:50

# Recent taskkill usage
wevtutil qe Security /q:"*[System[(EventID=4688)] and EventData[Data[@Name='NewProcessName'] and (contains(.,'taskkill'))]]" /f:text /rd:true /c:20

# WMIC usage for system enumeration
wevtutil qe Security /q:"*[System[(EventID=4688)] and EventData[Data[@Name='CommandLine'] and (contains(.,'wmic useraccount'))]]" /f:text /rd:true /c:10
```

### 3. Network IOCs

**Active Connections:**
```cmd
# Check for connections to known C2 servers
netstat -ano | findstr "166.88.54.158"

# Look for Telegram API connections (data exfiltration)
netstat -ano | findstr "api.telegram.org"

# Check for blockchain API connections
netstat -ano | findstr "api.trongrid.io"
netstat -ano | findstr "fullnode.mainnet.aptoslabs.com"
```

**DNS Query Analysis:**
```cmd
# Check DNS cache for malicious domains
ipconfig /displaydns | findstr -i "telegram\|trongrid\|aptoslabs\|166.88.54.158"
```

### 4. Registry Analysis

**While this malware doesn't use registry persistence, check for modifications:**
```cmd
# Standard startup locations
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"

# Service entries
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "python"
```

---

## Evidence Collection & Forensics

### 1. Critical Files to Preserve

**Before cleanup, collect these files for analysis:**
```cmd
# Create evidence directory
mkdir C:\Incident_Evidence\PolinRider_%DATE%_%TIME%

# Copy malware directories (if present)
xcopy "%USERPROFILE%\.npm" "C:\Incident_Evidence\PolinRider_%DATE%_%TIME%\.npm" /s /e /i

# Copy lock files
copy "%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp" "C:\Incident_Evidence\PolinRider_%DATE%_%TIME%\"

# Copy any suspicious zip files
copy "%USERPROFILE%\.npm\*.zip" "C:\Incident_Evidence\PolinRider_%DATE%_%TIME%\archives\"
```

**Browser Database Preservation:**
```cmd
# Copy browser databases that may have been accessed
copy "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" "C:\Incident_Evidence\PolinRider_%DATE%_%TIME%\browser\"
copy "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data" "C:\Incident_Evidence\PolinRider_%DATE%_%TIME%\browser\"
```

### 2. Memory Analysis

**If malware is still running:**
```cmd
# Create memory dump
procdump -ma python.exe C:\Incident_Evidence\PolinRider_%DATE%_%TIME%\memory\

# Or using built-in tools
wmic process where "name='python.exe'" call terminate
```

### 3. Timeline Analysis

**Check file modification times in target directories:**
```powershell
# Browser profile access times
Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} |
    Select-Object FullName, LastWriteTime, CreationTime

# System files recently accessed
Get-ChildItem -Path "$env:TEMP" -Recurse |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-4)} |
    Select-Object FullName, LastWriteTime
```

---

## Immediate Response Actions

### 1. Containment

**Stop active malware processes:**
```cmd
# Kill python.exe processes (verify they're malicious first)
taskkill /f /im python.exe

# Remove lock file to allow cleanup
del "%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp"
```

**Network isolation (if needed):**
```cmd
# Block C2 communication
netsh advfirewall firewall add rule name="Block_PolinRider_C2" dir=out action=block remoteip=166.88.54.158

# Block Telegram API (if exfiltration detected)
netsh advfirewall firewall add rule name="Block_Telegram_API" dir=out action=block remoteport=443 protocol=TCP remoteip=149.154.160.0/20
```

### 2. Eradication

**Remove malware files:**
```cmd
# Remove main malware directory
rmdir /s /q "%USERPROFILE%\.npm"

# Remove temporary files
del "%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp"
del "%LOCALAPPDATA%\Temp\*" /q 2>nul

# Clean any remaining archives
del "%USERPROFILE%\*.zip" /q 2>nul
del "%TEMP%\*.zip" /q 2>nul
```

**Browser cleanup:**
```cmd
# Force close all browsers to unlock databases
taskkill /f /im chrome.exe /im msedge.exe /im firefox.exe /im opera.exe /im brave.exe 2>nul

# Consider browser profile reset if credentials were compromised
```

### 3. Credential Security

**Immediate credential rotation:**
```cmd
# Clear Windows Credential Manager (after backing up legitimate credentials)
cmdkey /list
# Manual review and cleanup required

# Browser password reset
# - Clear saved passwords in all browsers
# - Force re-authentication on all sites
# - Enable 2FA where possible
```

---

## Data Theft Assessment

### 1. Determine Scope of Compromise

**Check for evidence of successful data theft:**
```cmd
# Look for compressed archives (indicates data ready for exfiltration)
dir "%USERPROFILE%\.npm\*.zip" /s
dir "%TEMP%\*.zip"

# Check for credential dump files
type "%USERPROFILE%\.npm\*\login\_credentials.json" 2>nul
type "%USERPROFILE%\.npm\*\login\_sysenv.json" 2>nul
```

**Environment variable analysis:**
```cmd
# Check if sensitive environment variables were exposed
echo %PATH%
echo %APPDATA%
echo %USERPROFILE%
# Look for API keys, tokens, or passwords in environment
```

### 2. Assess Cryptocurrency Exposure

**Check for wallet-related files in stolen data:**
```powershell
# Search for cryptocurrency wallet indicators
Get-ChildItem -Path "$env:USERPROFILE\.npm" -Recurse -Include "*.dat","*.wallet","*wallet*" -Force 2>$null

# Check AppData for wallet applications
Get-ChildItem -Path "$env:LOCALAPPDATA" -Directory | Where-Object {$_.Name -match "wallet|crypto|bitcoin|ethereum"}
Get-ChildItem -Path "$env:APPDATA" -Directory | Where-Object {$_.Name -match "wallet|crypto|bitcoin|ethereum"}
```

---

## Recovery & Hardening

### 1. System Recovery

**Reset compromised credentials:**
1. Change all browser-saved passwords
2. Clear Windows Credential Manager entries
3. Regenerate SSH keys
4. Rotate API keys and tokens
5. Change cryptocurrency wallet passwords/keys

**Browser hardening:**
1. Clear all saved passwords
2. Disable password saving temporarily
3. Enable enhanced security features
4. Review and remove suspicious extensions

### 2. Monitoring & Prevention

**Enhanced monitoring:**
```cmd
# Enable detailed process logging
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Monitor .npm directory for future changes
# (Use SIEM or file integrity monitoring)
```

**PowerShell logging:**
```powershell
# Enable PowerShell script block logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force
```

### 3. Security Improvements

**Application whitelisting:**
- Implement AppLocker or similar to prevent unauthorized Python execution
- Restrict script execution policies

**Network monitoring:**
- Monitor for connections to blockchain APIs (suspicious for non-crypto companies)
- Alert on connections to Telegram API from internal systems
- Block known malicious IPs: 166.88.54.158

**Endpoint protection:**
- Deploy behavioral analysis tools
- Monitor for process injection and hollowing
- Alert on credential access patterns

---

## Indicators of Compromise (IOCs)

### File System IOCs
```
%USERPROFILE%\.npm\*
%LOCALAPPDATA%\Temp\tmp7A863DD1.tmp
*_credentials.json
*_sysenv.json
*#{hash}.zip
```

### Process IOCs
```
python.exe with suspicious command lines
taskkill /f /im *.exe (targeting browsers)
wmic useraccount get sid
```

### Network IOCs
```
166.88.54.158:80 (HTTP C2)
api.telegram.org:443 (Exfiltration)
api.trongrid.io:443 (Blockchain queries)
fullnode.mainnet.aptoslabs.com:443 (Blockchain queries)
```

### Registry IOCs
```
# No direct registry persistence, but may appear in:
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

---

## Post-Incident Actions

### 1. Threat Hunting

**Expand search to other systems:**
```powershell
# Network-wide search for similar artifacts
# Use appropriate enterprise tools (PowerShell, SCCM, etc.)

# Search for .npm directories across network shares
Get-ChildItem -Path "\\*\c$\Users\*\.npm" -Recurse -Force

# Look for similar lock file patterns
Get-ChildItem -Path "\\*\c$\*\Temp\tmp*.tmp" -Recurse -Force
```

### 2. Intelligence Gathering

**Update threat intelligence:**
- Add IOCs to SIEM/EDR platforms
- Share IOCs with threat intelligence platforms
- Update security awareness training

### 3. Lessons Learned

**Security control improvements:**
- Review NPM package security policies
- Implement additional monitoring for Python script execution
- Enhance credential security policies
- Consider network segmentation for development environments

---

**Document Status:** ACTIVE
**Last Updated:** 2026-04-10
**Threat Level:** CRITICAL
**Response Priority:** IMMEDIATE

---
