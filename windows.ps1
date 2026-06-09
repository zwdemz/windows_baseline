<#
.SYNOPSIS
  Windows Security Baseline Audit
.DESCRIPTION
  Audits Windows security policy settings against a baseline standard.
  Exports local security policy via secedit and checks password policy,
  account lockout, user rights, audit policy, registry settings, etc.
.AUTHOR
  zwdemz
#>

$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

# --- helpers ---
function Test-SecPolValue {
  param([string]$Key, [string]$Expected, [string]$Operator, [string]$PassMsg, [string]$FailMsg)
  $val = $script:secpol | Where-Object { $_ -match "^$Key\s*=" } | ForEach-Object { ($_ -split "=",2)[1].Trim(" `"") }
  if (-not $val) { return }
  $ok = switch ($Operator) {
    'eq' { $val -eq $Expected }
    'ge' { [int]$val -ge [int]$Expected }
    'le' { [int]$val -le [int]$Expected }
  }
  $script:results += @{msg = if ($ok) { $PassMsg } else { $FailMsg } }
}

# export policy
secedit /export /cfg config.cfg /quiet
$script:secpol = Get-Content config.cfg
$script:results = @()

# accounts
$users = Get-WmiObject -Class Win32_UserAccount
$script:results += @{msg = "Current accounts: $($users)" }

# password / account lockout policy
Test-SecPolValue -Key "EnableGuestAccount"            -Expected "1"    -Operator eq  -PassMsg "Guest account disabled: OK"                           -FailMsg "Guest account disabled: FAIL"
Test-SecPolValue -Key "NewGuestName"                   -Expected "Guest" -Operator eq -PassMsg "Guest renamed: FAIL" -FailMsg "Guest renamed: OK"
Test-SecPolValue -Key "NewAdministratorName"            -Expected "Administrator" -Operator eq -PassMsg "Administrator renamed: FAIL" -FailMsg "Administrator renamed: OK"
Test-SecPolValue -Key "PasswordComplexity"              -Expected "1"    -Operator eq  -PassMsg "Password complexity: OK"                             -FailMsg "Password complexity: FAIL"
Test-SecPolValue -Key "MinimumPasswordLength"           -Expected "8"    -Operator ge  -PassMsg "Min password length >= 8: OK"                        -FailMsg "Min password length >= 8: FAIL"
Test-SecPolValue -Key "MaximumPasswordAge"              -Expected "90"   -Operator le  -PassMsg "Max password age <= 90: OK"                          -FailMsg "Max password age <= 90: FAIL"
Test-SecPolValue -Key "LockoutBadCount"                 -Expected "5"    -Operator le  -PassMsg "Lockout threshold <= 5: OK"                          -FailMsg "Lockout threshold <= 5: FAIL"
Test-SecPolValue -Key "ResetLockoutCount"               -Expected "10"   -Operator ge  -PassMsg "Lockout reset counter >= 10: OK"                     -FailMsg "Lockout reset counter >= 10: FAIL"

# user rights
Test-SecPolValue -Key "SeShutdownPrivilege"             -Expected "*S-1-5-32-544" -Operator eq -PassMsg "Shutdown privilege: OK"             -FailMsg "Shutdown privilege: FAIL"
Test-SecPolValue -Key "SeRemoteShutdownPrivilege"       -Expected "*S-1-5-32-544" -Operator eq -PassMsg "Remote shutdown privilege: OK"      -FailMsg "Remote shutdown privilege: FAIL"
Test-SecPolValue -Key "SeProfileSingleProcessPrivilege" -Expected "*S-1-5-32-544" -Operator eq -PassMsg "Take ownership privilege: OK"       -FailMsg "Take ownership privilege: FAIL"
Test-SecPolValue -Key "SeInteractiveLogonRight"         -Expected "*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551" -Operator eq -PassMsg "Local logon right: OK"   -FailMsg "Local logon right: FAIL"
Test-SecPolValue -Key "SeNetworkLogonRight"             -Expected "*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551" -Operator eq -PassMsg "Network logon right: OK" -FailMsg "Network logon right: FAIL"

# audit policy
Test-SecPolValue -Key "AuditSystemEvents"    -Expected "3" -Operator eq -PassMsg "Audit system events: OK"   -FailMsg "Audit system events: FAIL"
Test-SecPolValue -Key "AuditLogonEvents"     -Expected "3" -Operator eq -PassMsg "Audit logon events: OK"    -FailMsg "Audit logon events: FAIL"
Test-SecPolValue -Key "AuditObjectAccess"    -Expected "3" -Operator eq -PassMsg "Audit object access: OK"   -FailMsg "Audit object access: FAIL"
Test-SecPolValue -Key "AuditProcessTracking" -Expected "2" -Operator eq -PassMsg "Audit process tracking: OK" -FailMsg "Audit process tracking: FAIL"
Test-SecPolValue -Key "AuditDSAccess"        -Expected "3" -Operator eq -PassMsg "Audit DS access: OK"       -FailMsg "Audit DS access: FAIL"
Test-SecPolValue -Key "AuditPrivilegeUse"    -Expected "3" -Operator eq -PassMsg "Audit privilege use: OK"   -FailMsg "Audit privilege use: FAIL"
Test-SecPolValue -Key "AuditAccountLogon"    -Expected "3" -Operator eq -PassMsg "Audit account logon: OK"   -FailMsg "Audit account logon: FAIL"
Test-SecPolValue -Key "AuditAccountManage"   -Expected "3" -Operator eq -PassMsg "Audit account management: OK" -FailMsg "Audit account management: FAIL"

# session: auto-disconnect
$adVal = $script:secpol | Where-Object { $_ -match "^MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoDisconnect" }
if ($adVal) {
  $adParts = ($adVal -split "=",2)[1].Trim(" `"").Split(",")
  if ($adParts[1] -le 30) {
    $script:results += @{msg = "Auto-disconnect time <= 30 min: OK" }
  } else {
    $script:results += @{msg = "Auto-disconnect time <= 30 min: FAIL" }
  }
}

# registry checks
$logKeys = @{
  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application" = "Application log"
  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System"      = "System log"
  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security"    = "Security log"
}
foreach ($key in $logKeys.Keys) {
  $val = (Get-ItemProperty -Path "Registry::$key" -Name MaxSize -ErrorAction SilentlyContinue).MaxSize
  if ($val -ge 8388608) {
    $script:results += @{msg = "$($logKeys[$key]) size >= 8MB: OK" }
  } else {
    $script:results += @{msg = "$($logKeys[$key]) size >= 8MB: FAIL" }
  }
}

# startup items
$startup = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
$script:results += @{msg = "Startup items: $($startup | Out-String)" }

# IPC$ share (restrictanonymous)
$anon = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Name restrictanonymous -ErrorAction SilentlyContinue).restrictanonymous
$script:results += @{msg = if ($anon -eq 1) { "IPC`$ share restricted: OK" } else { "IPC`$ share restricted: FAIL" } }

# default share
$autoShare = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -ErrorAction SilentlyContinue).AutoShareServer
$script:results += @{msg = if ($autoShare -eq 0) { "Default share disabled: OK" } else { "Default share disabled: FAIL" } }

# autoplay
$autoRun = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
$script:results += @{msg = if ($autoRun -eq 255) { "Autoplay disabled: OK" } else { "Autoplay disabled: FAIL" } }

# screen saver timeout
$ssTimeout = (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Desktop" -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut
$script:results += @{msg = if ($ssTimeout -le 600) { "Screen saver timeout <= 600s: OK" } else { "Screen saver timeout <= 600s: FAIL" } }

# screen saver password
$ssSecure = (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue).ScreenSaverIsSecure
$script:results += @{msg = if ($ssSecure -eq 1) { "Screen saver password: OK" } else { "Screen saver password: FAIL" } }

# output
$windowsIp = (ipconfig | Select-String "IPv4" | Out-String).Split(":")[-1].Trim() -replace "\.", "-"
$date = Get-Date
$date | Out-File "${windowsIp}_result.txt"
foreach ($r in $script:results) {
  Write-Output "{'msg':[$($r.msg)]}"
  $r.msg | Out-File "${windowsIp}_result.txt" -Append
}
