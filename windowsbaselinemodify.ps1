<#
.SYNOPSIS
  Windows Security Baseline Hardening
.DESCRIPTION
  Applies security hardening settings based on Windows security baseline:
  - Renames Administrator / disables Guest
  - Enforces password policy (complexity, length, age, history)
  - Sets account lockout policy
  - Configures audit policy
  - Restricts user rights (shutdown, logon, etc.)
  - Disables autoplay, enables screen saver security
.AUTHOR
  zwdemz
#>

Function Parse-SecPol($CfgFile) {
  secedit /export /cfg "$CfgFile" | Out-Null
  $obj = New-Object psobject
  $index = 0
  $contents = Get-Content $CfgFile -Raw
  [regex]::Matches($contents, "(?<=\[)(.*)(?=\])") | ForEach-Object {
    $title = $_
    [regex]::Matches($contents, "(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | ForEach-Object {
      $section = New-Object psobject
      $_.value -split "\r\n" | Where-Object { $_.length -gt 0 } | ForEach-Object {
        $value = [regex]::Match($_, "(?<=\=).*").value
        $name  = [regex]::Match($_, ".*(?=\=)").value
        $section | Add-Member -MemberType NoteProperty -Name $name.ToString().Trim() -Value $value.ToString().Trim() -ErrorAction SilentlyContinue | Out-Null
      }
      $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
    }
    $index += 1
  }
  return $obj
}

Function Set-SecPol($Object, $CfgFile) {
  $Object.psobject.Properties.GetEnumerator() | ForEach-Object {
    "[$($_.Name)]"
    $_.Value | ForEach-Object {
      $_.psobject.Properties.GetEnumerator() | ForEach-Object {
        "$($_.Name)=$($_.Value)"
      }
    }
  } | Out-File $CfgFile -ErrorAction Stop
  secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile"
}

# temp file path
$tmpCfg = Join-Path $env:TEMP "secpol_$(Get-Random).cfg"

$SecPool = Parse-SecPol -CfgFile $tmpCfg

# --- account policy ---
$SecPool.'System Access'.NewAdministratorName = "admlntest"
$SecPool.'System Access'.EnableGuestAccount = 0
$SecPool.'System Access'.NewGuestName = (-join((48..57 + 65..90 + 97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })) + "guest"
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 8
$SecPool.'System Access'.MaximumPasswordAge = 90
$SecPool.'System Access'.PasswordHistorySize = 5
$SecPool.'System Access'.LockoutBadCount = 5
$SecPool.'System Access'.ResetLockoutCount = 30
$SecPool.'System Access'.LockoutDuration = 30

# --- audit policy ---
$SecPool.'Event Audit'.AuditSystemEvents = 3
$SecPool.'Event Audit'.AuditLogonEvents = 3
$SecPool.'Event Audit'.AuditObjectAccess = 3
$SecPool.'Event Audit'.AuditProcessTracking = 2
$SecPool.'Event Audit'.AuditDSAccess = 3
$SecPool.'Event Audit'.AuditPrivilegeUse = 3
$SecPool.'Event Audit'.AuditAccountLogon = 3
$SecPool.'Event Audit'.AuditAccountManage = 3

# --- user rights ---
$SecPool.'Privilege Rights'.SeShutdownPrivilege = "*S-1-5-32-544"
$SecPool.'Privilege Rights'.SeRemoteShutdownPrivilege = "*S-1-5-32-544"
$SecPool.'Privilege Rights'.SeProfileSingleProcessPrivilege = "*S-1-5-32-544"
$SecPool.'Privilege Rights'.SeInteractiveLogonRight = "*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551"

# --- session ---
$SecPool.'Registry Values'.'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect' = "4,15"

# apply
Set-SecPol -Object $SecPool -CfgFile $tmpCfg

# clean up
Remove-Item -Force $tmpCfg -Confirm:$false -ErrorAction SilentlyContinue

# --- registry hardening ---
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value 300
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1
