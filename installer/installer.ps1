<#
    Restricted Installer Admin Tool (Windows 11 23H2+)
    --------------------------------------------------
    - Creates a restricted local installer admin (InstallerUser)
    - Generates a two-word lowercase password (word1-word2)
    - Usable for UAC elevation, but blocked from interactive logon
    - Applies AppLocker deny rules + NTFS deny ACLs
    - Blocks user management + domain join UI
    - Denies local and RDP logon for InstallerUser
    - Supports Lock/Unlock (disable/enable account)
    - Logs all actions to C:\Windows\Temp\RestrictedInstaller.log
    - Supports full uninstall / rollback
    - Menu-driven interface
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

# -----------------------------
# Config
# -----------------------------
$Script:UserName   = "InstallerUser"
$Script:LogPath    = "C:\Windows\Temp\RestrictedInstaller.log"
$Script:MarkerKey  = "HKLM:\SOFTWARE\RestrictedInstaller"
$Script:MarkerName = "Installed"
$Script:RuleTag    = "RestrictedInstaller"

# Executables blocked via AppLocker Exe rules (.exe only)
$Script:BlockExePaths = @(
    "$env:windir\System32\mmc.exe",                          # covers lusrmgr.msc, compmgmt.msc
    "$env:windir\System32\net.exe",
    "$env:windir\System32\net1.exe",
    "$env:windir\System32\SystemPropertiesComputerName.exe"
)

# Files blocked via NTFS deny ACL (non-.exe files AppLocker Exe rules can't target)
$Script:BlockAclPaths = @(
    "$env:windir\System32\sysdm.cpl"
)

# Word list for password generation
$Script:Words = @(
    "amber","anchor","apex","ash","autumn","bamboo","beacon","birch","blaze","breeze",
    "canyon","cedar","charcoal","cinder","cobalt","coral","crimson","crystal","dawn","delta",
    "ember","falcon","fern","flint","forest","frost","galaxy","granite","harbor","hazel",
    "hollow","horizon","iron","ivory","jade","jet","lagoon","lantern","linen","maple",
    "marble","meadow","mesa","midnight","mist","molten","nebula","oak","onyx","opal",
    "pebble","pine","plume","quartz","raven","ridge","river","saffron","shadow","shale",
    "silk","silver","slate","spruce","steel","stone","storm","summit","sunset","tundra",
    "valley","velvet","violet","willow","wind","winter","zenith","zephyr","harvest"
)

# -----------------------------
# Logging
# -----------------------------
function Write-Log {
    param([string]$Message)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`t$Message"
    Write-Host $Message
    Add-Content -Path $Script:LogPath -Value $entry
}

# -----------------------------
# Password generator
# -----------------------------
function New-Password {
    $w1 = $Script:Words | Get-Random
    $w2 = $Script:Words | Get-Random
    return "$w1-$w2"
}

# -----------------------------
# SID helper
# -----------------------------
function Get-UserSid {
    param([string]$Name)
    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $user) { return $user.SID.Value }
    return $null
}

# -----------------------------
# Secedit user-right helpers
# -----------------------------
function Add-UserRightDeny {
    param(
        [string]$RightName,
        [string]$Sid
    )

    $cfg = Join-Path $env:TEMP "secpol_restrict_installer.cfg"
    secedit /export /cfg $cfg /areas USER_RIGHTS | Out-Null

    $content = [System.Collections.ArrayList]@(Get-Content $cfg)
    $matchLine = $content | Where-Object { $_ -like "$RightName*" } | Select-Object -First 1

    if ($null -ne $matchLine) {
        $idx = $content.IndexOf($matchLine)
        if ($matchLine -notmatch [regex]::Escape($Sid)) {
            if ($matchLine.Trim() -eq "$RightName =") {
                $content[$idx] = "$RightName = *$Sid"
            } else {
                $content[$idx] = "$matchLine,*$Sid"
            }
        }
    } else {
        $content.Add("$RightName = *$Sid") | Out-Null
    }

    $content | Set-Content $cfg -Encoding Unicode
    secedit /configure /db (Join-Path $env:windir "security\database\secedit.sdb") /cfg $cfg /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item $cfg -Force -ErrorAction SilentlyContinue
}

function Remove-UserRightDeny {
    param(
        [string]$RightName,
        [string]$Sid
    )

    $cfg = Join-Path $env:TEMP "secpol_restrict_installer.cfg"
    secedit /export /cfg $cfg /areas USER_RIGHTS | Out-Null

    $content = [System.Collections.ArrayList]@(Get-Content $cfg)
    $matchLine = $content | Where-Object { $_ -like "$RightName*" } | Select-Object -First 1

    if ($null -ne $matchLine) {
        $idx = $content.IndexOf($matchLine)
        if ($matchLine -match [regex]::Escape($Sid)) {
            $parts  = $matchLine.Split("=", 2)
            $values = $parts[1].Split(",") |
                      ForEach-Object { $_.Trim() } |
                      Where-Object { $_ -ne "" -and $_ -ne "*$Sid" }
            if ($values.Count -gt 0) {
                $content[$idx] = "$RightName = " + ($values -join ",")
            } else {
                $content[$idx] = "$RightName ="
            }
        }
    }

    $content | Set-Content $cfg -Encoding Unicode
    secedit /configure /db (Join-Path $env:windir "security\database\secedit.sdb") /cfg $cfg /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item $cfg -Force -ErrorAction SilentlyContinue
}

# -----------------------------
# AppLocker helpers
# -----------------------------
function New-AppLockerFilePathRule {
    param([string]$NameSuffix, [string]$Tag, [string]$SidValue, [string]$Action, [string]$PathValue)
    $id = [guid]::NewGuid().ToString()
    return "    <FilePathRule Id=`"$id`" Name=`"${Tag}_$NameSuffix`" Description=`"$Tag`" UserOrGroupSid=`"$SidValue`" Action=`"$Action`">`n      <Conditions><FilePathCondition Path=`"$PathValue`" /></Conditions>`n    </FilePathRule>"
}

function Install-AppLockerDenyRules {
    param([string]$Sid)

    # Check whether an Exe rule collection already exists
    $hasExeRules = $false
    try {
        $existingXmlStr = Get-AppLockerPolicy -Local -Xml -ErrorAction Stop
        $existingDoc    = [xml]$existingXmlStr
        $exeCol = $existingDoc.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Exe" }
        $hasExeRules = ($null -ne $exeCol) -and ($exeCol.HasChildNodes)
    } catch {}

    # If no Exe rules exist yet, add default allow rules to prevent blocking everything
    $ruleLines = [System.Collections.ArrayList]::new()
    if (-not $hasExeRules) {
        Write-Log "No existing AppLocker Exe rules found - adding default allow rules."
        $ruleLines.Add((New-AppLockerFilePathRule -NameSuffix "AllowWindows"      -Tag $Script:RuleTag -SidValue "S-1-1-0"      -Action "Allow" -PathValue "%WINDIR%\*"))         | Out-Null
        $ruleLines.Add((New-AppLockerFilePathRule -NameSuffix "AllowProgramFiles"  -Tag $Script:RuleTag -SidValue "S-1-1-0"      -Action "Allow" -PathValue "%PROGRAMFILES%\*"))   | Out-Null
        $ruleLines.Add((New-AppLockerFilePathRule -NameSuffix "AllowAdmins"        -Tag $Script:RuleTag -SidValue "S-1-5-32-544" -Action "Allow" -PathValue "*"))                  | Out-Null
    }

    # Build deny rules for each blocked executable
    foreach ($app in $Script:BlockExePaths) {
        $leaf = Split-Path $app -Leaf
        $ruleLines.Add((New-AppLockerFilePathRule -NameSuffix "Block_$leaf" -Tag $Script:RuleTag -SidValue $Sid -Action "Deny" -PathValue $app)) | Out-Null
    }

    $innerXml = $ruleLines -join "`n"
    $policyXml = "<AppLockerPolicy Version=`"1`">`n  <RuleCollection Type=`"Exe`" EnforcementMode=`"Enabled`">`n$innerXml`n  </RuleCollection>`n</AppLockerPolicy>"

    $xmlPath = Join-Path $env:TEMP "RestrictedInstaller_AppLocker.xml"
    $policyXml | Set-Content -Path $xmlPath -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy $xmlPath -Merge
    Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
}

function Remove-AppLockerDenyRules {
    try {
        $policyXmlStr = Get-AppLockerPolicy -Local -Xml -ErrorAction Stop
        $doc = [xml]$policyXmlStr
        $modified = $false

        foreach ($col in $doc.AppLockerPolicy.RuleCollection) {
            $toRemove = @()
            foreach ($node in $col.ChildNodes) {
                if ($node.Description -eq $Script:RuleTag) {
                    $toRemove += $node
                }
            }
            foreach ($n in $toRemove) {
                Write-Log "Removing AppLocker rule: $($n.Name)"
                $col.RemoveChild($n) | Out-Null
                $modified = $true
            }
        }

        if ($modified) {
            $xmlPath = Join-Path $env:TEMP "RestrictedInstaller_AppLocker.xml"
            $doc.Save($xmlPath)
            Set-AppLockerPolicy -XmlPolicy $xmlPath
            Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
            Write-Log "AppLocker rules removed."
        } else {
            Write-Log "No AppLocker rules found with tag '$($Script:RuleTag)'."
        }
    }
    catch {
        Write-Log "ERROR removing AppLocker rules: $_"
    }
}

# -----------------------------
# NTFS deny-ACL helpers
# -----------------------------
function Add-NtfsDenyRule {
    param([string]$Path, [string]$Identity)
    if (-not (Test-Path $Path)) { Write-Log "Path not found, skipping ACL: $Path"; return }
    $acl  = Get-Acl -Path $Path
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $Identity, 'ReadAndExecute', 'Deny'
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $Path -AclObject $acl
    Write-Log "NTFS deny ACL set on '$Path' for '$Identity'."
}

function Remove-NtfsDenyRule {
    param([string]$Path, [string]$Identity)
    if (-not (Test-Path $Path)) { Write-Log "Path not found, skipping ACL removal: $Path"; return }
    $acl   = Get-Acl -Path $Path
    $rules = $acl.Access | Where-Object {
        $_.IdentityReference.Value -like "*\$Identity" -and
        $_.AccessControlType -eq 'Deny'
    }
    foreach ($r in $rules) {
        $acl.RemoveAccessRule($r) | Out-Null
    }
    Set-Acl -Path $Path -AclObject $acl
    Write-Log "NTFS deny ACL removed from '$Path' for '$Identity'."
}

# -----------------------------
# Install
# -----------------------------
function Install-RestrictedInstaller {

    Write-Log "=== INSTALL STARTED ==="

    $passwordPlain = New-Password
    Write-Log "Generated password for $($Script:UserName): $passwordPlain"

    # 1 - Create / update local user
    try {
        $secPwd = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

        if (-not (Get-LocalUser -Name $Script:UserName -ErrorAction SilentlyContinue)) {
            Write-Log "Creating local user '$($Script:UserName)'..."
            New-LocalUser -Name $Script:UserName -Password $secPwd -FullName "Restricted Installer Account" -ErrorAction Stop
        } else {
            Write-Log "User '$($Script:UserName)' exists - updating password..."
            Set-LocalUser -Name $Script:UserName -Password $secPwd
        }

        Write-Log "Adding '$($Script:UserName)' to Administrators group..."
        Add-LocalGroupMember -Group "Administrators" -Member $Script:UserName -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "ERROR creating user or adding to Administrators: $_"
        return
    }

    # 2 - Enable Application Identity service (required for AppLocker)
    try {
        Write-Log "Enabling Application Identity (AppIDSvc) service..."
        Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
        Start-Service -Name AppIDSvc -ErrorAction Stop
    }
    catch {
        Write-Log "ERROR enabling AppIDSvc: $_"
        return
    }

    # 3 - Apply AppLocker deny rules
    try {
        Write-Log "Applying AppLocker deny rules..."
        $sid = Get-UserSid -Name $Script:UserName
        if ($null -eq $sid) { throw "Could not resolve SID for '$($Script:UserName)'" }
        Install-AppLockerDenyRules -Sid $sid
        Write-Log "AppLocker deny rules applied."
    }
    catch {
        Write-Log "ERROR configuring AppLocker: $_"
        return
    }

    # 4 - NTFS deny ACLs for non-.exe paths
    try {
        foreach ($path in $Script:BlockAclPaths) {
            Add-NtfsDenyRule -Path $path -Identity $Script:UserName
        }
    }
    catch {
        Write-Log "ERROR setting NTFS deny ACLs: $_"
    }

    # 5 - Hide Accounts settings page
    try {
        Write-Log "Hiding Accounts settings page..."
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -Name "SettingsPageVisibility" -Value "hide:accounts"
    }
    catch {
        Write-Log "ERROR setting Accounts visibility policy: $_"
    }

    # 6 - Block domain / workplace join UI
    try {
        Write-Log "Blocking domain join / workplace join UI..."
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" `
            -Name "BlockAADWorkplaceJoin" -Value 1 -Type DWord
    }
    catch {
        Write-Log "ERROR setting WorkplaceJoin policy: $_"
    }

    # 7 - Deny interactive + RDP logon
    try {
        $sid = Get-UserSid -Name $Script:UserName
        if ($null -ne $sid) {
            Write-Log "Denying local logon (SeDenyInteractiveLogonRight)..."
            Add-UserRightDeny -RightName "SeDenyInteractiveLogonRight" -Sid $sid

            Write-Log "Denying RDP logon (SeDenyRemoteInteractiveLogonRight)..."
            Add-UserRightDeny -RightName "SeDenyRemoteInteractiveLogonRight" -Sid $sid
        } else {
            Write-Log "WARNING: Could not resolve SID for deny logon rights."
        }
    }
    catch {
        Write-Log "ERROR applying deny logon rights: $_"
    }

    # 8 - Installation marker
    try {
        Write-Log "Writing installation marker..."
        New-Item -Path $Script:MarkerKey -Force | Out-Null
        New-ItemProperty -Path $Script:MarkerKey -Name $Script:MarkerName -Value 1 -PropertyType DWord -Force | Out-Null
    }
    catch {
        Write-Log "ERROR writing installation marker: $_"
    }

    Write-Log "=== INSTALL COMPLETED ==="
    Write-Host "`nInstall complete. Restricted installer account: $($Script:UserName)" -ForegroundColor Green
    Write-Host "Generated password (for UAC elevation only, not login): $passwordPlain" -ForegroundColor Yellow
}

# -----------------------------
# Uninstall (full rollback)
# -----------------------------
function Uninstall-RestrictedInstaller {

    Write-Log "=== UNINSTALL STARTED ==="

    # 1 - Remove AppLocker rules
    Write-Log "Removing AppLocker rules..."
    Remove-AppLockerDenyRules

    # 2 - Remove NTFS deny ACLs
    try {
        foreach ($path in $Script:BlockAclPaths) {
            Remove-NtfsDenyRule -Path $path -Identity $Script:UserName
        }
    }
    catch {
        Write-Log "ERROR removing NTFS deny ACLs: $_"
    }

    # 3 - Remove registry restrictions
    try {
        Write-Log "Removing Accounts settings visibility policy..."
        if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer") {
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "SettingsPageVisibility" -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "ERROR removing Accounts visibility policy: $_"
    }

    try {
        Write-Log "Removing WorkplaceJoin policy..."
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin") {
            Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "ERROR removing WorkplaceJoin policy: $_"
    }

    # 4 - Remove deny logon rights
    try {
        $sid = Get-UserSid -Name $Script:UserName
        if ($null -ne $sid) {
            Write-Log "Removing deny local logon..."
            Remove-UserRightDeny -RightName "SeDenyInteractiveLogonRight" -Sid $sid

            Write-Log "Removing deny RDP logon..."
            Remove-UserRightDeny -RightName "SeDenyRemoteInteractiveLogonRight" -Sid $sid
        } else {
            Write-Log "WARNING: Could not resolve SID for removing deny logon rights."
        }
    }
    catch {
        Write-Log "ERROR removing deny logon rights: $_"
    }

    # 5 - Remove local user
    try {
        Write-Log "Removing local user '$($Script:UserName)'..."
        if (Get-LocalUser -Name $Script:UserName -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $Script:UserName -ErrorAction Stop
        } else {
            Write-Log "User '$($Script:UserName)' does not exist - skipping."
        }
    }
    catch {
        Write-Log "ERROR removing local user: $_"
    }

    # 6 - Remove marker
    try {
        Write-Log "Removing installation marker..."
        if (Test-Path $Script:MarkerKey) {
            Remove-Item -Path $Script:MarkerKey -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "ERROR removing installation marker: $_"
    }

    Write-Log "=== UNINSTALL COMPLETED ==="
    Write-Host "`nUninstall complete. All restrictions and the user account have been removed." -ForegroundColor Green
}

# -----------------------------
# Lock / Unlock
# -----------------------------
function Lock-InstallerUser {
    Write-Log "=== LOCK STARTED ==="
    try {
        if (Get-LocalUser -Name $Script:UserName -ErrorAction SilentlyContinue) {
            Disable-LocalUser -Name $Script:UserName -ErrorAction Stop
            Write-Log "User '$($Script:UserName)' disabled."
            Write-Host "InstallerUser locked. UAC elevation with this account is now blocked." -ForegroundColor Yellow
        } else {
            Write-Log "User '$($Script:UserName)' does not exist."
            Write-Host "User '$($Script:UserName)' does not exist." -ForegroundColor Red
        }
    }
    catch {
        Write-Log "ERROR locking user: $_"
    }
    Write-Log "=== LOCK COMPLETED ==="
}

function Unlock-InstallerUser {
    Write-Log "=== UNLOCK STARTED ==="
    try {
        if (Get-LocalUser -Name $Script:UserName -ErrorAction SilentlyContinue) {
            Enable-LocalUser -Name $Script:UserName -ErrorAction Stop
            Write-Log "User '$($Script:UserName)' enabled."
            Write-Host "InstallerUser unlocked. UAC elevation is allowed again." -ForegroundColor Green
        } else {
            Write-Log "User '$($Script:UserName)' does not exist."
            Write-Host "User '$($Script:UserName)' does not exist." -ForegroundColor Red
        }
    }
    catch {
        Write-Log "ERROR unlocking user: $_"
    }
    Write-Log "=== UNLOCK COMPLETED ==="
}

# -----------------------------
# State check
# -----------------------------
function Test-Installed {
    if (Test-Path $Script:MarkerKey) {
        $val = (Get-ItemProperty -Path $Script:MarkerKey -Name $Script:MarkerName -ErrorAction SilentlyContinue).$($Script:MarkerName)
        return ($val -eq 1)
    }
    return $false
}

# -----------------------------
# Menu
# -----------------------------
:menuLoop while ($true) {
    Write-Host ""
    Write-Host "Restricted Installer Admin Tool" -ForegroundColor Cyan
    Write-Host "--------------------------------"
    Write-Host "1. Install restricted installer environment"
    Write-Host "2. Uninstall / revert changes"
    Write-Host "3. Lock InstallerUser account (disable, no UAC elevation)"
    Write-Host "4. Unlock InstallerUser account (enable, UAC elevation only)"
    Write-Host "5. Exit"
    Write-Host ""

    $choice = Read-Host "Select an option (1-5)"

    switch ($choice) {
        "1" {
            if (Test-Installed) {
                Write-Host "`nThe restricted installer environment is already installed." -ForegroundColor Yellow
                $overwrite = Read-Host "Reinstall / repair? (Y/N)"
                if ($overwrite -match '^[Yy]$') {
                    Install-RestrictedInstaller
                } else {
                    Write-Host "Skipping install."
                }
            } else {
                Install-RestrictedInstaller
            }
        }
        "2" {
            if (-not (Test-Installed)) {
                Write-Host "`nNo installation marker found." -ForegroundColor Yellow
                $cont = Read-Host "Attempt uninstall anyway? (Y/N)"
                if ($cont -notmatch '^[Yy]$') { continue }
            }

            $confirm = Read-Host "Are you sure you want to fully uninstall and rollback? (Y/N)"
            if ($confirm -match '^[Yy]$') {
                Uninstall-RestrictedInstaller
            } else {
                Write-Host "Uninstall cancelled."
            }
        }
        "3" { Lock-InstallerUser }
        "4" { Unlock-InstallerUser }
        "5" {
            Write-Host "Exiting." -ForegroundColor Cyan
            break menuLoop
        }
        default {
            Write-Host "Invalid selection. Please choose 1-5." -ForegroundColor Red
        }
    }
}
