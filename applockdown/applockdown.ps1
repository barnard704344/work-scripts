<#
    App Lockdown Tool (Windows 11 23H2+)
    -------------------------------------
    - For domain-joined Windows 11 23H2+ machines
    - Restricts standard-user app execution to Microsoft Office, Edge, and Chrome
    - Blocks Microsoft Store access (registry + AppLocker Appx deny)
    - Uses AppLocker path rules with Windows system allowances
    - Backs up existing AppLocker policy before applying
    - Administrators retain full unrestricted access
    - Supports full uninstall / rollback
    - Logs all actions to C:\Windows\Temp\AppLockdown.log
    - Menu-driven interface

    NOTE: On domain-joined machines, domain GPO AppLocker policies will merge
    with/override local policy. If AppLocker is already managed via GPO, these
    local rules may be superseded. The registry-based Store block and local
    AppLocker policy work best when AppLocker is NOT centrally managed via GPO.
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

# -----------------------------
# Config
# -----------------------------
$Script:LogPath       = "C:\Windows\Temp\AppLockdown.log"
$Script:BackupPath    = "C:\Windows\Temp\AppLockdown_backup.xml"
$Script:MarkerKey     = "HKLM:\SOFTWARE\AppLockdown"
$Script:MarkerName    = "Installed"
$Script:ServiceName   = "AppIDSvc"

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
# Pre-flight checks
# -----------------------------
function Test-Prerequisites {
    # Check Windows version (23H2 = build 22631+)
    $build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
    if ($build -lt 22631) {
        Write-Log "ERROR: Windows 11 23H2 or later is required (build 22631+). Current build: $build"
        return $false
    }

    # Check domain join
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain -ne $true) {
        Write-Log "ERROR: This machine is not domain-joined. Script is intended for domain-joined machines only."
        return $false
    }
    Write-Log "Domain: $($cs.Domain)"

    # Check AppLocker module
    if (-not (Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue)) {
        Write-Log "ERROR: AppLocker cmdlets not available. Windows Enterprise/Education may be required."
        return $false
    }

    # Warn if domain GPO already delivers AppLocker policy
    $gpoKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    if (Test-Path $gpoKey) {
        $children = Get-ChildItem $gpoKey -ErrorAction SilentlyContinue
        if ($children.Count -gt 0) {
            Write-Log "WARNING: Domain GPO AppLocker rules detected under $gpoKey."
            Write-Log "         Domain policy may merge with or override the local rules applied by this script."
            $confirm = Read-Host "Continue anyway? (Y/N)"
            if ($confirm -notin @('Y','y')) {
                Write-Log "Aborted by user."
                return $false
            }
        }
    }

    return $true
}

# -----------------------------
# AppLocker policy XML
# -----------------------------
function Get-LockdownPolicyXml {
    return @'
<AppLockerPolicy Version="1">

  <!-- ============ EXE RULES ============ -->
  <RuleCollection Type="Exe" EnforcementMode="Enabled">

    <!-- Administrators: unrestricted -->
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="Admins - all executables"
                  Description="Administrators can run any executable."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

    <!-- DENY user-writable locations under %WINDIR% (bypass prevention) -->
    <FilePathRule Id="e8a1b2c3-d4e5-6f70-8901-abcdef123456"
                  Name="Deny Windows Temp"
                  Description="Block execution from %WINDIR%\Temp (user-writable)."
                  UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Temp\*" />
      </Conditions>
    </FilePathRule>

    <!-- Windows system -->
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="Windows system files"
                  Description="Allow %WINDIR% for all users."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <!-- Microsoft Office (64-bit) -->
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473"
                  Name="Microsoft Office (x64)"
                  Description="Allow Office apps from Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files\Microsoft Office\*" />
      </Conditions>
    </FilePathRule>

    <!-- Microsoft Office (32-bit) -->
    <FilePathRule Id="c5e3c0f1-9a1b-4d5e-b8f2-6a7c8d9e0f1a"
                  Name="Microsoft Office (x86)"
                  Description="Allow Office apps from Program Files (x86)."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files (x86)\Microsoft Office\*" />
      </Conditions>
    </FilePathRule>

    <!-- Office shared components (64-bit) -->
    <FilePathRule Id="c5e3c0f1-9a1b-4d5e-b8f2-6a7c8d9e0f1b"
                  Name="Office shared components (x64)"
                  Description="Allow Office shared components from Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files\Common Files\microsoft shared\*" />
      </Conditions>
    </FilePathRule>

    <!-- Office shared components (32-bit) -->
    <FilePathRule Id="c5e3c0f1-9a1b-4d5e-b8f2-6a7c8d9e0f1c"
                  Name="Office shared components (x86)"
                  Description="Allow Office shared components from Program Files (x86)."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files (x86)\Common Files\microsoft shared\*" />
      </Conditions>
    </FilePathRule>

    <!-- Microsoft Edge (x86 install) -->
    <FilePathRule Id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                  Name="Microsoft Edge (x86)"
                  Description="Allow Edge from Program Files (x86)."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files (x86)\Microsoft\Edge\Application\*" />
      </Conditions>
    </FilePathRule>

    <!-- Microsoft Edge (x64 install) -->
    <FilePathRule Id="a1b2c3d4-e5f6-7890-abcd-ef1234567891"
                  Name="Microsoft Edge (x64)"
                  Description="Allow Edge from Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files\Microsoft\Edge\Application\*" />
      </Conditions>
    </FilePathRule>

    <!-- Edge WebView2 (x86 install) -->
    <FilePathRule Id="a1b2c3d4-e5f6-7890-abcd-ef1234567892"
                  Name="Edge WebView2 (x86)"
                  Description="Allow Edge WebView2 from Program Files (x86)."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files (x86)\Microsoft\EdgeWebView\Application\*" />
      </Conditions>
    </FilePathRule>

    <!-- Edge WebView2 (x64 install) -->
    <FilePathRule Id="a1b2c3d4-e5f6-7890-abcd-ef1234567893"
                  Name="Edge WebView2 (x64)"
                  Description="Allow Edge WebView2 from Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files\Microsoft\EdgeWebView\Application\*" />
      </Conditions>
    </FilePathRule>

    <!-- Google Chrome (x64) -->
    <FilePathRule Id="f1e2d3c4-b5a6-9870-fedc-ba0987654321"
                  Name="Google Chrome (x64)"
                  Description="Allow Chrome from Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files\Google\Chrome\Application\*" />
      </Conditions>
    </FilePathRule>

    <!-- Google Chrome (x86) -->
    <FilePathRule Id="f1e2d3c4-b5a6-9870-fedc-ba0987654322"
                  Name="Google Chrome (x86)"
                  Description="Allow Chrome from Program Files (x86)."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files (x86)\Google\Chrome\Application\*" />
      </Conditions>
    </FilePathRule>

    <!-- Google Chrome (per-user install) -->
    <FilePathRule Id="f1e2d3c4-b5a6-9870-fedc-ba0987654323"
                  Name="Google Chrome (user install)"
                  Description="Allow per-user Chrome installs."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\*\AppData\Local\Google\Chrome\Application\*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <!-- ============ MSI RULES ============ -->
  <RuleCollection Type="Msi" EnforcementMode="Enabled">

    <!-- Administrators: unrestricted -->
    <FilePathRule Id="64ad46ff-97e1-0799-a616-0e31c41cfb4b"
                  Name="Admins - all MSI"
                  Description="Administrators can run any MSI."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

    <!-- Windows Installer cache -->
    <FilePathRule Id="5b290184-345a-4453-b184-45c3ffc8a942"
                  Name="Windows Installer cache"
                  Description="Allow cached MSI files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Installer\*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <!-- ============ SCRIPT RULES ============ -->
  <RuleCollection Type="Script" EnforcementMode="Enabled">

    <!-- Administrators: unrestricted -->
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d"
                  Name="Admins - all scripts"
                  Description="Administrators can run any script."
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

    <!-- Windows system scripts -->
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c"
                  Name="Windows system scripts"
                  Description="Allow scripts in %WINDIR%."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <!-- Program Files scripts -->
    <FilePathRule Id="d2c955b0-f2ce-4b18-87ed-397a532dcf07"
                  Name="Program Files scripts"
                  Description="Allow scripts in Program Files."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <!-- Program Files (x86) scripts -->
    <FilePathRule Id="d2c955b0-f2ce-4b18-87ed-397a532dcf08"
                  Name="Program Files (x86) scripts"
                  Description="Allow scripts in Program Files (x86)."
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Program Files (x86)\*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <!-- ============ PACKAGED APP (APPX) RULES ============ -->
  <RuleCollection Type="Appx" EnforcementMode="Enabled">

    <!-- Administrators: unrestricted -->
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
                       Name="Admins - all packaged apps"
                       Description="Administrators can run any packaged app."
                       UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <!-- DENY Microsoft Store (takes precedence over allow rules) -->
    <FilePublisherRule Id="b2c3d4e5-f6a7-8901-bcde-f23456789012"
                       Name="Deny Microsoft Store"
                       Description="Block Microsoft Store for standard users."
                       UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                                ProductName="Microsoft.WindowsStore" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <!-- Allow Microsoft-signed packaged apps (system apps, Settings, etc.) -->
    <FilePublisherRule Id="c3d4e5f6-a7b8-9012-cdef-345678901234"
                       Name="Microsoft Corporation apps"
                       Description="Allow Microsoft Corporation signed apps."
                       UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                                ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <!-- Allow Microsoft Windows-signed packaged apps (core OS) -->
    <FilePublisherRule Id="d4e5f6a7-b8c9-0123-defa-456789012345"
                       Name="Microsoft Windows apps"
                       Description="Allow Microsoft Windows signed apps."
                       UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                                ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

  </RuleCollection>

</AppLockerPolicy>
'@
}

# -----------------------------
# Install
# -----------------------------
function Install-AppLockdown {
    Write-Log "=== App Lockdown - Install ==="

    if (-not (Test-Prerequisites)) { return }

    # Check if already installed
    if ((Test-Path $Script:MarkerKey) -and
        (Get-ItemProperty -Path $Script:MarkerKey -Name $Script:MarkerName -ErrorAction SilentlyContinue)) {
        Write-Log "Lockdown is already installed. Uninstall first to re-apply."
        return
    }

    # --- Back up existing AppLocker policy ---
    Write-Log "Backing up current AppLocker policy to $Script:BackupPath ..."
    try {
        [xml]$current = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
        $current.Save($Script:BackupPath)
        Write-Log "Backup saved."
    }
    catch {
        Write-Log "WARNING: Could not back up existing policy - $($_.Exception.Message)"
        Write-Log "Continuing without backup."
    }

    # --- Block Microsoft Store via registry ---
    Write-Log "Disabling Microsoft Store via registry policies ..."
    $storePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    if (-not (Test-Path $storePath)) { New-Item -Path $storePath -Force | Out-Null }
    Set-ItemProperty -Path $storePath -Name "RemoveWindowsStore" -Value 1 -Type DWord
    Set-ItemProperty -Path $storePath -Name "DisableStoreApps"   -Value 1 -Type DWord

    $explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path $explorerPath)) { New-Item -Path $explorerPath -Force | Out-Null }
    Set-ItemProperty -Path $explorerPath -Name "NoUseStoreOpenWith" -Value 1 -Type DWord

    # --- Apply AppLocker policy ---
    Write-Log "Applying AppLocker lockdown policy ..."
    $policyXml = Get-LockdownPolicyXml
    $tempFile  = Join-Path $env:TEMP "applockdown_policy.xml"
    try {
        $policyXml | Out-File -FilePath $tempFile -Encoding UTF8 -Force
        Set-AppLockerPolicy -XmlPolicy $tempFile -ErrorAction Stop
        Write-Log "AppLocker policy applied."
    }
    catch {
        Write-Log "ERROR: Failed to apply AppLocker policy - $($_.Exception.Message)"
        return
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }

    # --- Enable Application Identity service ---
    Write-Log "Enabling Application Identity service (AppIDSvc) ..."
    Set-Service -Name $Script:ServiceName -StartupType Automatic
    Start-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue

    # --- Set install marker ---
    if (-not (Test-Path $Script:MarkerKey)) { New-Item -Path $Script:MarkerKey -Force | Out-Null }
    Set-ItemProperty -Path $Script:MarkerKey -Name $Script:MarkerName -Value 1 -Type DWord

    Write-Log ""
    Write-Log "App lockdown installed successfully."
    Write-Log ""
    Write-Log "ALLOWED for standard users:"
    Write-Log "  Microsoft Office  (Word, Excel, PowerPoint, Outlook, etc.)"
    Write-Log "  Microsoft Edge"
    Write-Log "  Google Chrome"
    Write-Log "  Windows system processes"
    Write-Log ""
    Write-Log "BLOCKED:"
    Write-Log "  Microsoft Store"
    Write-Log "  All other applications"
    Write-Log ""
    Write-Log "Administrators retain full unrestricted access."
    Write-Log ""
    Write-Log "NOTE: On domain-joined machines, domain GPO may merge with local AppLocker policy."
    Write-Log "      If rules are not enforced as expected, check for conflicting GPO settings."
    Write-Log "A restart is recommended for all rules to take effect."
}

# -----------------------------
# Uninstall
# -----------------------------
function Uninstall-AppLockdown {
    Write-Log "=== App Lockdown - Uninstall ==="

    if (-not (Test-Path $Script:MarkerKey) -or
        -not (Get-ItemProperty -Path $Script:MarkerKey -Name $Script:MarkerName -ErrorAction SilentlyContinue)) {
        Write-Log "Lockdown is not currently installed. Nothing to remove."
        return
    }

    # --- Remove Store registry blocks ---
    Write-Log "Removing Microsoft Store registry restrictions ..."
    $storePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    if (Test-Path $storePath) {
        Remove-ItemProperty -Path $storePath -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $storePath -Name "DisableStoreApps"   -ErrorAction SilentlyContinue
    }
    $explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (Test-Path $explorerPath) {
        Remove-ItemProperty -Path $explorerPath -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
    }

    # --- Restore or clear AppLocker policy ---
    if (Test-Path $Script:BackupPath) {
        Write-Log "Restoring previous AppLocker policy from backup ..."
        try {
            Set-AppLockerPolicy -XmlPolicy $Script:BackupPath -ErrorAction Stop
            Write-Log "Previous policy restored."
            Remove-Item $Script:BackupPath -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log "WARNING: Could not restore backup - $($_.Exception.Message)"
            Write-Log "Clearing AppLocker policy instead."
            Clear-AppLockerPolicy
        }
    }
    else {
        Write-Log "No backup found. Clearing AppLocker policy ..."
        Clear-AppLockerPolicy
    }

    # --- Reset Application Identity service ---
    Write-Log "Resetting Application Identity service to manual ..."
    Stop-Service -Name $Script:ServiceName -Force -ErrorAction SilentlyContinue
    Set-Service -Name $Script:ServiceName -StartupType Manual

    # --- Remove install marker ---
    Remove-ItemProperty -Path $Script:MarkerKey -Name $Script:MarkerName -ErrorAction SilentlyContinue
    Remove-Item -Path $Script:MarkerKey -ErrorAction SilentlyContinue

    Write-Log ""
    Write-Log "App lockdown removed successfully."
    Write-Log "All application restrictions have been cleared."
    Write-Log "A restart is recommended for all changes to take effect."
}

function Clear-AppLockerPolicy {
    $emptyPolicy = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe"    EnforcementMode="NotConfigured" />
  <RuleCollection Type="Msi"    EnforcementMode="NotConfigured" />
  <RuleCollection Type="Script" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Appx"   EnforcementMode="NotConfigured" />
</AppLockerPolicy>
'@
    $tempFile = Join-Path $env:TEMP "applockdown_clear.xml"
    try {
        $emptyPolicy | Out-File -FilePath $tempFile -Encoding UTF8 -Force
        Set-AppLockerPolicy -XmlPolicy $tempFile -ErrorAction Stop
        Write-Log "AppLocker policy cleared."
    }
    catch {
        Write-Log "ERROR: Failed to clear AppLocker policy - $($_.Exception.Message)"
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# -----------------------------
# Status
# -----------------------------
function Show-Status {
    Write-Host ""
    if ((Test-Path $Script:MarkerKey) -and
        (Get-ItemProperty -Path $Script:MarkerKey -Name $Script:MarkerName -ErrorAction SilentlyContinue)) {
        Write-Host "  Status: INSTALLED" -ForegroundColor Green
    }
    else {
        Write-Host "  Status: NOT INSTALLED" -ForegroundColor Yellow
    }

    $svc = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  AppIDSvc: $($svc.Status) (StartType: $($svc.StartType))" -ForegroundColor Cyan
    }
    Write-Host ""
}

# -----------------------------
# Menu
# -----------------------------
function Show-Menu {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  App Lockdown Tool  (Win 11 23H2+)"     -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Show-Status
    Write-Host "  1) Install lockdown"
    Write-Host "  2) Uninstall lockdown"
    Write-Host "  3) Exit"
    Write-Host ""
}

# -----------------------------
# Main loop
# -----------------------------
do {
    Show-Menu
    $choice = Read-Host "Select an option"

    switch ($choice) {
        "1" { Install-AppLockdown }
        "2" { Uninstall-AppLockdown }
        "3" { Write-Host "Exiting." -ForegroundColor Gray; break }
        default { Write-Host "Invalid selection." -ForegroundColor Red }
    }
} while ($choice -ne "3")
