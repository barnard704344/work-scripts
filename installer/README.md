# Restricted Installer Admin Tool

A PowerShell script for **domain-joined** Windows 11 (23H2+) machines that creates a locked-down local administrator account for UAC elevation. Designed for school IT environments where students need the ability to install software but must not have unrestricted admin access.

## Overview

Standard domain users cannot install software without admin credentials. This script creates a local account called **InstallerUser** that:

- **Can** approve UAC elevation prompts (software installs, driver updates, etc.)
- **Cannot** log in interactively (local or RDP)
- **Cannot** open Computer Management, User Manager, or any account management tool
- **Cannot** modify domain membership or workplace join settings
- **Cannot** access System Properties or Account settings

The account password is a generated two-word phrase (e.g. `maple-storm`) intended to be shared with end users for UAC prompts only.

## How It Works

| Layer | What it does |
|---|---|
| **Local account** | Creates `InstallerUser` in the local Administrators group |
| **AppLocker** | Deny rules block `mmc.exe`, `net.exe`, `net1.exe`, and `SystemPropertiesComputerName.exe` for that account |
| **NTFS ACLs** | Deny read/execute on `sysdm.cpl` (System Properties) |
| **Secedit** | Assigns `SeDenyInteractiveLogonRight` and `SeDenyRemoteInteractiveLogonRight` |
| **Registry policies** | Hides the Accounts settings page; blocks domain/workplace join UI |
| **Scheduled task** | Fires on network profile changes and sends an email when the machine reconnects to the domain |
| **Email notifications** | Sends install/uninstall confirmations and domain-reconnect alerts via a no-auth SMTP relay |

All changes are fully reversible via the Uninstall option.

## Requirements

- **Domain-joined** Windows 11 23H2 or later
- PowerShell 5.1+
- **Run as Administrator** (enforced by `#Requires -RunAsAdministrator`)
- (Optional) A no-authentication SMTP relay for email notifications

## Deployment

### Installation

1. Open an **elevated PowerShell** session on the target machine.
2. Run the script:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\installer.ps1
   ```
3. Choose **option 1** (Install).
4. Enter SMTP settings when prompted (server, port, from/to addresses). If no mail relay is available, enter placeholder values — notifications will fail silently and all other functionality works normally.
5. The generated password is displayed on completion. Record it for distribution to end users.

### Providing Credentials to End Users

When a UAC prompt appears, users enter:
- **Username:** `InstallerUser`
- **Password:** the generated phrase (e.g. `cedar-falcon`)

The account cannot be used for anything beyond UAC elevation.

### Temporarily Disabling the Account

To prevent installs temporarily:

1. Run the script as admin.
2. Choose **option 3** (Lock) to disable the account.
3. Choose **option 4** (Unlock) to re-enable it.

### Reinstalling / Repairing

Run the script, choose **option 1**. If already installed, confirm the reinstall when prompted. This regenerates the password and re-applies all restrictions.

### Uninstalling

Choose **option 2** (Uninstall). This removes the account, AppLocker rules, ACLs, registry policies, the scheduled task, and the installation marker. The machine is returned to its previous state.

## Menu Options

| Option | Description |
|---|---|
| **1. Install** | Creates the restricted account and applies all lockdowns |
| **2. Uninstall** | Fully rolls back every change |
| **3. Lock** | Disables the account (UAC elevation blocked) |
| **4. Unlock** | Re-enables the account |
| **5. Exit** | Closes the script |

## Email Notifications

During install, the script prompts for SMTP relay settings. If configured:

- An email is sent on install and uninstall
- A scheduled task monitors for network profile changes — when the machine reconnects to the domain, a one-time notification is sent

SMTP settings are persisted in the registry at `HKLM:\SOFTWARE\RestrictedInstaller` and can be updated by reinstalling.

## Logs

All actions are logged to `C:\Windows\Temp\RestrictedInstaller.log`.

## FAQ

**Q: Can a user log in with the InstallerUser account?**
A: No. The account is denied interactive and remote logon rights via local security policy. Windows will reject the login even with the correct password.

**Q: What about `net user` from a command prompt?**
A: AppLocker blocks `net.exe` and `net1.exe` for the InstallerUser account. Standard users running under their own session cannot use those commands to modify admin accounts regardless.

**Q: Can AppLocker be bypassed by renaming executables?**
A: The rules block specific system paths. Renaming files in `%WINDIR%\System32` requires ownership changes and admin rights that standard users do not have.

**Q: Does this work on non-domain machines?**
A: No. The script is designed for domain-joined environments. The domain-reconnect notification depends on domain connectivity detection.

**Q: Does this work on Windows 10?**
A: It may work on Windows 10 Enterprise/Education (which include AppLocker) but is designed for Windows 11 23H2+. Windows 10 Home/Pro does not support AppLocker.

**Q: We don't have an SMTP relay. Does the script still work?**
A: Yes. Email notifications are best-effort. If sending fails, it logs a warning and continues normally.
