# Restricted Installer Admin Tool

A PowerShell script for **domain-joined** Windows 11 (23H2+) machines that creates a locked-down local administrator account so your kids can install software via UAC prompts **without** being able to log in, manage users, or remove the machine from the domain.

## What Does It Do?

When a standard (non-admin) user tries to install software on Windows, a UAC prompt asks for admin credentials. This script creates a special admin account called **InstallerUser** that:

- **Can** be used to approve UAC elevation prompts (software installs, driver updates, etc.)
- **Cannot** log in to the desktop (local or remote/RDP)
- **Cannot** open Computer Management, User Manager, or any tool that manages accounts
- **Cannot** join the computer to a domain or workplace
- **Cannot** open System Properties or Account settings

The password is a simple two-word phrase (e.g. `maple-storm`) that's easy to tell your kids over the phone or write on a sticky note, without worrying about them doing anything dangerous with it.

## How It Works (Technical Summary)

| Layer | What it does |
|---|---|
| **Local account** | Creates `InstallerUser` in the Administrators group |
| **AppLocker** | Deny rules block `mmc.exe`, `net.exe`, `net1.exe`, and `SystemPropertiesComputerName.exe` for that user |
| **NTFS ACLs** | Deny read/execute on `sysdm.cpl` (System Properties control panel) |
| **Secedit** | Assigns `SeDenyInteractiveLogonRight` and `SeDenyRemoteInteractiveLogonRight` so the account can't actually log in |
| **Registry policies** | Hides the Accounts page in Settings; blocks the domain/workplace join UI |
| **Scheduled task** | Fires on network profile changes and sends an email when the machine rejoins a domain |
| **Email notifications** | Sends install/uninstall confirmations and domain-reconnect alerts via a no-auth SMTP relay |

Everything is fully reversible — the Uninstall option rolls back every change.

## Requirements

- **Domain-joined** Windows 11 23H2 or later
- PowerShell 5.1+
- **Run as Administrator** (the script enforces this)
- (Optional) A no-authentication SMTP relay on your network for email notifications

## Parent How-To

### First-Time Setup

1. **Log in to your kid's computer** with your own admin account.
2. **Right-click** `installer.ps1` and choose **Run with PowerShell**, or open an elevated PowerShell window and run:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\installer.ps1
   ```
3. Choose **option 1** — Install.
4. The script will ask for **email settings** (SMTP server, port, from/to addresses). If you don't have a mail relay, just type any placeholder — notifications will silently fail and everything else still works.
5. When it finishes, it prints the generated password — something like `cedar-falcon`. **Write this down.** This is the password your kids will type into UAC prompts.

### What to Tell Your Kids

> "When Windows asks for permission to install something, type **InstallerUser** as the username and **cedar-falcon** as the password, then click Yes."

That's it. They can approve installs but they can't log in as that account, manage users, or change system settings.

### Temporarily Disabling the Account

If you want to block installs for a while (exam season, grounding, etc.):

1. Run the script as admin.
2. Choose **option 3** — Lock. This disables the account so UAC prompts won't accept it.
3. When you're ready to allow installs again, run the script and choose **option 4** — Unlock.

### Reinstalling / Repairing

Run the script, choose **option 1**. If it's already installed, it will ask if you want to reinstall. Say **Y** — this regenerates the password and re-applies all restrictions.

### Removing Everything

Run the script, choose **option 2** — Uninstall. This removes the account, all AppLocker rules, ACLs, registry policies, and the scheduled task. The machine goes back to exactly how it was before.

## Menu Options

| Option | Description |
|---|---|
| **1. Install** | Creates the restricted account and applies all lockdowns |
| **2. Uninstall** | Fully rolls back every change made by the script |
| **3. Lock** | Disables the account (UAC prompts stop working for it) |
| **4. Unlock** | Re-enables the account |
| **5. Exit** | Closes the script |

## Email Notifications

During install, the script asks for SMTP settings. If configured:

- An email is sent immediately after install and uninstall
- A scheduled task monitors for network profile changes — when the machine reconnects to the domain network, it sends a one-time alert

Settings are stored in the registry at `HKLM:\SOFTWARE\RestrictedInstaller` and can be updated by reinstalling.

## Logs

All actions are logged to `C:\Windows\Temp\RestrictedInstaller.log`.

## FAQ

**Q: What if my kid figures out the password and tries to log in with it?**
A: They can't. The account is denied interactive and remote logon rights via local security policy. Windows will reject the login even with the correct password.

**Q: What if they open Command Prompt and run `net user`?**
A: AppLocker blocks `net.exe` and `net1.exe` for that account. They'd also need to be running as InstallerUser to do anything with it, which they can't since they can't log in as that user.

**Q: Can they bypass AppLocker by renaming executables?**
A: AppLocker file path rules block the specific paths. Renaming system executables requires admin rights and ownership changes on protected Windows files, which standard users cannot do.

**Q: Does this work on non-domain machines?**
A: No. This script is designed for domain-joined machines. The domain-reconnect notification relies on domain connectivity, and the overall use case assumes a managed environment where kids use a domain-joined PC at home.

**Q: Does this work on Windows 10?**
A: It may work on Windows 10 Enterprise/Education (which support AppLocker), but it's designed and tested for Windows 11 23H2+. Windows 10 Home/Pro does not include AppLocker.

**Q: I don't have an SMTP relay. Will the script still work?**
A: Yes. Email notifications are best-effort. If sending fails, it logs a warning and continues normally.
