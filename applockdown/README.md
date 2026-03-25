# App Lockdown Tool

A PowerShell script for **domain-joined** Windows 11 (23H2+) machines that restricts standard users to only Microsoft Office, Microsoft Edge, and Google Chrome. All other application execution is blocked, including the Microsoft Store.

## Overview

Uses **AppLocker** path/publisher rules and **registry policies** to enforce a strict application allowlist. Administrators retain full unrestricted access — only standard (non-admin) users are affected.

### What standard users CAN run

| Application | Paths covered |
|---|---|
| **Microsoft Office** | `Program Files\Microsoft Office\*`, `Program Files (x86)\Microsoft Office\*`, and `Common Files\microsoft shared\*` (both architectures) |
| **Microsoft Edge** | `Program Files\Microsoft\Edge\*`, `Program Files (x86)\Microsoft\Edge\*`, and Edge WebView2 paths |
| **Google Chrome** | `Program Files\Google\Chrome\*`, `Program Files (x86)\Google\Chrome\*`, and per-user installs |
| **Windows system** | `%WINDIR%\*` (OS processes, Explorer, Settings, etc.) except `%WINDIR%\Temp` |
| **Windows Installer** | `%WINDIR%\Installer\*` (cached MSIs only) |
| **System scripts** | Scripts under `%WINDIR%\*`, `%PROGRAMFILES%\*`, and `Program Files (x86)\*` |
| **Microsoft-signed apps** | All Microsoft-signed packaged apps (except Store) |

### What is BLOCKED

- **Microsoft Store** — deny publisher rule + registry policies (`RemoveWindowsStore`, `DisableStoreApps`, `NoUseStoreOpenWith`)
- **All other executables** — anything not in the paths above is blocked for standard users

## How It Works

| Layer | What it does |
|---|---|
| **AppLocker EXE rules** | Deny `%WINDIR%\Temp`; allow Windows, Office (incl. shared components), Edge (incl. WebView2), Chrome paths; deny everything else for `S-1-1-0` (Everyone) |
| **AppLocker MSI rules** | Admins unrestricted; standard users limited to Windows Installer cache |
| **AppLocker Script rules** | Allow scripts from `%WINDIR%`, `%PROGRAMFILES%`, and `Program Files (x86)`; admins unrestricted |
| **AppLocker Appx rules** | Deny Microsoft Store by publisher; allow all other Microsoft-signed apps |
| **Registry policies** | `RemoveWindowsStore`, `DisableStoreApps`, `NoUseStoreOpenWith` |
| **AppIDSvc** | Application Identity service set to Automatic and started |
| **Backup** | Existing AppLocker policy backed up to `C:\Windows\Temp\AppLockdown_backup.xml` |

## Domain-Joined Considerations

This script applies **local** AppLocker policy. On domain-joined machines:

- If AppLocker is already managed via **Group Policy**, the domain GPO rules will merge with or override the local rules.
- The script detects existing GPO-delivered AppLocker rules under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2` and warns before proceeding.
- The registry-based Store block works independently of AppLocker and is effective regardless of GPO.
- For best results, ensure AppLocker is **not** centrally managed via GPO, or coordinate with your domain admin.

## Requirements

- **Domain-joined** Windows 11 23H2 or later (build 22631+)
- Windows **Enterprise** or **Education** edition (AppLocker requirement)
- PowerShell 5.1+
- **Run as Administrator** (enforced by `#Requires -RunAsAdministrator`)

## Usage

1. Open an **elevated PowerShell** session on the target machine.
2. Run the script:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\applockdown.ps1
   ```
3. Choose an option from the menu:

   | Option | Action |
   |---|---|
   | **1** | Install lockdown — applies AppLocker policy, blocks Store, enables AppIDSvc |
   | **2** | Uninstall lockdown — restores previous AppLocker policy, removes Store block, resets AppIDSvc |
   | **3** | Exit |

## Uninstall

The uninstall option fully reverses all changes:
- Restores the previous AppLocker policy from backup (or clears all rules if no backup exists)
- Removes all Microsoft Store registry restrictions
- Stops and resets the Application Identity service to manual start
- Removes the install marker from the registry

A restart is recommended after both install and uninstall for all changes to take effect.

## Logging

All actions are logged to `C:\Windows\Temp\AppLockdown.log`.
