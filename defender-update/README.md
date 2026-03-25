# Defender Daily Signature Update (OPSI Package)

OPSI deployment package that creates a daily scheduled task to update Windows Defender signatures on domain-joined machines.

## Problem

Domain-joined machines managed through WSUS may silently fail to update Defender signatures — `Update-MpSignature` and `MpCmdRun.exe` return success but definitions remain stale. This package deploys a scheduled task that uses multiple fallback methods, including direct download of the definition package from Microsoft, to ensure signatures stay current.

## How It Works

The scheduled task runs daily at **6:00 AM** as **SYSTEM** and tries 4 update methods in order, stopping at the first success:

| Method | Description |
|--------|-------------|
| `Update-MpSignature` | Built-in PowerShell cmdlet |
| `MpCmdRun -MMPC` | Direct from Microsoft Malware Protection Center |
| `MpCmdRun -SignatureUpdate` | Default update source (WSUS/WU) |
| **Direct download** | Downloads `mpam-fe.exe` from Microsoft and applies it locally |

Each method verifies the signature version actually changed before reporting success.

## Requirements

- Windows 11 23H2+ (build 22631+)
- Windows Defender active (not replaced by third-party AV)
- Network access to `go.microsoft.com` for direct download fallback
- OPSI 4.2+ with opsi-script 4.12+

## File Structure

```
defender-update/
├── OPSI/
│   └── control              # OPSI product metadata
├── CLIENT_DATA/
│   ├── setup.opsiscript     # Installs task + runs initial update
│   ├── uninstall.opsiscript # Removes task and deployed files
│   └── update-defender.ps1  # PowerShell script executed by the task
└── README.md
```

## Deployment

### Build the OPSI package

```bash
opsi-makepackage defender-update/
```

### Upload to OPSI depot

```bash
opsi-package-manager -i defender-update_1.0.0-1.opsi
```

### Deploy to clients

Use the OPSI management console (configed) or command line:

```bash
opsi-admin -d method setProductActionRequest defender-update <client-id> setup
```

## What Gets Installed

| Component | Path |
|-----------|------|
| Update script | `C:\ProgramData\DefenderUpdate\update-defender.ps1` |
| Log file | `C:\ProgramData\DefenderUpdate\update.log` |
| Scheduled task | `DefenderDailySignatureUpdate` (SYSTEM, 5 daily + logon) |

## Uninstall

Set the OPSI product action to `uninstall`. This removes:
- The `DefenderDailySignatureUpdate` scheduled task
- The `C:\ProgramData\DefenderUpdate\` directory and all contents

## Logs

The update script logs to `C:\ProgramData\DefenderUpdate\update.log` with automatic rotation at 5 MB. Each run records:
- Which methods were attempted
- Success/failure of each method
- Before and after signature versions

## Customisation

| Setting | Location | Default |
|---------|----------|---------|
| Schedule times | `setup.opsiscript` → `ShellInAnIcon_CreateTask` | 7AM, 10AM, 1PM, 4PM, 7PM + logon |
| Cooldown period | `update-defender.ps1` → `$lastRunFile` check | 4 hours |
| Log max size | `update-defender.ps1` → `$Script:MaxLogSizeMB` | 5 MB |
| Log path | `update-defender.ps1` → `$Script:LogDir` | `C:\ProgramData\DefenderUpdate` |
