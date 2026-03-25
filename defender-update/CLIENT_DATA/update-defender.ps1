<#
    Windows Defender Signature Update Script
    -----------------------------------------
    - Downloads and applies Defender definition updates
    - Tries 4 methods: cmdlet, MMPC, MpCmdRun, direct download
    - Logs all actions to C:\ProgramData\DefenderUpdate\update.log
    - Designed for scheduled task execution on domain-joined machines
    - Bypasses WSUS/GPO restrictions via direct definition download
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

# -----------------------------
# Config
# -----------------------------
$Script:LogDir  = "$env:ProgramData\DefenderUpdate"
$Script:LogPath = Join-Path $Script:LogDir "update.log"
$Script:MaxLogSizeMB = 5

# -----------------------------
# Logging
# -----------------------------
function Write-Log {
    param([string]$Message)
    if (-not (Test-Path $Script:LogDir)) {
        New-Item -Path $Script:LogDir -ItemType Directory -Force | Out-Null
    }
    # Rotate log if too large
    if (Test-Path $Script:LogPath) {
        $size = (Get-Item $Script:LogPath).Length / 1MB
        if ($size -ge $Script:MaxLogSizeMB) {
            $backup = $Script:LogPath + ".old"
            if (Test-Path $backup) { Remove-Item $backup -Force }
            Rename-Item $Script:LogPath $backup -Force
        }
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Script:LogPath -Value "[$timestamp] $Message"
}

function Test-SignaturesUpdated {
    param([string]$BeforeVersion)
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if ($status.AntivirusSignatureVersion -ne $BeforeVersion) { return $true }
        if ($status.AntivirusSignatureAge -le 1) { return $true }
    } catch { }
    return $false
}

# -----------------------------
# Main update logic
# -----------------------------
function Update-DefenderSignatures {
    Write-Log "=========================================="
    Write-Log "Starting Defender signature update"
    Write-Log "=========================================="

    # Check Defender is present
    try {
        $before = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        Write-Log "ERROR: Windows Defender not available: $($_.Exception.Message)"
        exit 1
    }

    $beforeVersion = $before.AntivirusSignatureVersion
    $beforeAge = $before.AntivirusSignatureAge
    Write-Log "Current version: $beforeVersion (age: $beforeAge days)"

    if ($beforeAge -le 0) {
        Write-Log "Signatures already up to date (age: $beforeAge days). Exiting."
        exit 0
    }

    # Skip if we already updated recently (avoid hammering on frequent triggers)
    $lastRunFile = Join-Path $Script:LogDir "lastupdate.txt"
    if (Test-Path $lastRunFile) {
        $lastRun = Get-Content $lastRunFile -ErrorAction SilentlyContinue
        if ($lastRun) {
            $lastRunTime = [DateTime]::Parse($lastRun)
            $hoursSince = (New-TimeSpan -Start $lastRunTime -End (Get-Date)).TotalHours
            if ($hoursSince -lt 4) {
                Write-Log "Last successful update was $([math]::Round($hoursSince,1)) hours ago. Skipping."
                exit 0
            }
        }
    }

    $mpCmd = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"

    # Method 1: Update-MpSignature cmdlet
    Write-Log "[1/4] Trying Update-MpSignature..."
    try {
        Update-MpSignature -ErrorAction Stop
        Write-Log "Update-MpSignature completed."
    } catch {
        Write-Log "Update-MpSignature failed: $($_.Exception.Message)"
    }
    if (Test-SignaturesUpdated $beforeVersion) {
        Write-Log "SUCCESS: Signatures updated via Update-MpSignature."
        Set-Content -Path $lastRunFile -Value (Get-Date -Format 'o') -Force
        exit 0
    }

    # Method 2: MpCmdRun -MMPC
    if (Test-Path $mpCmd) {
        Write-Log "[2/4] Trying MpCmdRun -MMPC..."
        try {
            & $mpCmd -SignatureUpdate -MMPC 2>&1 | Out-Null
            Write-Log "MpCmdRun -MMPC completed (exit $LASTEXITCODE)."
        } catch {
            Write-Log "MpCmdRun -MMPC failed: $($_.Exception.Message)"
        }
        if (Test-SignaturesUpdated $beforeVersion) {
            Write-Log "SUCCESS: Signatures updated via MMPC."
            Set-Content -Path $lastRunFile -Value (Get-Date -Format 'o') -Force
            exit 0
        }
    }

    # Method 3: MpCmdRun default
    if (Test-Path $mpCmd) {
        Write-Log "[3/4] Trying MpCmdRun default..."
        try {
            & $mpCmd -SignatureUpdate 2>&1 | Out-Null
            Write-Log "MpCmdRun default completed (exit $LASTEXITCODE)."
        } catch {
            Write-Log "MpCmdRun default failed: $($_.Exception.Message)"
        }
        if (Test-SignaturesUpdated $beforeVersion) {
            Write-Log "SUCCESS: Signatures updated via MpCmdRun."
            Set-Content -Path $lastRunFile -Value (Get-Date -Format 'o') -Force
            exit 0
        }
    }

    # Method 4: Direct download of definition package
    Write-Log "[4/4] Downloading definition package directly..."
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
    $downloadUrl = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=$arch&nri=true"
    $defStaging = Join-Path $Script:LogDir "staging"
    $tempFile = Join-Path $defStaging "mpam-fe.exe"
    $extractDir = Join-Path $defStaging "extracted"

    try {
        # Prepare staging directory
        if (Test-Path $defStaging) { Remove-Item $defStaging -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -Path $extractDir -ItemType Directory -Force | Out-Null

        # Download
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            Start-BitsTransfer -Source $downloadUrl -Destination $tempFile -ErrorAction Stop
            Write-Log "Downloaded definition package via BITS."
        } catch {
            Write-Log "BITS failed ($($_.Exception.Message)), trying WebRequest..."
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing -ErrorAction Stop
            Write-Log "Downloaded definition package via WebRequest."
        }

        # Validate download (real package is >50 MB, redirect page is <1 MB)
        $fileSize = (Get-Item $tempFile).Length / 1MB
        Write-Log "Downloaded file size: $([math]::Round($fileSize, 1)) MB"
        if ($fileSize -lt 10) {
            Write-Log "ERROR: Downloaded file too small ($([math]::Round($fileSize, 1)) MB). Possible redirect."
            Remove-Item $defStaging -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            # Extract definitions from mpam-fe.exe
            $extractProc = Start-Process -FilePath $tempFile -ArgumentList "-q -o`"$extractDir`"" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
            Write-Log "Extraction exit code: $($extractProc.ExitCode)"

            # Apply via MpCmdRun -SignatureUpdate -UNC (runs through Defender service as SYSTEM)
            $applyResult = & $mpCmd -SignatureUpdate -UNC $extractDir 2>&1
            Write-Log "MpCmdRun -UNC result: $applyResult (exit $LASTEXITCODE)"

            # Give Defender a moment to reload
            Start-Sleep -Seconds 5

            # Clean up staging
            Remove-Item $defStaging -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "Direct download/apply failed: $($_.Exception.Message)"
        Remove-Item $defStaging -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-SignaturesUpdated $beforeVersion) {
        Write-Log "SUCCESS: Signatures updated via direct download."
        Set-Content -Path $lastRunFile -Value (Get-Date -Format 'o') -Force
        exit 0
    }

    Write-Log "ERROR: All 4 methods exhausted. Signatures still at $beforeVersion."
    exit 1
}

# Run
Update-DefenderSignatures
