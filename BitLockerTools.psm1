# ----------------------------
# Logging helper
# ----------------------------
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$time][$Level] $Message"
}

# ----------------------------
# Online test
# ----------------------------
function Test-DeviceOnline {
    param([string]$ComputerName)
    Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
}

# ----------------------------
# Remote BitLocker status query
# ----------------------------
function Get-BitLockerStatusRemote {
    param([string]$ComputerName)
    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $b = Get-BitLockerVolume -MountPoint "C:"
            [PSCustomObject]@{
                VolumeStatus      = $b.VolumeStatus
                ProtectionStatus  = $b.ProtectionStatus
                EncryptionPercent = $b.EncryptionPercentage
            }
        } -ErrorAction Stop
    }
    catch { return $null }
}

# ----------------------------
# AD Recovery Key query
# ----------------------------
function Get-ADBitLockerRecoveryKeys {
    param([string]$ComputerName)
    try {
        $Comp = Get-ADComputer -Identity $ComputerName
        $RecoveryObjects = Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
                                         -SearchBase $Comp.DistinguishedName `
                                         -Properties 'msFVE-RecoveryPassword'

        $RecoveryObjects | ForEach-Object {
            [PSCustomObject]@{
                Computer         = $ComputerName
                RecoveryKeyID    = $_.ObjectGUID
                RecoveryPassword = $_.'msFVE-RecoveryPassword'
            }
        }
    }
    catch { return @() }
}

# ----------------------------
# Core worker (single computer)
# ----------------------------
function Process-Computer {
    param(
        [string]$ComputerName,
        [switch]$IncludeRecoveryKey,
        [switch]$BackupMissingADKey,
        [switch]$ADOnly
    )

    $timestamp = Get-Date

    if (-not $ADOnly) {
        $online = Test-DeviceOnline $ComputerName
        if (-not $online) {
            return [PSCustomObject]@{
                Timestamp        = $timestamp
                Computer         = $ComputerName
                Online           = $false
                Reported         = $false
                Volume           = ""
                Protected        = ""
                Percent          = ""
                RecoveryKeyID    = ""
                RecoveryPassword = ""
            }
        }

        $status = Get-BitLockerStatusRemote $ComputerName
    }
    else {
        $status = [PSCustomObject]@{
            VolumeStatus      = ""
            ProtectionStatus  = ""
            EncryptionPercent = ""
        }
    }

    $key = if ($IncludeRecoveryKey) { Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName | Select-Object -First 1 } else { $null }

    # Backup missing AD key if requested
    if (-not $ADOnly -and -not $key -and $BackupMissingADKey) {
        Write-Log "Recovery key missing in AD for $ComputerName. Attempting backup..."
        try {
            $Protector = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                (Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
            }

            foreach ($p in $Protector) {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($ID)
                    Backup-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $ID
                } -ArgumentList $p.KeyProtectorId
            }

            # Query AD again after backup
            $key = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName | Select-Object -First 1
            Write-Log "Recovery key for $ComputerName backed up to AD."
        }
        catch {
            Write-Log ("Failed to backup recovery key for " + $ComputerName + ": " + $_) "ERROR"
        }
    }

    # Build object
    return [PSCustomObject]@{
        Timestamp        = $timestamp
        Computer         = $ComputerName
        Online           = if($ADOnly){$null}else{$true}
        Reported         = if($ADOnly){$true}else{$status -ne $null}
        Volume           = $status.VolumeStatus
        Protected        = $status.ProtectionStatus
        Percent          = $status.EncryptionPercent
        RecoveryKeyID    = if($IncludeRecoveryKey){$key.RecoveryKeyID}else{""}
        RecoveryPassword = if($IncludeRecoveryKey){$key.RecoveryPassword}else{""}
    }
}

# ----------------------------
# CSV export helper
# ----------------------------
function Export-ResultsSafe {
    param(
        [array]$Results,
        [string]$Path,
        [ValidateSet("Append","Overwrite")]
        [string]$Mode = "Append"
    )

    if ($Mode -eq "Overwrite") {
        Write-Log "Overwriting report $Path"
        $Results | Export-Csv $Path -NoTypeInformation
    }
    else {
        if (Test-Path $Path) {
            Write-Log "Appending to existing report $Path"
            $Results | Export-Csv $Path -NoTypeInformation -Append
        }
        else {
            Write-Log "Creating new report $Path"
            $Results | Export-Csv $Path -NoTypeInformation
        }
    }
}

<#
.SYNOPSIS
BitLocker Reporting, Recovery Key Query, Backup, and ADOnly Mode

.DESCRIPTION
Retrieves BitLocker status for AD computers or a computer list.
Optionally includes AD-stored BitLocker recovery keys.
If a recovery key is missing in Active Directory, it can automatically
backup the local BitLocker recovery key to AD.

Supports:
- Queue file processing (comments out only online computers)
- AD filter mode
- ADOnly mode (query AD only, no online checks / no remoting)
- CSV output (Append or Overwrite)
- Timestamps
- Parallel scanning in PowerShell 7+
- Scheduler-safe operation

.PARAMETER Filter
Active Directory prefix string (e.g., "LAB-*").
Automatically prepends "Name -like" for AD queries.

.PARAMETER ComputerList
Path to a text file containing computer names (one per line).
Only online computers are commented out after reporting.

.PARAMETER OutputPath
Path to CSV file. Default: .\BitLocker_Report.csv

.PARAMETER Mode
"Append" to add to existing CSV, or "Overwrite" for fresh output.
Default: Append

.PARAMETER ThrottleLimit
Number of computers to process in parallel (PowerShell 7+).
Default: 20

.PARAMETER IncludeRecoveryKey
Include AD-stored BitLocker recovery keys in the report.

.PARAMETER BackupMissingADKey
If a recovery key does not exist in AD, attempt to backup the local
BitLocker recovery password protector to Active Directory automatically
using Backup-BitLockerKeyProtector.

.PARAMETER ADOnly
Switch. Query AD only. Skips online checks and BitLocker remoting.

.EXAMPLE
Basic BitLocker status only (no recovery keys).

Get-ADBitLockerReport -Filter "LAB-*"

.EXAMPLE
Include recovery keys stored in Active Directory.

Get-ADBitLockerReport -Filter "LAB-*" -IncludeRecoveryKey

.EXAMPLE
Include keys and automatically back up any missing recovery keys to AD.

Get-ADBitLockerReport -Filter "LAB-*" -IncludeRecoveryKey -BackupMissingADKey

.EXAMPLE
Process computers from a queue file for scheduled task usage.

Get-ADBitLockerReport -ComputerList "C:\Scripts\ComputerQueue.txt" -Mode Append

.EXAMPLE
Queue mode with recovery keys and automatic backup of missing keys.

Get-ADBitLockerReport -ComputerList "C:\Scripts\ComputerQueue.txt" -IncludeRecoveryKey -BackupMissingADKey -OutputPath "C:\Reports\BitLocker_Queue.csv"

.EXAMPLE
Run a full audit and overwrite the previous report.

Get-ADBitLockerReport -Filter "*" -IncludeRecoveryKey -Mode Overwrite -OutputPath "C:\Reports\FullAudit.csv"

.EXAMPLE
Query only AD for computers (no online checks).

Get-ADBitLockerReport -Filter "LAB-*" -ADOnly -IncludeRecoveryKey
#>
function Get-ADBitLockerReport {
    [CmdletBinding()]
    param(
        [string]$Filter,
        [string]$ComputerList,
        [string]$OutputPath = ".\BitLocker_Report.csv",
        [ValidateSet("Append","Overwrite")]
        [string]$Mode = "Append",
        [int]$ThrottleLimit = 20,
        [switch]$IncludeRecoveryKey,
        [switch]$BackupMissingADKey,
        [switch]$ADOnly
    )

    $Results = @()
    $UseParallel = $PSVersionTable.PSVersion.Major -ge 7

    # -----------------------------
    # Prep Filter
    # -----------------------------
    if ($Filter) {
        if (-not $Filter.Trim().StartsWith("Name -like")) {
            $Filter = "Name -like '$Filter'"
        }
    }
    else {
        $Filter = "*"
    }

    if ($ComputerList) {
        if (-not (Test-Path $ComputerList)) { Write-Log "Computer list file not found: $ComputerList" "ERROR"; exit 1 }

        Write-Log "Using queue file: $ComputerList"
        $ComputersToProcess = Get-Content $ComputerList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
        if (-not $ComputersToProcess) { Write-Log "No computers to process in queue."; return }

        if ($UseParallel) {
            $Results = $ComputersToProcess | ForEach-Object -Parallel {
                param($ComputerName,$IncludeRecoveryKey,$BackupMissingADKey,$ADOnly)
                function Process-Computer { param($ComputerName,$IncludeRecoveryKey,$BackupMissingADKey,$ADOnly); & $using:Process-Computer -ComputerName $ComputerName -IncludeRecoveryKey:$IncludeRecoveryKey -BackupMissingADKey:$BackupMissingADKey -ADOnly:$ADOnly }
                & { Process-Computer -ComputerName $ComputerName -IncludeRecoveryKey:$IncludeRecoveryKey -BackupMissingADKey:$BackupMissingADKey -ADOnly:$ADOnly }
            } -ThrottleLimit $ThrottleLimit -ArgumentList $IncludeRecoveryKey,$BackupMissingADKey,$ADOnly
        }
        else {
            foreach ($c in $ComputersToProcess) { $Results += Process-Computer -ComputerName $c -IncludeRecoveryKey:$IncludeRecoveryKey -BackupMissingADKey:$BackupMissingADKey -ADOnly:$ADOnly }
        }

        # Comment out online computers if not ADOnly
        if (-not $ADOnly) {
            $OnlineComputers = $Results | Where-Object { $_.Online -eq $true } | Select-Object -ExpandProperty Computer
            $QueueContent = Get-Content $ComputerList
            $NewQueue = $QueueContent | ForEach-Object { $line = $_.Trim(); if ($line -and -not $_.StartsWith("#") -and $OnlineComputers -contains $line) { "#$line" } else { $_ } }
            $NewQueue | Set-Content $ComputerList
        }
    }
    else {
        # -----------------------------
        # AD filter mode
        # -----------------------------
        Write-Log "Querying AD with filter: $Filter"
        $Computers = Get-ADComputer -Filter $Filter | Select-Object -ExpandProperty Name
        if (-not $Computers) { Write-Log "No computers found for filter."; return }

        if ($UseParallel) {
            $Results = $Computers | ForEach-Object -Parallel {
                param($ComputerName,$IncludeRecoveryKey,$BackupMissingADKey,$ADOnly)
                & $using:Process-Computer -ComputerName $ComputerName -IncludeRecoveryKey:$IncludeRecoveryKey -BackupMissingADKey:$BackupMissingADKey -ADOnly:$ADOnly
            } -ThrottleLimit $ThrottleLimit -ArgumentList $IncludeRecoveryKey,$BackupMissingADKey,$ADOnly
        }
        else {
            foreach ($c in $Computers) { $Results += Process-Computer -ComputerName $c -IncludeRecoveryKey:$IncludeRecoveryKey -BackupMissingADKey:$BackupMissingADKey -ADOnly:$ADOnly }
        }
    }

    # Export CSV
    Export-ResultsSafe -Results $Results -Path $OutputPath -Mode $Mode
    return $Results
}

Export-ModuleMember -Function Get-ADBitLockerReport
