<#
.SYNOPSIS
Generates a BitLocker status and recovery key report for Active Directory computers.

.DESCRIPTION
Get-ADBitLockerReport queries one or more domain-joined computers and collects:

• Online/WinRM availability
• BitLocker protection status
• Encryption percentage
• TPM presence and readiness
• Active Directory recovery key information

Optional capabilities include:
• Automatically enabling BitLocker on eligible devices
• Backing up missing recovery keys to AD
• Removing duplicate recovery password protectors
• Running in AD-only mode (no remote connectivity required)
• Parallel processing for faster execution
• Safe CSV export with append or overwrite modes

This cmdlet can operate either:
• Against all computers matching an AD filter, OR
• From a supplied text file queue of computer names

Results are exported to CSV and also returned to the pipeline.

.PARAMETER Filter
Active Directory computer filter.
Defaults to "*" (all computers).

Examples:
    -Filter "Name -like 'LAB-*'"
    -Filter "Name -like 'LT-*'"

.PARAMETER ComputerList
Path to a text file containing one computer name per line.
Lines starting with # are ignored.
Useful for queue-based or retry processing.

.PARAMETER OutputPath
Path to the CSV report file.
Default: .\BitLocker_Report.csv

.PARAMETER Mode
Controls CSV behavior:
Append     – adds to existing file
Overwrite  – replaces file

Default: Append

.PARAMETER ThrottleLimit
Maximum number of parallel threads when running in PowerShell 7+.
Default: 20

.PARAMETER IncludeRecoveryKey
Includes the BitLocker recovery password and key ID from AD in the report.

WARNING: Recovery passwords are sensitive information.

.PARAMETER BackupMissingADKey
If a recovery key exists locally but not in AD, attempts to back it up automatically.

.PARAMETER ADOnly
Skips all remote connectivity and only checks Active Directory for recovery keys.
Useful for offline or unreachable machines.

.PARAMETER AutoEnableBitLocker
Automatically enables BitLocker on eligible machines where:
• TPM is present
• TPM is ready
• BitLocker is not already enabled

.PARAMETER CleanupDuplicateProtectors
Removes extra recovery password protectors after enabling BitLocker,
keeping only the newest protector to prevent duplicates.

.EXAMPLE
Get-ADBitLockerReport

Runs against all domain computers and exports a basic BitLocker status report.

.EXAMPLE
Get-ADBitLockerReport -Filter "Name -like 'LT-*'" -IncludeRecoveryKey

Reports on all laptops and includes AD recovery passwords.

.EXAMPLE
Get-ADBitLockerReport -ComputerList .\queue.txt -BackupMissingADKey

Processes only machines in queue.txt and backs up missing recovery keys.

.EXAMPLE
Get-ADBitLockerReport -Filter "*" -AutoEnableBitLocker

Automatically enables BitLocker on all eligible devices and reports results.

.EXAMPLE
Get-ADBitLockerReport -Filter "Name -like 'LAB-*'" `
    -AutoEnableBitLocker `
    -CleanupDuplicateProtectors `
    -IncludeRecoveryKey `
    -Mode Overwrite

Full remediation mode:
* enables BitLocker
* removes duplicate protectors
* includes recovery keys
* overwrites report

.EXAMPLE
Get-ADBitLockerReport -ADOnly -IncludeRecoveryKey

Performs an AD-only audit of recovery key presence without contacting endpoints.

.OUTPUTS
PSCustomObject with:
Timestamp, Computer, Online, Reported, Volume, Protected, Percent,
RecoveryKeyID, RecoveryPassword, TPMPresent, TPMReady, CanEnableBitLocker

.NOTES
Author: Bill Galway
Module: BitLockerTools
Requires:
• ActiveDirectory module
• BitLocker cmdlets
• WinRM enabled on targets
• PowerShell 7+ recommended for parallel processing
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
        [switch]$ADOnly,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupDuplicateProtectors
    )

    $Results = @()
    $UseParallel = $PSVersionTable.PSVersion.Major -ge 7

    # Prep Filter
    if ($Filter) { if (-not $Filter.Trim().StartsWith("Name -like")) { $Filter = "Name -like '$Filter'" } } else { $Filter = "*" }

    # Determine computers to process
    if ($ComputerList) {
        if (-not (Test-Path $ComputerList)) { Write-Log "Computer list file not found: $ComputerList" "ERROR"; exit 1 }
        Write-Log "Using queue file: $ComputerList"

        $ComputersToProcess = Get-Content $ComputerList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
        if (-not $ComputersToProcess) { Write-Log "No computers to process in queue."; return }

        if ($UseParallel) {
            $Results = $ComputersToProcess | ForEach-Object -Parallel {
                param($ComputerName,$IncludeRecoveryKey,$BackupMissingADKey,$ADOnly,$AutoEnableBitLocker,$CleanupDuplicateProtectors)
                & $using:Process-Computer -ComputerName $ComputerName `
                    -IncludeRecoveryKey:$IncludeRecoveryKey `
                    -BackupMissingADKey:$BackupMissingADKey `
                    -ADOnly:$ADOnly `
                    -AutoEnableBitLocker:$AutoEnableBitLocker `
                    -CleanupDuplicateProtectors:$CleanupDuplicateProtectors
            } -ThrottleLimit $ThrottleLimit -ArgumentList $IncludeRecoveryKey,$BackupMissingADKey,$ADOnly,$AutoEnableBitLocker,$CleanupDuplicateProtectors
        }
        else {
            foreach ($c in $ComputersToProcess) {
                $Results += Process-Computer -ComputerName $c `
                    -IncludeRecoveryKey:$IncludeRecoveryKey `
                    -BackupMissingADKey:$BackupMissingADKey `
                    -ADOnly:$ADOnly `
                    -AutoEnableBitLocker:$AutoEnableBitLocker `
                    -CleanupDuplicateProtectors:$CleanupDuplicateProtectors
            }
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
        # AD filter mode
        Write-Log "Querying AD with filter: $Filter"
        $Computers = Get-ADComputer -Filter $Filter | Select-Object -ExpandProperty Name
        if (-not $Computers) { Write-Log "No computers found for filter."; return }

        if ($UseParallel) {
            $Results = $Computers | ForEach-Object -Parallel {
                param($ComputerName,$IncludeRecoveryKey,$BackupMissingADKey,$ADOnly,$AutoEnableBitLocker,$CleanupDuplicateProtectors)
                & $using:Process-Computer -ComputerName $ComputerName `
                    -IncludeRecoveryKey:$IncludeRecoveryKey `
                    -BackupMissingADKey:$BackupMissingADKey `
                    -ADOnly:$ADOnly `
                    -AutoEnableBitLocker:$AutoEnableBitLocker `
                    -CleanupDuplicateProtectors:$CleanupDuplicateProtectors
            } -ThrottleLimit $ThrottleLimit -ArgumentList $IncludeRecoveryKey,$BackupMissingADKey,$ADOnly,$AutoEnableBitLocker,$CleanupDuplicateProtectors
        }
        else {
            foreach ($c in $Computers) {
                $Results += Process-Computer -ComputerName $c `
                    -IncludeRecoveryKey:$IncludeRecoveryKey `
                    -BackupMissingADKey:$BackupMissingADKey `
                    -ADOnly:$ADOnly `
                    -AutoEnableBitLocker:$AutoEnableBitLocker `
                    -CleanupDuplicateProtectors:$CleanupDuplicateProtectors
            }
        }
    }

    # Export CSV
    Export-ResultsSafe -Results $Results -Path $OutputPath -Mode $Mode
    return $Results
}


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
# Remote TPM check
# ----------------------------
function Test-TPM {
    param([string]$ComputerName)
    try {
        $tpm = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerID
        }
        return $tpm
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
# Enable BitLocker remotely
# ----------------------------
function Enable-BitLockerRemote {
    param(
        [string]$ComputerName,
        [int]$TimeoutSeconds = 15
    )

    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($TimeoutSeconds)

            $vol = Get-BitLockerVolume -MountPoint "C:"
            if ($vol.ProtectionStatus -eq "On") { return $true }

            # Enable BitLocker (creates ONE recovery protector automatically)
            Enable-BitLocker `
                -MountPoint "C:" `
                -EncryptionMethod XtsAes256 `
                -UsedSpaceOnly `
                -RecoveryPasswordProtector `
                -Confirm:$false

            # Get that protector
            $protector = (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
                Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
                Select-Object -First 1

            # Backup to AD
            Backup-BitLockerKeyProtector `
                -MountPoint $env:SystemDrive `
                -KeyProtectorId $protector.KeyProtectorId

            # wait until protection turns on
            $start = Get-Date
            do {
                Start-Sleep 5
                $vol = Get-BitLockerVolume -MountPoint "C:"
            }
            while ($vol.ProtectionStatus -ne "On" -and ((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds)

            return ($vol.ProtectionStatus -eq "On")
        } -ArgumentList $TimeoutSeconds -ErrorAction Stop
    }
    catch {
        return $false
    }
}

# ----------------------------
# Remove extra recovery protectors (keep newest)
# ----------------------------
function Remove-ExtraBitLockerProtectors {
    param([string]$ComputerName)

    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {

            $protectors = (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
                Where-Object KeyProtectorType -eq "RecoveryPassword"

            if ($protectors.Count -le 1) { return }

            # Keep newest
            $keep = $protectors | Select-Object -Last 1
            $remove = $protectors | Where-Object { $_.KeyProtectorId -ne $keep.KeyProtectorId }

            foreach ($p in $remove) {
                Remove-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $p.KeyProtectorId
            }
        }
    }
    catch {
        Write-Log "Protector cleanup failed on $ComputerName : $_" "WARN"
    }
}

# ----------------------------
# Core worker (single computer)
# ----------------------------
function Process-Computer {
    param(
        [string]$ComputerName,
        [switch]$IncludeRecoveryKey,
        [switch]$BackupMissingADKey,
        [switch]$ADOnly,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupDuplicateProtectors
    )

    $timestamp = Get-Date
    $TPMPresent = $false
    $TPMReady   = $false
    $status     = $null
    $key        = $null

    if (-not $ADOnly) {

        # ----------------------------
        # Test if computer is online via ping
        # ----------------------------
        $online = Test-DeviceOnline $ComputerName
        if (-not $online) {
            Write-Log "$ComputerName is offline (ping failed)." "WARN"
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
                TPMPresent       = $false
                TPMReady         = $false
                CanEnableBitLocker = $false
            }
        }

        # ----------------------------
        # Test WinRM connectivity
        # ----------------------------
        try {
            Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
            $WinRM = $true
        }
        catch {
            Write-Log "Cannot reach $ComputerName via WinRM: $($_.Exception.Message)" "WARN"
            $WinRM = $false
        }

        if (-not $WinRM) {
            return [PSCustomObject]@{
                Timestamp        = $timestamp
                Computer         = $ComputerName
                Online           = $true
                Reported         = $false
                Volume           = ""
                Protected        = ""
                Percent          = ""
                RecoveryKeyID    = ""
                RecoveryPassword = ""
                TPMPresent       = $false
                TPMReady         = $false
                CanEnableBitLocker = $false
            }
        }

        # ----------------------------
        # Query BitLocker and TPM
        # ----------------------------
        $status = Get-BitLockerStatusRemote $ComputerName
        $TPMInfo = Test-TPM -ComputerName $ComputerName
        $TPMPresent = if ($TPMInfo) { $TPMInfo.TpmPresent } else { $false }
        $TPMReady   = if ($TPMInfo) { $TPMInfo.TpmReady } else { $false }

        $CanEnableBitLocker = ($status.ProtectionStatus -ne 1) -and $TPMPresent -and $TPMReady

        # -----------------------------------
        # Auto-enable BitLocker if requested
        # -----------------------------------
        if ($AutoEnableBitLocker) {
            if (-not $status) {
                Write-Log "Unable to query BitLocker status on $ComputerName" "WARN"
            }
            elseif ($status.ProtectionStatus -eq 1) {
                Write-Log "BitLocker already enabled on $ComputerName. Skipping."
            }
            elseif ($TPMPresent -and $TPMReady) {
	        
                Write-Log "BitLocker disabled on $ComputerName. Attempting enable..."
	        
                $enabled = Enable-BitLockerRemote -ComputerName $ComputerName
	        
                if ($enabled) {
	        
                    Write-Log "BitLocker enabled successfully on $ComputerName"
	        
                    if ($CleanupDuplicateProtectors) {
                        Write-Log "Cleaning duplicate recovery protectors on $ComputerName"
                        Remove-ExtraBitLockerProtectors -ComputerName $ComputerName | Out-Null
                    }
	        
                    $status = Get-BitLockerStatusRemote $ComputerName
	        
                    if ($IncludeRecoveryKey) {
                        $key = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName | Select-Object -Last 1
                    }
                }
                else {
                    Write-Log "Failed to enable BitLocker on $ComputerName" "ERROR"
                }
            }
            else {
                Write-Log "Cannot enable BitLocker on $ComputerName (TPM not ready or missing)." "WARN"
            }
        }

    }
    else {
        # ADOnly mode
        $status = [PSCustomObject]@{
            VolumeStatus      = ""
            ProtectionStatus  = ""
            EncryptionPercent = ""
        }
        $TPMPresent = $false
        $TPMReady   = $false
        $CanEnableBitLocker = $false
    }

    # ----------------------------
    # Get AD recovery key if requested
    # ----------------------------
    if ($IncludeRecoveryKey -or $ADOnly) {
        $key = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName | Select-Object -First 1
    }

    # ----------------------------
    # Backup missing AD key if requested
    # ----------------------------
    if (-not $ADOnly -and -not $key -and $BackupMissingADKey) {

        Write-Log "Recovery key missing in AD for $ComputerName. Attempting backup..."

        try {

            $Protector = Invoke-Command -ComputerName $ComputerName -ScriptBlock {

                $vol = Get-BitLockerVolume -MountPoint "C:"

                $existing = $vol.KeyProtector |
                            Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }

                # If no protector exists, create one
                if (-not $existing) {
                    Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
                }
                else {
                    $existing
                }
            }

            foreach ($p in $Protector) {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($ID)
                    Backup-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $ID
                } -ArgumentList $p.KeyProtectorId
            }

            # refresh AD lookup
            $key = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName | Select-Object -First 1

            Write-Log "Recovery key successfully backed up for $ComputerName"
        }
        catch {
            Write-Log "Failed to backup recovery key for ${ComputerName}: $_" "ERROR"
        }
    }

    # ----------------------------
    # Build result object
    # ----------------------------
    return [PSCustomObject]@{
        Timestamp          = $timestamp
        Computer           = $ComputerName
        Online             = if($ADOnly){$null}else{$true}
        Reported           = if($ADOnly){$true}else{$status -ne $null}
        Volume             = $status.VolumeStatus
        Protected          = $status.ProtectionStatus
        Percent            = $status.EncryptionPercent
        RecoveryKeyID      = if($IncludeRecoveryKey){$key.RecoveryKeyID} elseif ($ADOnly){ if($key){$true}else{$false} } else { "" }
        RecoveryPassword   = if($IncludeRecoveryKey){$key.RecoveryPassword} elseif ($ADOnly){ if($key){$true}else{$false} } else { "" }
        TPMPresent         = $TPMPresent
        TPMReady           = $TPMReady
        CanEnableBitLocker = $CanEnableBitLocker
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

    # Ensure consistent column order
    $ColumnOrder = @(
        "Timestamp",
        "Computer",
        "Online",
        "Reported",
        "Volume",
        "Protected",
        "Percent",
        "RecoveryKeyID",
        "RecoveryPassword",
        "TPMPresent",
        "TPMReady",
        "CanEnableBitLocker"
    )

    # Reorder properties
    $OrderedResults = $Results | Select-Object $ColumnOrder

    if ($Mode -eq "Overwrite") {
        Write-Log "Overwriting report $Path"
        $OrderedResults | Export-Csv $Path -NoTypeInformation
    }
    else {
        if (Test-Path $Path) {
            Write-Log "Appending to existing report $Path"
            $OrderedResults | Export-Csv $Path -NoTypeInformation -Append
        }
        else {
            Write-Log "Creating new report $Path"
            $OrderedResults | Export-Csv $Path -NoTypeInformation
        }
    }
}

Export-ModuleMember -Function Get-ADBitLockerReport
