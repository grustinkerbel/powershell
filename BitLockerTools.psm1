<#
.SYNOPSIS
BitLocker Reporting and Status Module

.DESCRIPTION
Provides BitLocker status reporting for AD computers or a specified computer list.
Supports:
- Queue file processing (comments out only online computers)
- AD filter mode
- CSV output (Append or Overwrite)
- Timestamps
- Parallel scanning in PowerShell 7+
- Scheduler-safe operation

.AUTHOR
Bill Galway
#>

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
# Remote BitLocker query
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
# Core worker (single computer)
# ----------------------------
function Process-Computer {
    param([string]$ComputerName)

    $timestamp = Get-Date
    $online = Test-DeviceOnline $ComputerName

    if (-not $online) {
        return [PSCustomObject]@{
            Timestamp = $timestamp
            Computer  = $ComputerName
            Online    = $false
            Reported  = $false
            Volume    = ""
            Protected = ""
            Percent   = ""
        }
    }

    $status = Get-BitLockerStatusRemote $ComputerName

    if ($status) {
        return [PSCustomObject]@{
            Timestamp = $timestamp
            Computer  = $ComputerName
            Online    = $true
            Reported  = $true
            Volume    = $status.VolumeStatus
            Protected = $status.ProtectionStatus
            Percent   = $status.EncryptionPercent
        }
    }
    else {
        return [PSCustomObject]@{
            Timestamp = $timestamp
            Computer  = $ComputerName
            Online    = $true
            Reported  = $false
            Volume    = "Error"
            Protected = ""
            Percent   = ""
        }
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

# =================================================
# MAIN FUNCTION
# =================================================
function Get-ADBitLockerReport {

<#
.SYNOPSIS
Retrieves BitLocker status for AD computers or a computer list.

.DESCRIPTION
Supports queue files, AD filters, parallel scanning in PS7+, CSV output, timestamps, and scheduler-friendly operation.

.PARAMETER Filter
Active Directory filter string (e.g., "Name -like 'LAB-*'").

.PARAMETER ComputerList
Path to a text file with computer names (one per line). Only online computers are commented out.

.PARAMETER OutputPath
Path to CSV file. Default: .\BitLocker_Report.csv

.PARAMETER Mode
"Append" to add to existing CSV, or "Overwrite" for fresh output. Default: Append

.PARAMETER ThrottleLimit
Number of computers to process in parallel (PS7+). Default: 20

.EXAMPLE
# Interactive AD filter
Get-ADBitLockerReport

.EXAMPLE
# AD filter with overwrite
Get-ADBitLockerReport -Filter "Name -like 'LIB-*'" -OutputPath "C:\Reports\BitLocker_Report.csv" -Mode Overwrite

.EXAMPLE
# Queue file mode for scheduled tasks
Get-ADBitLockerReport -ComputerList "C:\Scripts\computers.txt" -OutputPath "C:\Reports\BitLocker_Report.csv"

.EXAMPLE
# Parallel scanning with 30 threads (PS7+)
Get-ADBitLockerReport -Filter "Name -like 'LAB-*'" -ThrottleLimit 30
#>

    [CmdletBinding()]
    param(
        [string]$Filter,
        [string]$ComputerList,
        [string]$OutputPath = ".\BitLocker_Report.csv",
        [ValidateSet("Append","Overwrite")]
        [string]$Mode = "Append",
        [int]$ThrottleLimit = 20
    )

    $Results = @()

    # -----------------------------
    # Determine PS version for parallel
    # -----------------------------
    $UseParallel = $false
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $UseParallel = $true
        Write-Log "PowerShell 7+ detected, parallel scanning enabled."
    }
    else {
        Write-Log "PowerShell <7 detected, sequential scanning will be used."
    }

    # -----------------------------
    # QUEUE FILE MODE
    # -----------------------------
    if ($ComputerList) {

        if (-not (Test-Path $ComputerList)) {
            Write-Log "Computer list file not found: $ComputerList" "ERROR"
            exit 1
        }

        Write-Log "Using queue file: $ComputerList"

        $ComputersToProcess = Get-Content $ComputerList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }

        if (-not $ComputersToProcess) {
            Write-Log "No computers to process in queue."
            return
        }

        # -------------------------
        # PROCESS COMPUTERS
        # -------------------------
        if ($UseParallel) {
            # PS7+ parallel
            $Results = $ComputersToProcess | ForEach-Object -Parallel {
                param($ComputerName)
                function Test-DeviceOnline { param($ComputerName); Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue }
                function Get-BitLockerStatusRemote { param($ComputerName); try { Invoke-Command -ComputerName $ComputerName -ScriptBlock { $b = Get-BitLockerVolume -MountPoint "C:"; [PSCustomObject]@{VolumeStatus=$b.VolumeStatus; ProtectionStatus=$b.ProtectionStatus; EncryptionPercent=$b.EncryptionPercentage} } -ErrorAction Stop } catch { $null } }

                $timestamp = Get-Date
                $online = Test-DeviceOnline $ComputerName

                if (-not $online) {
                    [PSCustomObject]@{Timestamp=$timestamp;Computer=$ComputerName;Online=$false;Reported=$false;Volume="";Protected="";Percent=""}
                }
                else {
                    $status = Get-BitLockerStatusRemote $ComputerName
                    if ($status) {
                        [PSCustomObject]@{Timestamp=$timestamp;Computer=$ComputerName;Online=$true;Reported=$true;Volume=$status.VolumeStatus;Protected=$status.ProtectionStatus;Percent=$status.EncryptionPercent}
                    }
                    else {
                        [PSCustomObject]@{Timestamp=$timestamp;Computer=$ComputerName;Online=$true;Reported=$false;Volume="Error";Protected="";Percent=""}
                    }
                }

            } -ThrottleLimit $ThrottleLimit
        }
        else {
            # Sequential fallback
            foreach ($c in $ComputersToProcess) {
                $Results += Process-Computer -ComputerName $c
            }
        }

        # -------------------------
        # COMMENT OUT ONLY ONLINE COMPUTERS
        # -------------------------
        $OnlineComputers = $Results | Where-Object { $_.Online -eq $true } | Select-Object -ExpandProperty Computer

        $QueueContent = Get-Content $ComputerList
        $NewQueue = $QueueContent | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#") -and $OnlineComputers -contains $line) {
                "#$line"   # comment out only online computers
            }
            else {
                $_
            }
        }
        $NewQueue | Set-Content $ComputerList
    }

    # -----------------------------
    # AD FILTER MODE
    # -----------------------------
    else {

        if (-not $Filter) {
            $Filter = Read-Host "Enter AD filter (example: Name -like 'LAB-*')"
        }

        Write-Log "Querying AD with filter: $Filter"

        $Computers = Get-ADComputer -Filter $Filter | Select-Object -ExpandProperty Name

        if (-not $Computers) {
            Write-Log "No computers found for filter."
            return
        }

        if ($UseParallel) {
            $Results = $Computers | ForEach-Object -Parallel {
                param($ComputerName)
                function Test-DeviceOnline { param($ComputerName); Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue }
                function Get-BitLockerStatusRemote { param($ComputerName); try { Invoke-Command -ComputerName $ComputerName -ScriptBlock { $b = Get-BitLockerVolume -MountPoint "C:"; [PSCustomObject]@{VolumeStatus=$b.VolumeStatus; ProtectionStatus=$b.ProtectionStatus; EncryptionPercent=$b.EncryptionPercentage} } -ErrorAction Stop } catch { $null } }

                $timestamp = Get-Date
                $online = Test-DeviceOnline $ComputerName

                if (-not $online) {
                    [PSCustomObject]@{Timestamp=$timestamp;Computer=$ComputerName;Online=$false;Reported=$false;Volume="";Protected="";Percent=""}
                }
                else {
                    $status = Get-BitLockerStatusRemote $ComputerName
                    if ($status) {
                        [PSCustomObject]@{Timestamp=$timestamp;Computer=$ComputerName;Online=$true;Reported=$true;Volume=$status.VolumeStatus;Protected=$status.ProtectionStatus;Percent=$status.EncryptionPercent}
                    }
                    else {
                        [PSCustomObject]@{Timestamp=$timestamp;Computer=$ComputerName;Online=$true;Reported=$false;Volume="Error";Protected="";Percent=""}
                    }
                }

            } -ThrottleLimit $ThrottleLimit
        }
        else {
            foreach ($c in $Computers) {
                $Results += Process-Computer -ComputerName $c
            }
        }
    }

    # Export results
    Export-ResultsSafe -Results $Results -Path $OutputPath -Mode $Mode

    return $Results
}

Export-ModuleMember -Function Get-ADBitLockerReport
