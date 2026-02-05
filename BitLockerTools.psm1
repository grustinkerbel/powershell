<#
.SYNOPSIS
BitLocker Reporting and Status Module

.DESCRIPTION
This module provides reporting of BitLocker status for Active Directory computers or a provided computer list.
Supports:
- Queue file processing (comments out completed devices)
- AD filter mode
- CSV output (append or overwrite)
- Timestamped results
- Parallel scanning for speed (PowerShell 7+)
- Scheduler-friendly operation

.AUTHOR
Bill Galway (style + enhanced)

.EXAMPLE
# Interactive AD filter
Import-Module .\BitLockerTools.psm1
Get-ADBitLockerReport

.EXAMPLE
# AD filter with overwrite CSV
Get-ADBitLockerReport -Filter "Name -like 'LAB-*'" -OutputPath C:\Reports\BitLocker_Report.csv -Mode Overwrite

.EXAMPLE
# Scheduled task queue file
Get-ADBitLockerReport -ComputerList C:\Scripts\computers.txt -OutputPath C:\Reports\BitLocker_Report.csv

# ThrottleLimit default = 20 for parallel processing
# Make sure you are running PowerShell 7+ for parallel execution
#>
# ============================================

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
    catch {
        return $null
    }
}


# ----------------------------
# Core worker (single computer)
# ----------------------------
function Process-Computer {
    param(
        [string]$ComputerName
    )

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

    [CmdletBinding()]
    param(
        [string]$Filter,
        [string]$ComputerList,
        [string]$OutputPath = ".\BitLocker_Report.csv",
        [ValidateSet("Append","Overwrite")]
        [string]$Mode = "Append",
        [int]$ThrottleLimit = 20
    )

    # Array to hold results
    $Results = @()

    # -----------------------------
    # QUEUE FILE MODE
    # -----------------------------
    if ($ComputerList) {

        if (-not (Test-Path $ComputerList)) {
            Write-Log "Computer list file not found: $ComputerList" "ERROR"
            exit 1
        }

        Write-Log "Using queue file: $ComputerList"

        # Read queue and remove comments/blanks
        $ComputersToProcess = Get-Content $ComputerList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }

        if (-not $ComputersToProcess) {
            Write-Log "No computers to process in queue."
            return
        }

        # Parallel processing
        $Results = $ComputersToProcess | ForEach-Object -Parallel {
            param($ComputerName)

            # Import functions into parallel runspace
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

        # Comment out processed computers
        foreach ($c in $ComputersToProcess) {
            (Get-Content $ComputerList) | ForEach-Object {
                if ($_ -eq $c) { "#$_" } else { $_ }
            } | Set-Content $ComputerList
        }
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

        # Parallel processing
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

    # Export results
    Export-ResultsSafe -Results $Results -Path $OutputPath -Mode $Mode

    return $Results
}


Export-ModuleMember -Function Get-ADBitLockerReport
