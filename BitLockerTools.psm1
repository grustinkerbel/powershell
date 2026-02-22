<#
.SYNOPSIS
Generates a BitLocker status and recovery key compliance report for Active Directory computers.

.DESCRIPTION
Get-ADBitLockerReport queries domain-joined computers and collects:

• WinRM connectivity status
• BitLocker protection state
• Encryption percentage
• TPM presence and readiness
• Active Directory recovery key information

Optional remediation capabilities include:

• Automatically enabling BitLocker on eligible devices
• Backing up missing recovery keys to Active Directory
• Removing duplicate recovery password protectors
• Performing AD-only audits (no endpoint contact required)

Results are returned to the pipeline and exported to CSV.

This cmdlet supports -WhatIf and -Confirm for safe remediation execution.

.PARAMETER Filter
Active Directory filter string in standard PowerShell AD syntax.

This parameter is passed directly to Get-ADComputer -Filter.

Examples:
    "Name -like 'LT-*'"
    "Enabled -eq 'True'"
    "OperatingSystem -notlike '*Server*'"
    "Name -like 'LAB-*' -and Enabled -eq 'True'"

Default: "*"

NOTE:
This is NOT LDAP filter syntax.

.PARAMETER ComputerList
Path to a text file containing one computer name per line.
Lines beginning with # are ignored.

Useful for queue-based processing or retry batches.

.PARAMETER OutputPath
Path to the CSV report file.

Default: .\BitLocker_Report.csv

.PARAMETER Mode
Controls CSV export behavior.

Append     – Adds to existing file
Overwrite  – Replaces existing file

Default: Append

.PARAMETER ThrottleLimit
Maximum number of parallel threads when running under PowerShell 7+.

Default: 20

.PARAMETER IncludeRecoveryKey
Includes the most recent BitLocker recovery password stored in AD
in the exported report.

WARNING:
Recovery passwords are exported in plaintext.


.PARAMETER ADOnly
Performs an Active Directory–only audit of recovery key presence.
Skips WinRM connectivity and endpoint inspection.

.PARAMETER AutoEnableBitLocker
Automatically enables BitLocker on eligible machines where:

• BitLocker is not already enabled
• TPM is present
• TPM is ready

Supports -WhatIf and -Confirm.

.PARAMETER CleanupProtectors
Removes older duplicate recovery password protectors,
keeping only the newest protector.

Supports -WhatIf and -Confirm.

.EXAMPLE
Get-ADBitLockerReport

Runs against all domain computers (Filter defaults to "*")
and exports a BitLocker compliance report.

.EXAMPLE
Get-ADBitLockerReport -Filter "Name -like 'LT-*'"

Reports on all laptop devices.

.EXAMPLE
Get-ADBitLockerReport -Filter "Enabled -eq 'True'"

Processes only enabled AD computer accounts.

.EXAMPLE
Get-ADBitLockerReport -Filter "OperatingSystem -notlike '*Server*'"

Reports on non-server Windows devices.

.EXAMPLE
Get-ADBitLockerReport -Filter "Name -like 'LT-*'" -IncludeRecoveryKey

Reports on laptops and includes AD recovery passwords.

.EXAMPLE
Get-ADBitLockerReport -Filter "Name -like 'LT-*'" `
    -AutoEnableBitLocker `
    -WhatIf

Shows what would happen if BitLocker were enabled
without making changes.

.EXAMPLE
Get-ADBitLockerReport -Filter "Name -like 'LT-*'" `
    -AutoEnableBitLocker `
    -CleanupProtectors `
    -IncludeRecoveryKey `
    -Mode Overwrite `
    -Confirm:$false

Full remediation mode:
• Enables BitLocker where eligible
• Removes duplicate protectors
• Includes recovery passwords
• Overwrites existing report

.EXAMPLE
Get-ADBitLockerReport -ComputerList .\queue.txt

Processes only machines listed in queue.txt
and attempts to escrow missing recovery keys.

.EXAMPLE
Get-ADBitLockerReport -ADOnly -IncludeRecoveryKey

Performs an AD-only recovery key audit without contacting endpoints.

.OUTPUTS
PSCustomObject with properties:

Timestamp
Computer
Online
Reported
Volume
Protected
Percent
RecoveryKeyID
RecoveryPassword
ADVerified
TPMPresent
TPMReady
CanEnableBitLocker

.NOTES
Author: Bill Galway
Module: BitLockerTools
Version: 2.0 (Hardened)

Requires:
• ActiveDirectory module
• BitLocker cmdlets
• WinRM enabled on target systems
• PowerShell 7+ recommended for parallel processing

Supports:
• -WhatIf
• -Confirm
• Parallel execution
• Safe CSV export
#>
# --- BitlockerRecoveryTools_v14.psm1 ---

# Store the path to THIS file so it's always accurate regardless of where it's saved
$Global:BitLockerModulePath = Join-Path -Path $PSScriptRoot -ChildPath "BitlockerRecoveryTools_v23.psm1"
function Get-ADBitLockerReport {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param(
        [Parameter(ParameterSetName = "ADFilter")][string]$Filter = "*",
        [Parameter(ParameterSetName = "FileList")][string]$ComputerList,
        [string]$OutputPath = ".\BitLocker_Report.csv",
        [ValidateSet("Append", "Overwrite")][string]$Mode = "Append",
        [int]$ThrottleLimit = 20,
        [switch]$IncludeRecoveryKey,
        [switch]$ADOnly,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupProtectors
    )

    process {
        # Determine computer list (AD or File)
        $Computers = if ($PSCmdlet.ParameterSetName -eq "FileList") {
            Get-Content $ComputerList | Where-Object { $_ -and -not $_.StartsWith("#") }
        } else {
            Get-ADComputer -Filter $Filter | Select-Object -ExpandProperty Name
        }

        if (-not $Computers) { return }

        # Capture the global path variable into the local scope so $using: can find it
        $CurrentModulePath = $Global:BitLockerModulePath

        Write-Host "Starting parallel processing using: $CurrentModulePath" -ForegroundColor Cyan

        # --- Parallel processing ---
        $Results = $Computers | ForEach-Object -Parallel {
            Import-Module $using:CurrentModulePath -Force
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue

            Invoke-ComputerProcess `
                -ComputerName $_ `
                -IncludeRecoveryKey:$using:IncludeRecoveryKey `
                -ADOnly:$using:ADOnly `
                -AutoEnableBitLocker:$using:AutoEnableBitLocker `
                -CleanupProtectors:$using:CleanupProtectors
        } -ThrottleLimit $ThrottleLimit

        # --- Export BitLocker report ---
        if ($Results) {
            $ExportArgs = @{ Path = $OutputPath; NoTypeInformation = $true }
            if ($Mode -eq "Append") { $ExportArgs.Append = $true } else { $ExportArgs.Force = $true }
            $Results | Export-Csv @ExportArgs
        }

        # --- Export unreachable computers (idempotent) ---
        $NotContactedPath = Join-Path -Path (Split-Path $OutputPath) -ChildPath "NotContacted_Computers.txt"

        # Ensure file exists
        if (-not (Test-Path $NotContactedPath)) { New-Item -Path $NotContactedPath -ItemType File | Out-Null }

        # Load existing entries
        $existing = Get-Content $NotContactedPath -ErrorAction SilentlyContinue

        # Get new unreachable computers that aren’t already in the file
        $newUnreachable = $Results |
            Where-Object { $_.Online -eq $false } |
            Select-Object -ExpandProperty Computer |
            Where-Object { $_ -and ($existing -notcontains $_) } |
            Sort-Object

        # Append new entries
        if ($newUnreachable) {
            $newUnreachable | Out-File -FilePath $NotContactedPath -Encoding UTF8 -Append
            Write-Host "Added $($newUnreachable.Count) new unreachable computers to $NotContactedPath" -ForegroundColor Yellow
        } else {
            Write-Host "No new unreachable computers to add." -ForegroundColor Green
        }

        # Return full results
        return $Results
    }
}



# ----------------------------
# Logging helper
# ----------------------------
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$ComputerName
    )

    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if ($ComputerName) {
        $line = "[$time][$Level][$ComputerName] $Message"
    }
    else {
        $line = "[$time][$Level] $Message"
    }

    Write-Host $line

    $logPath = ".\BitlockerTools.log"
    $mutexName = "Global\ARDScriptsLogMutex"
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)

    try {
        $null = $mutex.WaitOne()
        Add-Content -Path $logPath -Value $line -Encoding UTF8 | Out-Null
    }
    finally {
        $null = $mutex.ReleaseMutex()
        $mutex.Dispose() | Out-Null
    }
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

    Write-Log "Starting Remote BitLocker Status Query" -ComputerName $ComputerName

    try {
        $Status = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $b = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
                [PSCustomObject]@{
                    VolumeStatus      = $b.VolumeStatus
                    ProtectionStatus  = $b.ProtectionStatus
                    EncryptionPercent = $b.EncryptionPercentage
                }
            }
            catch {
                Write-Error "Failed to get BitLocker volume on remote system: $($_.Exception.Message)"
                return $null
            }
        } -ErrorAction Stop

        if ($Status) {
            Write-Log "Successfully retrieved BitLocker status" -ComputerName $ComputerName
        } else {
            Write-Log "No BitLocker status returned  " -ComputerName $ComputerName
        } 

        return $Status
    }
    catch {
        Write-Log "ERROR: Remote BitLocker query failed   - $($_.Exception.Message)" -ComputerName $ComputerName
        return $null
    }
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
        $Comp = Get-ADComputer -Identity $ComputerName -ErrorAction Stop

        Write-Log "Found computer: $($Comp.DistinguishedName)" -ComputerName $ComputerName

        $RecoveryObjects = Get-ADObject `
            -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
            -SearchBase $Comp.DistinguishedName `
            -Properties 'msFVE-RecoveryPassword' `
            -ErrorAction Stop

        $KeyCount = ($RecoveryObjects | Measure-Object).Count
        Write-Log "Found $KeyCount Escrowed AD BitLocker recovery key(s)" -ComputerName $ComputerName

        return $RecoveryObjects | ForEach-Object {
            [PSCustomObject]@{
                Computer         = $ComputerName
                RecoveryKeyID    = $_.ObjectGUID.ToString().Trim('{}')
                RecoveryPassword = ($_. 'msFVE-RecoveryPassword').ToString().Trim()
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to get BitLocker keys   - $($_.Exception.Message)" -ComputerName $ComputerName
        return @()
    }
}


# ----------------------------
# Enable Bitlocker
# ----------------------------
function Enable-BitLockerRemote {
    param([string]$ComputerName)

    Write-Log "Starting Enable BitLocker Remote" -ComputerName $ComputerName

    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {

            $mount = "C:"
            $rebootRequired = $false

            $vol = Get-BitLockerVolume -MountPoint $mount | Select-Object -First 1
            if ($null -eq $vol) {
                throw "Volume $mount not found"
            }

            # Resume if suspended
            if ($vol.VolumeStatus -eq "Suspended") {
                Resume-BitLocker -MountPoint $mount
                Start-Sleep 3
            }

            # Enable BitLocker
            if ($vol.ProtectionStatus -eq "Off") {

                Enable-BitLocker -MountPoint $mount `
                                 -EncryptionMethod XtsAes256 `
                                 -RecoveryPasswordProtector `
                                 -Confirm:$false | Out-Null
            }

        } -ErrorAction Stop | Select-Object -First 1
      
        return $result
    }
    catch {
        $errorMsg = $_.Exception.Message
            Write-Log "Failed to enable BitLocker on $ComputerName : $errorMsg" -Level ERROR -ComputerName $ComputerName
    }
}




# ----------------------------
# Remove extra recovery protectors (keep newest)
# ----------------------------

function Remove-ExtraBitLockerProtectors {
    param([string]$ComputerName)

    try {
        # 1. REMOTELY: Get the newest key and trigger a backup to AD
        $remoteResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $mount = "C:"
            $vol = Get-BitLockerVolume -MountPoint $mount | Select-Object -First 1
            $passwords = @($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" })

            if ($passwords.Count -le 1) { return $null } # Nothing to clean

            # Identify newest
            $keep = $passwords | Sort-Object CreationTime -Descending | Select-Object -First 1
            
            # Trigger Backup to AD just in case
            Backup-BitLockerKeyProtector -MountPoint $mount -KeyProtectorId $keep.KeyProtectorId | Out-Null
            
            return @{
                KeepID = $keep.KeyProtectorId
                AllIDs = $passwords.KeyProtectorId
            }
        }

        if ($null -eq $remoteResult) { return }

        # 2. LOCALLY: Verify the "KeepID" exists in AD before deleting others
        # Requires ActiveDirectory module on your admin machine
        $adObject = Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
                                 -Properties msFVE-RecoveryGuid `
                                 -SearchBase (Get-ADComputer $ComputerName).DistinguishedName |
                    Where-Object { $_.Name -like "*$($remoteResult.KeepID)*" }

        if ($adObject) {
            Write-Log "Verified: Newest key found in AD. Proceeding with cleanup." -ComputerName $ComputerName
            
            # 3. REMOTELY: Delete everything except the verified KeepID
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($KeepID, $AllIDs)
                foreach ($id in $AllIDs) {
                    if ($id -ne $KeepID) {
                        Remove-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $id
                    }
                }
            } -ArgumentList $remoteResult.KeepID, $remoteResult.AllIDs
        }
        else {
            Write-Log "ABORT: Newest key   NOT found in AD. Cleanup skipped for safety." "WARN" -ComputerName $ComputerName
        }
    }
    catch {
        Write-Log "Cleanup failed on $ComputerName : $_" "ERROR" -ComputerName $ComputerName
    }
}



# ----------------------------
# Backup & Verify BitLocker Key in AD
# ----------------------------
function Backup-AndVerifyBitLockerKey {
    param(
        [string]$ComputerName,
        [string]$MountPoint = "C:",
        [switch]$IncludeRecoveryKey
    )

    Write-Log "Determining newest BitLocker recovery key" -ComputerName $ComputerName

    # Retrieve newest protector AND password inside remote session
    $NewestProtector = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $vol = Get-BitLockerVolume -MountPoint "C:"
        $p = $vol.KeyProtector |
            Where-Object KeyProtectorType -eq "RecoveryPassword" |
            Sort-Object CreationTime -Descending |
            Select-Object -First 1

        # Return a clean object with real values BEFORE deserialization
        [PSCustomObject]@{
            KeyProtectorId   = $p.KeyProtectorId
            RecoveryPassword = $p.RecoveryPassword
        }
    }

    if (-not $NewestProtector) {
        Write-Log "ERROR: No RecoveryPassword protector found" -Level "ERROR" -ComputerName $ComputerName
        return
    }

    $RecoveryKeyID    = $NewestProtector.KeyProtectorId.ToString().Trim('{}')
    $RecoveryPassword = $NewestProtector.RecoveryPassword
    $ADVerified       = $false

    Write-Log "Starting backup of newest BitLocker recovery key   (ID: $RecoveryKeyID)" -ComputerName $ComputerName

    try {
        # Backup the newest protector
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($MP, $KPID)
            Backup-BitLockerKeyProtector -MountPoint $MP -KeyProtectorId $KPID
        } -ArgumentList $MountPoint, $NewestProtector.KeyProtectorId -ErrorAction Stop

        Start-Sleep -Seconds 15

        # Verify in AD
        $comp = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
        $adObjs = Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
                               -SearchBase $comp.DistinguishedName `
                               -Properties 'msFVE-RecoveryPassword' -ErrorAction Stop

        if ($adObjs.'msFVE-RecoveryPassword' -contains $RecoveryPassword) {
            $ADVerified = $true
            Write-Log "Escrowed Recovery key verified in AD" -ComputerName $ComputerName
        }
        else {
            Write-Log "Recovery key NOT found in AD after backup  !" -Level "WARN" -ComputerName $ComputerName
        }
    }
    catch {
        Write-Log "ERROR: Failed to back up/verify   : $($_.Exception.Message)" -Level "ERROR" -ComputerName $ComputerName
    }

    # Construct result
    $properties = [ordered]@{
        RecoveryKeyID = $RecoveryKeyID
        ADVerified    = $ADVerified
    }
    
    if ($IncludeRecoveryKey) {
        $properties.RecoveryPassword = $RecoveryPassword
    }
    return [PSCustomObject]$properties
}

function Get-CVolumeRecoveryKeyCount {
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [switch]$Raw
    )

    # How many times to retry when WMI/manage-bde return stale data
    $maxRetries = 3
    $retryDelay = 3  # seconds

    function Get-WmiProtectorCount {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $vol = Get-BitLockerVolume -MountPoint 'C:'
                $count = ($vol.KeyProtector |
                          Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).Count

                [PSCustomObject]@{
                    Count            = $count
                    ProtectionStatus = $vol.ProtectionStatus
                }
            }
            catch {
                [PSCustomObject]@{
                    Count            = $null
                    ProtectionStatus = $null
                }
            }
        }
    }

    function Get-BdeProtectorCount {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $output = manage-bde -protectors -get C: | Out-String
                $count = ($output | Select-String "Numerical Password").Count
                return $count
            }
            catch {
                return $null
            }
        }
    }

    # -----------------------------
    # RETRY LOOP
    # -----------------------------
    for ($i = 1; $i -le $maxRetries; $i++) {

        $wmi = Get-WmiProtectorCount

        # If WMI is good, use it
        if ($wmi.Count -gt 0 -and $wmi.ProtectionStatus -eq 'On') {
            $keyCount = $wmi.Count
            break
        }

        # If WMI says Off or null, try manage-bde
        $bde = Get-BdeProtectorCount

        if ($bde -gt 0) {
            $keyCount = $bde
            break
        }

        # If both failed, retry
        if ($i -lt $maxRetries) {
            Write-Log "[$ComputerName] Protector count stale (attempt $i). Retrying in $retryDelay seconds..." -ComputerName $ComputerName
            Start-Sleep -Seconds $retryDelay
        }
    }

    # If still null, treat as 0
    if (-not $keyCount) { $keyCount = 0 }

    # -----------------------------
    # Return object
    # -----------------------------
    $obj = [PSCustomObject]@{
        ComputerName = $ComputerName
        Drive        = 'C:'
        RecoveryKeys = $keyCount
        Status       = $wmi.ProtectionStatus
    }

    if ($Raw) { return $obj }

    $obj | Format-Table -AutoSize
}

#--------------------------
# Bitlocker Remediation
#---------------------------

function Invoke-BitLockerRemediation {
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ComputerName,
        [bool]$CanEnableBitLocker,
        [int]$ProtectionStatus,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupProtectors,
        [bool]$ADVerified,
        [array]$EscrowedADKey
    )

    # Temporary working variables (NOT the final result)
    $Final_ADVerified       = $ADVerified
    $Final_RecoveryKeyID    = $null
    $Final_RecoveryPassword = $null
    $Final_VolumeStatus     = $null
    $Final_ProtectionStatus = $ProtectionStatus
    $Final_Percent          = $null

    # ----------------------------------------------------
    # CHECK EXISTING RECOVERY KEYS ON C:
    # ----------------------------------------------------

    $keyInfo = Get-CVolumeRecoveryKeyCount -ComputerName $ComputerName -Raw
	
	$MachineKeyCount = $keyInfo.RecoveryKeys
    $ADKeyCount      = if ($ADKeys) { $ADKeys.Count } else { 0 }


    if ($keyInfo.RecoveryKeys -gt 0) {
         $CanEnableBitLocker = $false
    }
    else {
        Write-Log "No existing RecoveryPassword protectors found on C:. AutoEnableBitLocker may proceed" -ComputerName $ComputerName
    }

    # ----------------------------------------------------
    # ENABLE BITLOCKER
    # ----------------------------------------------------

    if ($AutoEnableBitLocker -and $CanEnableBitLocker) {
        Write-Log "AutoEnableBitLocker is enabled and machine can be encrypted" -ComputerName $ComputerName

        if ($PSCmdlet.ShouldProcess($ComputerName,"Enable BitLocker")) {

            $enable = Enable-BitLockerRemote -ComputerName $ComputerName
            Write-Log "Enable-BitLockerRemote returned status: $($enable.Status)" -ComputerName $ComputerName

            if ($enable.Status -eq "Success") {
                $Final_RecoveryKeyID    = $enable.RecoveryKeyID
                $Final_RecoveryPassword = $enable.RecoveryPassword
                $Final_ADVerified       = $enable.ADVerified
                $Final_VolumeStatus     = $enable.VolumeStatus
                $Final_ProtectionStatus = $enable.ProtectionStatus
                $Final_Percent          = $enable.Percent
            }
        }
    }

    # ----------------------------------------------------
    # CLEANUP DUPLICATE PROTECTORS
    # ----------------------------------------------------

    if ($CleanupProtectors) {
        Write-Log "Cleaning up duplicate protectors" -ComputerName $ComputerName

        if ($PSCmdlet.ShouldProcess($ComputerName,"Remove additional recovery protectors")) {
            Remove-ExtraBitLockerProtectors -ComputerName $ComputerName
            Write-Log "Cleanup completed" -ComputerName $ComputerName
        }
    }

    # ----------------------------------------------------
    # BACKUP MISSING AD KEY
    # ----------------------------------------------------

    if (-not $Final_ADVerified) {
        Write-Log "Backing up missing AD recovery key " -ComputerName $ComputerName

        $backupResult = Backup-AndVerifyBitLockerKey `
            -ComputerName $ComputerName `
            -IncludeRecoveryKey

        # Assign clean values
        $Final_ADVerified       = $backupResult.ADVerified
        $Final_RecoveryKeyID    = $backupResult.RecoveryKeyID
        $Final_RecoveryPassword = $backupResult.RecoveryPassword
    }

    return [PSCustomObject]@{
        ADVerified       = $Final_ADVerified
        RecoveryKeyID    = $Final_RecoveryKeyID
        RecoveryPassword = $Final_RecoveryPassword
        VolumeStatus     = $Final_VolumeStatus
        ProtectionStatus = $Final_ProtectionStatus
        Percent          = $Final_Percent
    }
}

# ----------------------------
# Core worker (single computer)
# ----------------------------
function Invoke-ComputerProcess {

    param(
        [string]$ComputerName,
        [switch]$IncludeRecoveryKey,
        [switch]$ADOnly,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupProtectors
    )

    $timestamp = Get-Date
    $WinRM     = $false
    $online    = $false
    $ADVerified = $false

    $VolumeStatus = ""
    $ProtectionStatus = $null
    $Percent = 0
    $RecoveryPassword = $null
    $RecoveryKeyID = $null
    $TPMPresent = $false
    $TPMReady = $false
    $CanEnableBitLocker = $false
    $ADKeys = $null
    $ADKeys = $null

    if (-not $ADOnly) {

        try {
            Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
            $WinRM = $true
            $online = $true
        }
        catch {
            Write-Verbose "$ComputerName unreachable via WinRM."
        }

        if (-not $WinRM) {
            return [PSCustomObject]@{
                Timestamp          = $timestamp
                Computer           = $ComputerName
                Online             = $false
                Reported           = $false
                Volume             = ""
                Protected          = ""
                Percent            = ""
                RecoveryKeyID      = ""
                RecoveryPassword   = ""
                ADVerified         = $false
                TPMPresent         = $false
                TPMReady           = $false
                CanEnableBitLocker = $false
            }
        }

        # ----------------------------------------------------
        # STATUS COLLECTION
        # ----------------------------------------------------
        $status  = Get-BitLockerStatusRemote $ComputerName
		
        if ($status) {
            $VolumeStatus     = $status.VolumeStatus
            $ProtectionStatus = $status.ProtectionStatus
            $Percent          = $status.EncryptionPercent
        }

        # ----------------------------------------------------
        # Query AD once and cache result
        # ----------------------------------------------------
        $ADKeys = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName

        # ----------------------------------------------------
        # Validate AD escrow integrity
        # ----------------------------------------------------

       if ($ProtectionStatus -eq 1 -and $ADKeys) {
        
            Write-Log "Validating Escrowed AD Recovery Key integrity " -ComputerName $ComputerName
            $localProtector = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $vol = Get-BitLockerVolume -MountPoint "C:"
                $vol.KeyProtector |
                    Where-Object KeyProtectorType -eq "RecoveryPassword" |
                    Sort-Object CreationTime -Descending |
                    Select-Object -First 1
				
            }

            if ($localProtector) {
                $localPassword = $localProtector.RecoveryPassword
                $adPasswords   = $ADKeys.RecoveryPassword
        
                if ($adPasswords -contains $localPassword) {
                    $ADVerified = $true
                    Write-Log "Escrowed AD Key matches local Recovery Key" -ComputerName $ComputerName
                }
                else {
                    $ADVerified = $false
                    Write-Log "Escrowed AD Key does NOT match local Recovery Key" "WARN" -ComputerName $ComputerName
                }
            }
        }		
		
        $TPMInfo = Test-TPM -ComputerName $ComputerName

        if ($TPMInfo) {
            $TPMPresent = $TPMInfo.TpmPresent
            $TPMReady   = $TPMInfo.TpmReady
        }

        $CanEnableBitLocker =
            ($ProtectionStatus -ne 1) -and
            $TPMPresent -and
            $TPMReady

        # ----------------------------------------------------
        # REMEDIATION
        # ----------------------------------------------------
        $params_remediation = @{
            ComputerName               = $ComputerName
            CanEnableBitLocker         = $CanEnableBitLocker
            ProtectionStatus           = $ProtectionStatus
            AutoEnableBitLocker        = $AutoEnableBitLocker
            CleanupProtectors          = $CleanupProtectors
            ADVerified                 = $ADVerified
            EscrowedADKey              = $ADKeys
		}
		
        $remediation = Invoke-BitLockerRemediation @params_remediation
        if ($remediation) {
            $ADVerified = $remediation.ADVerified
            
            # Only expose keys if -IncludeRecoveryKey was used
            if ($IncludeRecoveryKey) {
                $RecoveryKeyID    = $remediation.RecoveryKeyID
                $RecoveryPassword = $remediation.RecoveryPassword
            }
        }
    }

    # ----------------------------------------------------
    # Optional Recovery Key Export (reuse cached $ADKeys)
    # ----------------------------------------------------
    if ($IncludeRecoveryKey -and -not $RecoveryPassword -and $ADKeys) {
        $RecoveryKeyID    = $ADKeys.RecoveryKeyID
        $RecoveryPassword = $ADKeys.RecoveryPassword
    }

    # --- Normalize values BEFORE building object ---
    if ($RecoveryKeyID -is [array]) { $RecoveryKeyID = $RecoveryKeyID | Where-Object { $_ } | Select-Object -Last 1 }
    if ($RecoveryPassword -is [array]) { $RecoveryPassword = $RecoveryPassword | Where-Object { $_ } | Select-Object -Last 1 }

    $ADVerified = [bool]$ADVerified

    $keyInfo = Get-CVolumeRecoveryKeyCount -ComputerName $ComputerName -Raw
    $MachineKeyCount = $keyInfo.RecoveryKeys
    $ADKeyCount      = if ($ADKeys) { $ADKeys.Count } else { 0 }


    return [PSCustomObject]@{
        Timestamp          = $timestamp
        Computer           = $ComputerName
        Online             = if($ADOnly){$null}else{$online}
        Reported           = if($ADOnly){$null}else{$WinRM}
        Volume             = $VolumeStatus
        Protected          = $ProtectionStatus
        Percent            = $Percent
		RecoveryKeyID      = if ($IncludeRecoveryKey) { $RecoveryKeyID } else { $null }
        RecoveryPassword   = if ($IncludeRecoveryKey) { $RecoveryPassword } else { $null }
		MachineKeyCount    = $MachineKeyCount
        ADKeyCount         = $ADKeyCount
        ADVerified         = $ADVerified
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

    # 1. Standardize and Flatten (Ensures no System.Object[] arrays)
    $CleanedResults = $Results | ForEach-Object {
        [PSCustomObject]@{
            Timestamp          = $_.Timestamp
            Computer           = $_.Computer
            Online             = $_.Online
            Reported           = $_.Reported
            Volume             = $_.Volume
            Protected          = $_.Protected
            Percent            = $_.Percent
            RecoveryKey        = $_.RecoveryKeyID
			RecoveryPassword   = $_.RecoveryPassword 
			MachineKeyCount    = $_.MachineKeyCount
			ADKeyCount         = $_.ADKeyCount
            ADVerified         = $_.ADVerified
            TPMPresent         = $_.TPMPresent
            TPMReady           = $_.TPMReady
            CanEnableBitLocker = $_.CanEnableBitLocker
        }
    }

    # 2. Handle Export logic
    if ($Mode -eq "Overwrite") {
        Write-Log "Overwriting report $Path"
        # Sort chronologically before overwrite
        $CleanedResults | Sort-Object Timestamp | Export-Csv $Path -NoTypeInformation
    }
    else {
        if (Test-Path $Path) {
            Write-Log "Appending to existing report $Path"
            # Append doesn't support sorting the whole file, but we sort the NEW batch
            $CleanedResults | Sort-Object Timestamp | Export-Csv $Path -NoTypeInformation -Append
        }
        else {
            Write-Log "Creating new report $Path"
            $CleanedResults | Sort-Object Timestamp | Export-Csv $Path -NoTypeInformation
        }
    }
}

Export-ModuleMember -Function `
    Get-ADBitLockerReport, `
    Invoke-ComputerProcess, `
    Get-BitLockerStatusRemote, `
    Test-TPM, `
    Invoke-BitLockerRemediation, `
    Get-CVolumeRecoveryKeyCount, `
    Write-Log
