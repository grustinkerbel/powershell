<#
.SYNOPSIS
Generates a BitLocker status and recovery key compliance report for Active Directory computers
using parallel processing.

.DESCRIPTION
Invoke-BitLockerParallel queries domain-joined computers and collects:

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
Parallel execution is optimized for PowerShell 7+ using ForEach-Object -Parallel.

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
• No existing Machine RecoveryPassword protector exists

Supports -WhatIf and -Confirm.

.PARAMETER CleanupProtectors
Removes older duplicate recovery password protectors,
keeping only the newest protector.

Supports -WhatIf and -Confirm.

.EXAMPLE
Invoke-BitLockerParallel

Runs against all domain computers (Filter defaults to "*")
and exports a BitLocker compliance report.

.EXAMPLE
Invoke-BitLockerParallel -Filter "Name -like 'LT-*'"

Reports on all laptop devices.

.EXAMPLE
Invoke-BitLockerParallel -ComputerList .\queue.txt

Processes only machines listed in queue.txt
and attempts to escrow missing recovery keys.

.EXAMPLE
Invoke-BitLockerParallel -ADOnly -IncludeRecoveryKey

Performs an AD-only recovery key audit without contacting endpoints.

.EXAMPLE
Invoke-BitLockerParallel -Filter "Name -like 'LT-*'" `
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
• Parallel execution with ForEach-Object -Parallel
• Safe CSV export
#>
function Invoke-BitLockerParallel {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param(
        [Parameter(ParameterSetName="AD")]
        [string]$Filter = "*",

        [Parameter(ParameterSetName="File")]
        [string]$ComputerList,

        [string]$OutputPath = ".\BitLocker_Report.csv",

        [ValidateSet("Append","Overwrite")]
        [string]$Mode = "Append",

        [int]$ThrottleLimit = 20,

        [switch]$IncludeRecoveryKey,
        [switch]$ADOnly,
        [switch]$AutoEnableBitLocker,
        [switch]$CleanupProtectors
    )

    # --------------------------------------------------
    # 1️⃣ Build Computer List
    # --------------------------------------------------
    if ($PSCmdlet.ParameterSetName -eq "File") {
        $Computers = Get-Content $ComputerList |
                     ForEach-Object { $_.Trim() } |
                     Where-Object { $_ -and -not $_.StartsWith("#") }
    }
    else {
        $Computers = Get-ADComputer -Filter $Filter |
                     Select-Object -ExpandProperty Name
    }

    if (-not $Computers) {
        Write-Log "No computers found to process."
        return
    }

    Write-Log "Starting parallel BitLocker processing for $($Computers.Count) computers."

    # --------------------------------------------------
    # 2️⃣ Parallel Processing
    # --------------------------------------------------
    $Results = $Computers | ForEach-Object -Parallel {
    
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        Import-Module C:\bat\BitlockerRecoveryTools\BitlockerRecoveryTools -Force
    
        $ComputerName = $_
        $IncludeKey   = $using:IncludeRecoveryKey
        $ADOnlyFlag   = $using:ADOnly
        $AutoEnable   = $using:AutoEnableBitLocker
        $CleanupFlag  = $using:CleanupProtectors
    
        Write-Log "DEBUG: Loaded module version: $((Get-Module BitlockerRecoveryTools).Version)" -ComputerName $ComputerName
    
        try {
        
            # ----------------------------
            # AD‑Only Mode
            # ----------------------------
            if ($ADOnlyFlag) {
                $ADKeys = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName
                $ADKeyCount = if ($ADKeys) { $ADKeys.Count } else { 0 }
        
                return [PSCustomObject]@{
                    Timestamp          = Get-Date
                    Computer           = $ComputerName
                    Online             = $null
                    Reported           = $false
                    Volume             = "C:"
                    Protected          = $null
                    Percent            = $null
                    MachineKeyCount    = 0
                    ADKeyCount         = $ADKeyCount
                    ADVerified         = $false
                    RecoveryKeyID      = $null
                    RecoveryPassword   = $null
                    TPMPresent         = $null
                    TPMReady           = $null
                    CanEnableBitLocker = $false
                }
            }
        
            # ----------------------------
            # Connectivity Test
            # ----------------------------
            $conn = Test-ComputerConnectivity -ComputerName $ComputerName
            if (-not $conn.Online) { throw "Offline: $($conn.Reason)" }
            if (-not $conn.WinRM)  { throw "WinRM unavailable: $($conn.Reason)" }
        
            # ----------------------------
            # Remote BitLocker Snapshot
            # ----------------------------
            $status = Get-BitLockerSnapshotRemote -ComputerName $ComputerName
            if (-not $status) { throw "Failed to retrieve BitLocker snapshot" }
        
            # ----------------------------
            # AD Recovery Keys
            # ----------------------------
            $ADKeys      = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName
            $ADPasswords = if ($ADKeys) { $ADKeys.RecoveryPassword } else { @() }
            $ADKeyCount  = $ADPasswords.Count
        
            # ----------------------------
            # TPM Status
            # ----------------------------
            $tpm = Test-TPM -ComputerName $ComputerName
            
            # ----------------------------
            # Determine Enable Eligibility
            # ----------------------------
			
			# Only get MachineKeyCount from Get-CVolumeRecoveryKeyCount
            $keyInfo = Get-CVolumeRecoveryKeyCount -ComputerName $ComputerName
            $MachineKeyCount = if ($keyInfo) { $keyInfo.Count } else { 0 }
			
            # Only enable BitLocker if MachineKeyCount is 0
            $CanEnable = ($MachineKeyCount -eq 0)
            Write-Log "DEBUG: AutoEnable=$AutoEnable  CanEnable=$CanEnable  MachineKeyCount=$MachineKeyCount" -ComputerName $ComputerName
            
            # ----------------------------
            # Optional Auto-Enable
            # ----------------------------
            $BitLockerJustEnabled = $false
            if ($AutoEnable -and $CanEnable) {
                if ($PSCmdlet.ShouldProcess($ComputerName, "Enable BitLocker")) {
                    $EnableResult = Enable-BitLockerRemote -ComputerName $ComputerName
                    if ($EnableResult -and $EnableResult.ProtectionStatus -ne "Off") {
                        $BitLockerJustEnabled = $true
                        Start-Sleep -Seconds 5
                        # Refresh snapshot after enable
                        $status = Get-BitLockerSnapshotRemote -ComputerName $ComputerName
                    }
                }
            }
            else {
                Write-Log "Skipping BitLocker enable because MachineKeyCount > 0 or AutoEnable disabled" -ComputerName $ComputerName
            }
        
            # ----------------------------
            # Determine newest local RecoveryPassword protector
            # ----------------------------
            $NewestProtector = $status.NewestRecovery
            if ($NewestProtector) {
                Write-Log "Newest local RecoveryPassword protector ID: $($NewestProtector.KeyProtectorId)" -ComputerName $ComputerName
            } else {
                Write-Log "No local RecoveryPassword protectors found" -Level "WARN" -ComputerName $ComputerName
            }
        
            # ----------------------------
            # Remove Password Protectors Keep Newest
            # ----------------------------
            if ($CleanupFlag) {
                Remove-ExtraBitLockerProtectors -ComputerName $ComputerName -PSCmdlet $PSCmdlet
            }
        
            # ----------------------------
            # Backup & Verify (safe logic)
            # ----------------------------
            $BackupResult = $null
        
            if ($NewestProtector -and
                -not [string]::IsNullOrWhiteSpace($NewestProtector.RecoveryPassword)) {
        
                $localKey = $NewestProtector.RecoveryPassword
                $IsEscrowed = $ADPasswords -contains $localKey
        
                if (-not $IsEscrowed -or $BitLockerJustEnabled) {
                    Write-Log "Backing up BitLocker recovery key" -Level "WARN" -ComputerName $ComputerName
        
                    $BackupResult = Backup-AndVerifyBitLockerKey `
                                        -ComputerName $ComputerName `
                                        -IncludeRecoveryKey:$IncludeKey
                }
                else {
                    Write-Log "Local key already escrowed to AD" -ComputerName $ComputerName
        
                    $BackupResult = [PSCustomObject]@{
                        ADVerified       = $true
                        RecoveryKeyID    = $NewestProtector.KeyProtectorId.ToString().Trim('{}')
                        RecoveryPassword = if ($IncludeKey) { $localKey } else { $null }
                    }
                }
            }
            else {
                Write-Log "No valid RecoveryPassword protector found — skipping escrow check" -Level "WARN" -ComputerName $ComputerName
            }
        
            # ----------------------------
            # Success Object
            # ----------------------------
            [PSCustomObject]@{
                Timestamp          = Get-Date
                Computer           = $ComputerName
                Online             = $true
                Reported           = $true
                Volume             = "C:"
                Protected          = $status.ProtectionStatus
                Percent            = $status.EncryptionPercent
                MachineKeyCount    = $MachineKeyCount
                ADKeyCount         = $ADKeyCount
                ADVerified         = if ($BackupResult) { $BackupResult.ADVerified } else { $false }
                RecoveryKeyID      = if ($BackupResult) { $BackupResult.RecoveryKeyID } else { $null }
                RecoveryPassword   = if ($BackupResult -and $IncludeKey) { $BackupResult.RecoveryPassword } else { $null }
                TPMPresent         = if ($tpm) { $tpm.TpmPresent } else { $false }
                TPMReady           = if ($tpm) { $tpm.TpmReady } else { $false }
                CanEnableBitLocker = $CanEnable
            }
        }
        catch {
            # ----------------------------
            # Failure Object
            # ----------------------------
            Write-Log "ERROR: $($_.Exception.Message)" -Level "ERROR" -ComputerName $ComputerName
        
            [PSCustomObject]@{
                Timestamp          = Get-Date
                Computer           = $ComputerName
                Online             = $false
                Reported           = $false
                Volume             = "C:"
                Protected          = $null
                Percent            = $null
                MachineKeyCount    = 0
                ADKeyCount         = 0
                ADVerified         = $false
                RecoveryKeyID      = $null
                RecoveryPassword   = $null
                TPMPresent         = $false
                TPMReady           = $false
                CanEnableBitLocker = $false
            }
		}
    } -ThrottleLimit $ThrottleLimit

    # --------------------------------------------------
    # 3️⃣ Export CSV
    # --------------------------------------------------
    if ($Results) {
        Export-ResultsSafe -Results $Results -Path $OutputPath -Mode $Mode
    }

    # --------------------------------------------------
    # 4️⃣ Track Unreachable Machines
    # --------------------------------------------------
    $NotContactedPath = Join-Path (Split-Path $OutputPath) "NotContacted_Computers.txt"

    if (-not (Test-Path $NotContactedPath)) {
        New-Item -Path $NotContactedPath -ItemType File | Out-Null
    }

    $existing = Get-Content $NotContactedPath -ErrorAction SilentlyContinue

    $newUnreachable = $Results |
        Where-Object { $_.Online -eq $false } |
        Select-Object -ExpandProperty Computer |
        Where-Object { $_ -and ($existing -notcontains $_) } |
        Sort-Object

    if ($newUnreachable) {
        $newUnreachable | Out-File -FilePath $NotContactedPath -Encoding UTF8 -Append
        Write-Host "Added $($newUnreachable.Count) new unreachable computers." -ForegroundColor Yellow
    }
    else {
        Write-Host "No new unreachable computers to add." -ForegroundColor Green
    }

    # --------------------------------------------------
    # 5️⃣ Comment out successfully contacted computers
    # --------------------------------------------------
    if ($PSCmdlet.ParameterSetName -eq "File") {

        $successful = $Results |
            Where-Object { $_.Online -eq $true -and $_.Reported -eq $true } |
            Select-Object -ExpandProperty Computer |
            Sort-Object

        if ($successful) {

            $lines = Get-Content $ComputerList

            $updated = foreach ($line in $lines) {
                $trim = $line.Trim()

                if ($trim -and ($successful -contains $trim) -and -not $trim.StartsWith("#")) {
                    "#$trim"
                }
                else {
                    $line
                }
            }

            $updated | Set-Content -Path $ComputerList -Encoding UTF8

            Write-Host "Commented out $($successful.Count) successfully contacted computers in $ComputerList." -ForegroundColor Cyan
        }
        else {
            Write-Host "No successfully contacted computers to comment out." -ForegroundColor DarkGray
        }
    }

    return $Results
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

function Test-ComputerConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    # Default result object
    $result = [PSCustomObject]@{
        ComputerName = $ComputerName
        Online       = $false
        WinRM        = $false
        Reason       = $null
    }

    try {
        # Basic ICMP reachability
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Reason = "Ping failed"
            return $result
        }

        $result.Online = $true

        # WSMan test (remote PowerShell availability)
        try {
            Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
            $result.WinRM = $true
        }
        catch {
            $result.Reason = "WinRM unavailable: $($_.Exception.Message)"
        }
    }
    catch {
        $result.Reason = "Unexpected error: $($_.Exception.Message)"
    }

    return $result
}


function Get-BitLockerSnapshotRemote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        try {
            # Get BitLocker volume
            $vol = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop

            # Extract protectors
            $all = $vol.KeyProtector
            $rp  = $all | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }

            # Newest RecoveryPassword protector
            $Newest = $rp | Sort-Object -Property KeyProtectorId -Descending | Select-Object -First 1

            # TPM info (optional but recommended)
            $tpm = $null
            try { $tpm = Get-Tpm } catch {}

            # Return snapshot object
            [PSCustomObject]@{
                Volume             = $vol
                ProtectionStatus   = $vol.ProtectionStatus
                EncryptionPercent  = $vol.EncryptionPercentage
                Protectors         = $all
                RecoveryProtectors = $rp
                NewestRecovery     = $Newest
                TPM                = $tpm
            }
        }
        catch {
            $null
        }
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
            -Filter {objectClass -eq "msFVE-RecoveryInformation"} `
            -SearchBase $Comp.DistinguishedName `
            -Properties msFVE-RecoveryPassword `
            -ErrorAction Stop

        $KeyCount = ($RecoveryObjects | Measure-Object).Count
        Write-Log "Found $KeyCount Escrowed AD BitLocker recovery key(s)" -ComputerName $ComputerName

        return $RecoveryObjects | ForEach-Object {
            [PSCustomObject]@{
                Computer         = $ComputerName
                RecoveryKeyID    = $_.ObjectGUID.ToString().Trim('{}')
                RecoveryPassword = if ($_.PSObject.Properties['msFVE-RecoveryPassword']) {
                    $_.'msFVE-RecoveryPassword'.Trim()
                } else { "" }
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to get BitLocker keys - $($_.Exception.Message)" -ComputerName $ComputerName
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

            $vol = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $vol) {
                throw "Volume $mount not found"
            }

            # Resume if suspended
            if ($vol.VolumeStatus -eq "Suspended") {
                Resume-BitLocker -MountPoint $mount -ErrorAction Stop
                Start-Sleep 3
            }

            # Enable BitLocker if protection is off (0 = Off)
            if ($vol.ProtectionStatus -eq "Off") {
                Enable-BitLocker -MountPoint $mount `
                                 -EncryptionMethod XtsAes256 `
                                 -RecoveryPasswordProtector `
                                 -Confirm:$false -ErrorAction Stop | Out-Null
            }

            # Return current status
            $vol = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop
            [PSCustomObject]@{
                VolumeStatus     = $vol.VolumeStatus
                ProtectionStatus = $vol.ProtectionStatus
                EncryptionPercent= $vol.EncryptionPercentage
                RebootRequired   = $rebootRequired
            }

        } -ErrorAction Stop | Select-Object -First 1
      
        Write-Log "BitLocker operation completed on $ComputerName" -ComputerName $ComputerName
        return $result
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Failed to enable BitLocker on $ComputerName : $errorMsg" -Level ERROR -ComputerName $ComputerName
        return $null
    }
}


function Ensure-BitLockerAndEscrow {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter()][switch]$IncludeRecoveryKey,
        [Parameter()][switch]$AutoEnable
    )

    Write-Log "Starting BitLocker orchestration" -ComputerName $ComputerName

    # ----------------------------
    # Step 0: Get current AD Keys
    # ----------------------------
    $ADKeys = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName
    $ADPasswords = if ($ADKeys) { $ADKeys.RecoveryPassword } else { @() }

    # ----------------------------
    # Step 1: Snapshot of BitLocker
    # ----------------------------
    $Snapshot = Get-BitLockerSnapshotRemote -ComputerName $ComputerName

    if (-not $Snapshot) {
        Write-Log "ERROR: Failed to retrieve BitLocker snapshot" -Level "ERROR" -ComputerName $ComputerName
        return
    }

    $NewestProtector = $Snapshot.NewestRecovery
    $BitLockerJustEnabled = $false

    # ----------------------------
    # Step 2: Determine if BitLocker can be enabled
    # ----------------------------
    $CanEnable = ($Snapshot.ProtectionStatus -eq "Off")

    if ($AutoEnable -and $CanEnable) {
        if ($PSCmdlet.ShouldProcess($ComputerName, "Enable BitLocker")) {

            Write-Log "Auto-enabling BitLocker on $ComputerName" -ComputerName $ComputerName

            $EnableResult = Enable-BitLockerRemote -ComputerName $ComputerName

            if ($EnableResult -and $EnableResult.ProtectionStatus -ne "Off") {
                Write-Log "BitLocker enabled successfully" -ComputerName $ComputerName
                $BitLockerJustEnabled = $true

                # Refresh snapshot after enable
                Start-Sleep -Seconds 5
                $Snapshot = Get-BitLockerSnapshotRemote -ComputerName $ComputerName
                $NewestProtector = $Snapshot.NewestRecovery
            }
        }
    }

    # ----------------------------
    # Step 3: Decide if backup is needed
    # ----------------------------
    $BackupResult = $null

    if ($NewestProtector -and
        -not [string]::IsNullOrWhiteSpace($NewestProtector.RecoveryPassword)) {

        $LocalKey = $NewestProtector.RecoveryPassword
        $IsEscrowed = $ADPasswords -contains $LocalKey

        if (-not $IsEscrowed -or $BitLockerJustEnabled) {
            Write-Log "Backing up BitLocker recovery key" -ComputerName $ComputerName

            $BackupResult = Backup-AndVerifyBitLockerKey `
                                -ComputerName $ComputerName `
                                -IncludeRecoveryKey:$IncludeRecoveryKey `
								-PSCmdlet $PSCmdlet
        }
        else {
            Write-Log "Recovery key already escrowed — no backup needed" -ComputerName $ComputerName

            $BackupResult = [PSCustomObject]@{
                ADVerified       = $true
                RecoveryKeyID    = $NewestProtector.KeyProtectorId.ToString().Trim('{}')
                RecoveryPassword = if ($IncludeRecoveryKey) { $LocalKey } else { $null }
            }
        }
    }
    else {
        Write-Log "No valid RecoveryPassword protector found — skipping backup" -Level "WARN" -ComputerName $ComputerName
    }

    return $BackupResult
}

# ----------------------------
# Remove extra recovery protectors (keep newest) — safe for -WhatIf
# ----------------------------
function Remove-ExtraBitLockerProtectors {
    param(
        [string]$ComputerName,
        [Parameter()]$PSCmdlet
    )

    try {
        # 1️⃣ Get local snapshot
        $vol = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-BitLockerVolume -MountPoint "C:" | Select-Object -First 1
        }

        $passwords = @($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" })
        if ($passwords.Count -le 1) { return }

        # Identify newest protector
        $keep = $passwords | Sort-Object CreationTime -Descending | Select-Object -First 1

        # Precompute ShouldProcess flags
        $doBackup = $false
        if ($PSCmdlet) {
            $doBackup = $PSCmdlet.ShouldProcess(
                "$ComputerName", "Backup newest BitLocker key $($keep.KeyProtectorId)"
            )
        }

        # 2️⃣ Backup newest key if allowed
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($KeepID, $DoBackup)
            if ($DoBackup) {
                Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $KeepID
            } else {
                Write-Host "Skipping backup of newest key $KeepID due to -WhatIf/confirmation."
            }
        } -ArgumentList $keep.KeyProtectorId, $doBackup

        # 3️⃣ Verify KeepID exists in AD before deleting others
        $adObject = Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
                                 -Properties msFVE-RecoveryGuid `
                                 -SearchBase (Get-ADComputer $ComputerName).DistinguishedName |
                    Where-Object { $_.Name -like "*$($keep.KeyProtectorId)*" }

        if ($adObject) {
            Write-Log "Verified: Newest key found in AD. Proceeding with cleanup." -ComputerName $ComputerName

            # Precompute deletion flags
            $deletionFlags = @{}
            foreach ($id in $passwords.KeyProtectorId) {
                if ($id -ne $keep.KeyProtectorId) {
                    $deletionFlags[$id] = $PSCmdlet -and $PSCmdlet.ShouldProcess("$ComputerName", "Remove BitLocker key $id")
                }
            }

            # 4️⃣ Remove older keys remotely
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($AllIDs, $KeepID, $DeletionFlags)
                foreach ($id in $AllIDs) {
                    if ($id -ne $KeepID) {
                        if ($DeletionFlags[$id]) {
                            Remove-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $id
                        } else {
                            Write-Host "Skipping removal of key $id due to -WhatIf/confirmation."
                        }
                    }
                }
            } -ArgumentList $passwords.KeyProtectorId, $keep.KeyProtectorId, $deletionFlags
        } else {
            Write-Log "ABORT: Newest key NOT found in AD. Cleanup skipped for safety." "WARN" -ComputerName $ComputerName
        }

    } catch {
        Write-Log "Cleanup failed on $ComputerName : $_" "ERROR" -ComputerName $ComputerName
    }
}

function Backup-AndVerifyBitLockerKey {
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [string]$MountPoint = "C:",
        [switch]$IncludeRecoveryKey,
        [PSCustomObject]$Snapshot,          # optional, pass from parallel block
        [Parameter()]$PSCmdlet               # optional, used for -WhatIf/-Confirm
    )

    Write-Log "Retrieving local BitLocker keys for backup" -ComputerName $ComputerName

    # Use passed snapshot or fetch new
    if (-not $Snapshot) {
        $Snapshot = Get-BitLockerSnapshotRemote -ComputerName $ComputerName
    }

    if (-not $Snapshot) {
        Write-Log "ERROR: Failed to retrieve BitLocker snapshot" -Level "ERROR" -ComputerName $ComputerName
        return
    }

    # Newest RecoveryPassword protector
    $NewestProtector = $Snapshot.NewestRecovery
    if (-not $NewestProtector) {
        Write-Log "ERROR: No RecoveryPassword protector found" -Level "ERROR" -ComputerName $ComputerName
        return
    }

    $RecoveryKeyID    = $NewestProtector.KeyProtectorId.ToString().Trim('{}')
    $RecoveryPassword = $NewestProtector.RecoveryPassword
    $ADVerified       = $false

    Write-Log "Preparing to backup newest BitLocker recovery key (ID: $RecoveryKeyID)" -ComputerName $ComputerName

    try {
        # Only execute backup if ShouldProcess allows
        if ($PSCmdlet -and $PSCmdlet.ShouldProcess("$ComputerName", "Backup BitLocker recovery key $RecoveryKeyID")) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($MP, $KPID)
                Backup-BitLockerKeyProtector -MountPoint $MP -KeyProtectorId $KPID -ErrorAction Stop | Out-Null
            } -ArgumentList $MountPoint, $NewestProtector.KeyProtectorId -ErrorAction Stop

            Write-Log "Backup completed, allowing time for AD replication..." -ComputerName $ComputerName
            Start-Sleep -Seconds 15
        }
        else {
            Write-Log "Skipping backup due to -WhatIf or confirmation prompt" -ComputerName $ComputerName
        }

        # ----------------------------
        # AD Recovery Keys verification
        # ----------------------------
        $ADKeys = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName
        $adPasswords = if ($ADKeys) { $ADKeys.RecoveryPassword } else { @() }

        if ($adPasswords -contains $RecoveryPassword) {
            $ADVerified = $true
            Write-Log "Escrowed recovery key verified in AD" -ComputerName $ComputerName
        }
        else {
            Write-Log "Recovery key NOT found in AD after backup!" -Level "WARN" -ComputerName $ComputerName
        }
    }
    catch {
        Write-Log "ERROR: Failed to back up or verify recovery key: $($_.Exception.Message)" -Level "ERROR" -ComputerName $ComputerName
    }

    # ----------------------------
    # Construct result object
    # ----------------------------
    $properties = [ordered]@{
        RecoveryKeyID = $RecoveryKeyID
        ADVerified    = [bool]$ADVerified
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

    # Retry settings
    $maxRetries = 3
    $retryDelay = 3  # seconds

    # ----------------------------
    # 1. Try Get-BitLockerSnapshotRemote (preferred)
    # ----------------------------
    $snapshot = $null

    for ($i = 1; $i -le $maxRetries; $i++) {

        $snapshot = Get-BitLockerSnapshotRemote -ComputerName $ComputerName

        # Success if we got protector info
        if ($snapshot -and $snapshot.RecoveryProtectors) { break }

        Start-Sleep -Seconds $retryDelay
    }

    if ($snapshot -and $snapshot.RecoveryProtectors) {

        $count  = $snapshot.RecoveryProtectors.Count
        $prot   = $snapshot.ProtectionStatus

        if ($Raw) { return $count }

        return [PSCustomObject]@{
            Count            = $count
            ProtectionStatus = $prot
        }
    }

    # ----------------------------
    # 2. Fallback to manage-bde
    # ----------------------------
    function Get-BdeProtectorCount {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $output = manage-bde -protectors -get C: | Out-String
                ($output | Select-String -Pattern "Numerical Password" -SimpleMatch).Count
            }
            catch {
                $null
            }
        }
    }

    $bdeCount = $null

    for ($i = 1; $i -le $maxRetries; $i++) {
        $bdeCount = Get-BdeProtectorCount
        if ($bdeCount -ne $null) { break }
        Start-Sleep -Seconds $retryDelay
    }

    if ($Raw) { return $bdeCount }

    return [PSCustomObject]@{
        Count            = $bdeCount
        ProtectionStatus = "Unknown"
    }
}


# ----------------------------
# CSV export helper
# ----------------------------
function Export-ResultsSafe {
    param(
        [array]$Results,
        [string]$Path,
        [ValidateSet("Append","Overwrite")][string]$Mode = "Append"
    )

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

    if ($Mode -eq "Overwrite") {
        Write-Log "Overwriting report $Path"
        $CleanedResults | Sort-Object Timestamp | Export-Csv $Path -NoTypeInformation
    }
    else {
        if (Test-Path $Path) {
            Write-Log "Appending to existing report $Path"
            $CleanedResults | Sort-Object Timestamp | Export-Csv $Path -NoTypeInformation -Append
        }
        else {
            Write-Log "Creating new report $Path"
            $CleanedResults | Sort-Object Timestamp | Export-Csv $Path -NoTypeInformation
        }
    }
}

Export-ModuleMember -Function `
    Write-Log, `
    Test-ComputerConnectivity, `
    Get-CVolumeRecoveryKeyCount, `
    Get-ADBitLockerRecoveryKeys, `
    Test-TPM, `
    Backup-AndVerifyBitLockerKey, `
    Remove-ExtraBitLockerProtectors, `
    Export-ResultsSafe, `
    Invoke-BitLockerParallel, `
    Enable-BitLockerRemote,
	Get-BitLockerSnapshotRemote
