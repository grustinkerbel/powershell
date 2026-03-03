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

0.PARAMETER ComputerList
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
    # Build Computer List
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
    # Parallel Processing
    # --------------------------------------------------
	
	$WhatIfMode = $WhatIfPreference
	
    $Results = $Computers | ForEach-Object -Parallel {
		

        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        Import-Module C:\bat\BitlockerRecoveryTools\BitlockerRecoveryTools -Force
        $WhatIfMode = $using:WhatIfMode
        $ComputerName = $_
        $IncludeKey   = $using:IncludeRecoveryKey
        $ADOnlyFlag   = $using:ADOnly
        $AutoEnable   = $using:AutoEnableBitLocker
        $CleanupFlag  = $using:CleanupProtectors
		$IncludeKey   = $using:IncludeRecoveryKey
       
        try {
            # ----------------------------
            # AD Only Mode
            # ----------------------------
            if ($ADOnlyFlag) {
                $ADKeys = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName
				
                
				$ADKeyCount = if ($ADKeys) { $ADKeys.Count } else { 0 }
				
			   
        
                return [PSCustomObject]@{
                    Timestamp              = Get-Date
                    Computer               = $ComputerName
                    Online                 = $false
                    Reported               = $false
                    Volume                 = "C:"
                    Protected              = $false
                    Percent                = $null
                    MachineKeyCount        = $null
                    ADKeyCount             = $ADKeyCount
                    ADVerified             = $false
                    ADRecoveryKeyID        = if ($ADKeys) { $ADKeys.ADRecoveryKeyID } else { @() }
                    ADRecoveryKeyPassword  = if ($ADKeys) { $ADKeys.ADRecoveryPassword } else { @() } 
                    RecoveryKeyID          = $null
                    RecoveryPassword       = $null
                    TPMPresent             = $false
                    TPMReady               = $false
                    CanEnableBitLocker     = $false
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
            $status = Get-BitLockerStatus -ComputerName $ComputerName
            if (-not $status) { throw "Failed to retrieve BitLocker snapshot" }
        
            # ----------------------------
            # AD Recovery Keys
            # ----------------------------
            $ADKeys                       = @(Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName)
			$status.ADRecoveryKeyID       = if ($ADKeys) { $ADKeys.ADRecoveryKeyID } else { @() }
			$status.ADRecoveryKeyPassword = if ($ADKeys) { $ADKeys.ADRecoveryPassword } else { @() }
			$ADPasswords                  = if ($ADKeys) { $ADKeys.ADRecoveryPassword } else { @() }
            $ADKeyCount                   = $ADPasswords.Count
        
        
            # ----------------------------
            # Determine BitLocker Enable Eligibility
            # ----------------------------
            # Only get MachineKeyCount from Get-CVolumeRecoveryKeyCount
            $keyInfo = Get-CVolumeRecoveryKeyCount -ComputerName $ComputerName
            $MachineKeyCount = if ($keyInfo) { $keyInfo.MachineKeyCount } else { 0 }
            
            # Only enable BitLocker if MachineKeyCount is 0
			$CanEnable = ($status.Protected -eq "Off" -and $MachineKeyCount -eq 0)
            
            # ----------------------------
            # Optional Auto-Enable
            # ----------------------------
            if ($AutoEnable -and $CanEnable) {
            
                if (-not $WhatIfMode) {
            
                    $EnableBDEResult = Enable-BitLockerRemote -ComputerName $ComputerName
            
                    if ($EnableBDEResult -and $EnableBDEResult.ProtectionStatus -ne "Off") {
                        Start-Sleep -Seconds 5
                    }
                }
                else {
                    Write-Log "WhatIf: Would enable BitLocker" -ComputerName $ComputerName
                }
            }
            else {
                Write-Log "Skipping BitLocker enable because MachineKeyCount > 0 or AutoEnable disabled" -ComputerName $ComputerName
            }
        
        
            # ----------------------------
            # Remove Password Protectors Keep Newest
            # ----------------------------
            if ($CleanupFlag) {
            
                if (-not $WhatIfMode) {
                    Remove-ExtraBitLockerProtectors -ComputerName $ComputerName
                }
                else {
                    Write-Log "WhatIf: Would remove extra BitLocker protectors" -ComputerName $ComputerName
                }
            }
        
            #------------------------------------------------------
            # Backup local recovery key if not escrowed with AD
            #------------------------------------------------------
			$backup = Backup-BitLocker -Status $status -ADPasswords $ADPasswords
			
			
			#--------------------------
			# Backup local Recovery Key
			#--------------------------
			if ($EnableBDEResult) {
				Write-Log "$EnableBDEResult"
                Write-Log "Local Recovery Keys Backup Attempted..Confirming" Local Recovery Keys Backup Attempted..Confirming
				$status                       = Get-BitLockerStatus -ComputerName $ComputerName
				if (-not $status) { throw "Failed to retrieve BitLocker snapshot" }
				$ADKeys                       = @(Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName)
				$status.Protected             = $EnableBDEResult.ProtectionStatus
				$status.ActivatedBitlocker    = $EnableBDEResult.ActivatedBitlocker
			    $status.ADRecoveryKeyID       = if ($ADKeys) { $ADKeys.ADRecoveryKeyID } else { @() }
			    $status.ADRecoveryKeyPassword = if ($ADKeys) { $ADKeys.ADRecoveryPassword } else { @() }
			    $ADPasswords                  = if ($ADKeys) { $ADKeys.ADRecoveryPassword } else { @() }
                $ADKeyCount                   = $ADPasswords.Count
				$backup                       = Backup-BitLocker -Status $status -ADPasswords $ADPasswords
				

				
			}
			
            #-----------------------------------------
			#Confirme the local key was escrowed to AD
			#-----------------------------------------
			if ($backup.AttemptBackup) {
				Write-Log "Backup BitLocker key attempted. Confirming Recovery Key Escrowed..." -ComputerName $ComputerName
				$ADKeys                       = @(Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName)
			    $status.ADRecoveryKeyID       = if ($ADKeys) { $ADKeys.ADRecoveryKeyID } else { @() }
			    $status.ADRecoveryKeyPassword = if ($ADKeys) { $ADKeys.ADRecoveryPassword } else { @() }
			    $ADPasswords                  = if ($ADKeys) { $ADKeys.ADRecoveryPassword } else { @() }
                $ADKeyCount                   = $ADPasswords.Count
				$backup                       = Backup-BitLocker -Status $status -ADPasswords $ADPasswords
            }
        
            # ----------------------------
            # Success Object
            # ----------------------------
            [PSCustomObject]@{
                Timestamp              = Get-Date
                Computer               = $ComputerName
                Online                 = $true
                Reported               = $true
                Volume                 = "C:"
                Protected              = $status.Protected
                Percent                = $status.Percent
                MachineKeyCount        = $status.MachineKeyCount
                ADKeyCount             = $ADKeyCount
                ADVerified             = $backup.ADVerified
                ADRecoveryKeyID        = $status.ADRecoveryKeyID
                ADRecoveryKeyPassword  = if ($IncludeKey) { $status.ADRecoveryKeyPassword }
                LocalKeySource         = $keyInfo.LocalKeySource
                RecoveryKeyID          = if ($status.RecoveryKeyID) { 
                                             [string]$status.RecoveryKeyID.Trim('{}') 
                                         } else { 
                                             $null 
                                         }
                RecoveryPassword       = if ($IncludeKey) { $status.RecoveryPassword }
                TPMPresent             = $status.TpmPresent
                TPMReady               = $status.TpmReady
                CanEnableBitLocker     = $CanEnable
                ActivatedBitlocker     = $status.ActivatedBitlocker
            }
        }
        catch {
            # ----------------------------
            # Failure Object
            # ----------------------------
            Write-Log "ERROR: $($_.Exception.Message)" -Level "ERROR" -ComputerName $ComputerName
        
            [PSCustomObject]@{
                Timestamp              = Get-Date
                Computer               = $ComputerName
                Online                 = $false
                Reported               = $false
                Volume                 = $null
                Protected              = $null
                Percent                = $null
                MachineKeyCount        = $null
                ADKeyCount             = $null
                ADVerified             = $false
				ADRecoveryKeyID        = $null
	            ADRecoveryKeyPassword  = $null
				LocalKeySource         = $null
                RecoveryKeyID          = $null
                RecoveryPassword       = $null
                TPMPresent             = $false
                TPMReady               = $false
                CanEnableBitLocker     = $false
				ActivatedBitlocker     = $false
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

    # Console output (not mutex-protected)
    Write-Host $line

    # File output (mutex-protected)
    try {
        $null = $script:LogMutex.WaitOne()
        Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
    }
    finally {
        $script:LogMutex.ReleaseMutex() | Out-Null
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


# ----------------------------
# Define the master template once
# ----------------------------
$BitLockerTemplate = [PSCustomObject]@{
    Timestamp              = Get-Date
    Computer               = $null
    Online                 = $false
    Reported               = $false
    Volume                 = "C:"
    Protected              = $null
    Percent                = 0
    MachineKeyCount        = 0
    ADKeyCount             = 0
    ADVerified             = $null
	ADRecoveryKeyID        = $null
	ADRecoverykeyPassword  = $null
    LocalKeySource         = $null
    RecoveryKeyID          = $null
    RecoveryPassword       = $null
    TPMPresent             = $false
    TPMReady               = $false
    CanEnableBitLocker     = $null
	ActivatedBitlocker     = $false
    Error                  = $null
}

# ----------------------------
# Optional helper to get a fresh copy of the template
# ----------------------------
function New-BitLockerResult {
    param([string]$ComputerName)
    $obj = $BitLockerTemplate.PSObject.Copy()
    $obj.Computer = $ComputerName
    return $obj
}

function Get-BitLockerStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    # Start with fresh template
    $result = New-BitLockerResult -ComputerName $ComputerName

    # First, check if computer is online
    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
        $result.Online = $false
        $result.Error  = "Computer is offline"
        return $result
    }

    $result.Online = $true

    try {
        $snapshot = Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {
            param($template, $computer)
            # Fresh copy in remote session
            $remoteResult = $template.PSObject.Copy()
            $remoteResult.Computer = $computer
            $remoteResult.Online   = $true

            try {
                # Attempt to get BitLocker volume
                $vol = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop |
                       Select-Object -First 1

                if (-not $vol) {
                    $remoteResult.Error = "BitLocker volume not found."
                    return $remoteResult
                }

                $remoteResult.Protected = $vol.ProtectionStatus
                $remoteResult.Percent   = $vol.EncryptionPercentage

                # Recovery Password Protectors
                $rp = @($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
                $remoteResult.MachineKeyCount = $rp.Count

                if ($rp.Count -gt 0) {
                    $newest = $rp | Sort-Object CreationTime -Descending | Select-Object -First 1
                    $remoteResult.RecoveryKeyID    = $newest.KeyProtectorId
                    $remoteResult.RecoveryPassword = $newest.RecoveryPassword
                }

                # TPM info (optional)
                try {
                    $tpm = Get-Tpm -ErrorAction Stop
                    $remoteResult.TPMPresent = $true
                    $remoteResult.TPMReady   = $tpm.TpmReady
                }
                catch {
                    # TPM absence is expected; do nothing
                }

                $remoteResult.Reported = $true
                return $remoteResult
            }
            catch {
                $remoteResult.Error = $_.Exception.Message
                return $remoteResult
            }

        } -ArgumentList $BitLockerTemplate, $ComputerName

        if ($snapshot.Count -eq 1) { $snapshot = $snapshot[0] }
        $result = $snapshot
    }
    catch {
        # Only triggers on true remoting failure
        $result.Error = $_.Exception.Message
        $result.Online = $false
    }

    return $result
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
                ADRecoveryKeyID    = $_.ObjectGUID.ToString().Trim('{}')
                ADRecoveryPassword = if ($_.PSObject.Properties['msFVE-RecoveryPassword']) {
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
    param(
        [string]$ComputerName
    )

    Write-Log "Starting Enable BitLocker Remote" -ComputerName $ComputerName

    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($PSCmdlet)

            $mount = "C:"

            $vol = Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $vol) { throw "Volume $mount not found" }

            # Resume if suspended
            if ($vol.VolumeStatus -eq "Suspended") {
                if ($PSCmdlet -and $PSCmdlet.ShouldProcess("$env:COMPUTERNAME", "Resume BitLocker on $mount")) {
                    Resume-BitLocker -MountPoint $mount -ErrorAction Stop
                    Start-Sleep 3
                } else {
                    Write-Host "WhatIf: Would resume BitLocker on $mount"
                }
            }

            # Enable BitLocker if protection is off
            if ($vol.ProtectionStatus -eq "Off") {
                if (-not $WhatIfMode) {
                    Enable-BitLocker -MountPoint $mount `
                                     -EncryptionMethod XtsAes256 `
                                     -RecoveryPasswordProtector `
                                     -Confirm:$false -ErrorAction Stop | Out-Null
                } else {
                    Write-Log "WhatIf: Would remove BitLocker key $NewestProtector.KeyProtectorId" -ComputerName $ComputerName
                }
            }
        } -ArgumentList $PSCmdlet -ErrorAction Stop | Select-Object -First 1
        $status = [PSCustomObject]@{
			ProtectionStatus      = "Off (Reboot Pending)"
            ActivatedBitlocker    = "$true"
            }
        Write-Log "BitLocker operation completed on $ComputerName" -ComputerName $ComputerName
        return $status
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Failed to enable BitLocker on $ComputerName : $errorMsg" -Level ERROR -ComputerName $ComputerName
        return $null
    }
}


# ----------------------------
# Remove extra recovery protectors (keep newest)
# ----------------------------
function Remove-ExtraBitLockerProtectors {
    param(
        [string]$ComputerName,
        [bool]$WhatIfMode = $false
    )

    try {
        Write-Log "Starting BitLocker protector cleanup..." -ComputerName $ComputerName

        # Get volume and protectors remotely
        $protectors = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-BitLockerVolume -MountPoint "C:" | Select-Object -First 1
        }

        $passwords = @($protectors.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" })

        if ($passwords.Count -le 1) {
            Write-Log "No duplicate protectors found" -ComputerName $ComputerName
            return
        }

        # Keep only the newest
        $keep = $passwords | Sort-Object CreationTime -Descending | Select-Object -First 1
        Write-Log "Keeping newest protector $($keep.KeyProtectorId)" -ComputerName $ComputerName

        # Prepare list of IDs to remove
        $toRemove = $passwords | Where-Object { $_.KeyProtectorId -ne $keep.KeyProtectorId } | Select-Object -ExpandProperty KeyProtectorId

        # Remove each protector one by one
        foreach ($id in $toRemove) {
            if (-not $WhatIfMode) {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($RemoveID)
                    Remove-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $RemoveID -ErrorAction Stop
                } -ArgumentList $id

                Write-Log "Removed protector $id" -ComputerName $ComputerName
            }
            else {
                Write-Log "WhatIf: Would remove protector $id" -ComputerName $ComputerName
            }
        }

        Write-Log "BitLocker protector cleanup complete." -ComputerName $ComputerName
    }
    catch {
        Write-Log "ERROR: Failed during cleanup: $($_.Exception.Message)" -Level ERROR -ComputerName $ComputerName
    }
}


function Get-CVolumeRecoveryKeyCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [switch]$Raw
    )

    # Retry settings
    $maxRetries = 3
    $retryDelay = 2

    # Start with template
    $result = New-BitLockerResult -ComputerName $ComputerName
    $result.LocalKeySource = "None"

    # ----------------------------
    # 1️⃣ Preferred Method: Get-BitLockerStatus
    # ----------------------------
    try {
        for ($i = 1; $i -le $maxRetries; $i++) {

            $snapshot = Get-BitLockerStatus -ComputerName $ComputerName

            if ($snapshot -and $snapshot.Reported) {
                $result = $snapshot
                $result.LocalKeySource = "BitLockerStatus"

                if ($Raw) {
                    return $result.MachineKeyCount
                }

                return [PSCustomObject]@{
                    Computer         = $result.Computer
                    Online           = $result.Online
                    Reported         = $result.Reported
                    MachineKeyCount  = $result.MachineKeyCount
                    ProtectionStatus = $result.Protected
                    LocalKeySource   = $result.LocalKeySource
                    Error            = $result.Error
                }
            }

            Start-Sleep -Seconds $retryDelay
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    # ----------------------------
    # 2️⃣ Fallback: manage-bde
    # ----------------------------
    try {
        $bdeCount = Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {

            try {
                $output = manage-bde -protectors -get C: | Out-String
                return ($output | Select-String "Numerical Password").Count
            }
            catch {
                return -1
            }

        }

        if ($bdeCount -ge 0) {

            $result.Reported        = $true
            $result.LocalKeySource  = "ManageBDE"
            $result.MachineKeyCount = $bdeCount

            if ($Raw) {
                return $bdeCount
            }

            return [PSCustomObject]@{
                Computer         = $result.Computer
                Online           = $true
                Reported         = $true
                MachineKeyCount  = $bdeCount
                ProtectionStatus = "Unknown"
                LocalKeySource   = "ManageBDE"
                Error            = $null
            }
        }

    }
    catch {
        $result.Error = $_.Exception.Message
    }

    # ----------------------------
    # 3️⃣ Final Failure Return
    # ----------------------------
    if ($Raw) {
        return 0
    }

    return [PSCustomObject]@{
        Computer         = $ComputerName
        Online           = $false
        Reported         = $false
        MachineKeyCount  = 0
        ProtectionStatus = "Unknown"
        LocalKeySource        = "Failed"
        Error            = $result.Error
    }
}

# ----------------------------
# ----Backup Bitlocker--------
# ----------------------------
function Backup-BitLocker {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Status,           # BitLocker snapshot object
        [string[]]$ADPasswords             # AD escrowed keys as strings, can be null
    )

    $AttemptBackup = $false
    $ADVerified    = $false
	
    # Ensure local key and RecoveryKeyID are strings
    $LocalKey      = $Status.RecoveryPassword
    $RecoveryKeyID = if ($Status.RecoveryKeyID) { [string]$Status.RecoveryKeyID.Trim('{}') } else { $null }

    if (-not $LocalKey) {
        Write-Log "No valid RecoveryPassword protector found — skipping backup" -Level "WARN" -ComputerName $Status.Computer
        return [PSCustomObject]@{
            ADVerified       = $false
            RecoveryKeyID    = $RecoveryKeyID
            RecoveryPassword = if ($LocalKey) { $LocalKey } else { $null }
        }
    }

    # Ensure $ADPasswords is never null
    if (-not $ADPasswords) { $ADPasswords = @() }

    # Compare with AD keys (always a string)
    $IsEscrowed = if ($ADPasswords.Count -gt 0) { $ADPasswords -contains $LocalKey } else { $false }

    if (-not $IsEscrowed) {
		$AttemptBackup = $true
        Write-Log "Backing up BitLocker recovery key ID: $RecoveryKeyID" -ComputerName $Status.Computer
		

        try {
            if ($PSCmdlet -and $PSCmdlet.ShouldProcess("$($Status.Computer)", "Backup BitLocker recovery key $RecoveryKeyID")) {
                Invoke-Command -ComputerName $Status.Computer -ScriptBlock {
                    param($MP, $KPID)
                    Backup-BitLockerKeyProtector -MountPoint $MP -KeyProtectorId $KPID -ErrorAction Stop | Out-Null
                } -ArgumentList "C:", $Status.RecoveryKeyID -ErrorAction Stop

                Write-Log "Backup completed, allowing time for AD replication..." -ComputerName $Status.Computer
                Start-Sleep -Seconds 15
            }
            else {
                Write-Log "Skipping backup due to -WhatIf or confirmation prompt" -ComputerName $Status.Computer
            }
        }
        catch {
            Write-Log "ERROR: Failed to back up recovery key: $($_.Exception.Message)" -Level "ERROR" -ComputerName $Status.Computer
        }
	$ADVerified = $true
    }
    else {
        Write-Log "Recovery key escrowed — no backup needed" -ComputerName $Status.Computer
        $ADVerified = $true
    }

    # Return a clean PSCustomObject with string values
    return [PSCustomObject]@{
        ADVerified            = $ADVerified
		AttemptBackup         = $AttemptBackup
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
        # Helper function to join arrays, leave single values as-is
        $JoinArray = {
            param($Value)
            if ($Value -is [System.Array]) {
                $Value -join ','
            } elseif ($Value) {
                $Value
            } else {
                ''
            }
        }

        [PSCustomObject]@{
            Timestamp              = $_.Timestamp
            Computer               = $_.Computer
            Online                 = $_.Online
            Reported               = $_.Reported
            Volume                 = $_.Volume
            Protected              = $_.Protected
            Percent                = $_.Percent
            ADRecoveryKeyID        = & $JoinArray $_.ADRecoveryKeyID
            ADRecoverykeyPassword  = & $JoinArray $_.ADRecoverykeyPassword
			LocalKeySource         = & $JoinArray $_.LocalKeySource
            RecoveryKey            = & $JoinArray $_.RecoveryKeyID
            RecoveryPassword       = & $JoinArray $_.RecoveryPassword
            MachineKeyCount        = $_.MachineKeyCount
            ADKeyCount             = $_.ADKeyCount
            ADVerified             = $_.ADVerified
            TPMPresent             = $_.TPMPresent
            TPMReady               = $_.TPMReady
            CanEnableBitLocker     = $_.CanEnableBitLocker
            ActivatedBitlocker     = $_.ActivatedBitlocker
        }
    }

    # Export to CSV
    $exportParams = @{
        Path              = $Path
        NoTypeInformation = $true
    }

    if ($Mode -eq "Append" -and (Test-Path $Path)) {
        $exportParams.Add("Append", $true)
    }

    $CleanedResults | Export-Csv @exportParams
}

if (-not $script:LogMutex) {
    $script:LogMutex = New-Object System.Threading.Mutex($false, "Global\ARDScriptsLogMutex")
}

$script:LogPath = ".\BitlockerTools.log"

Export-ModuleMember -Function `
    Write-Log, `
    Test-ComputerConnectivity, `
    Get-CVolumeRecoveryKeyCount, `
    Get-ADBitLockerRecoveryKeys, `
    Test-TPM, `
    Backup-Bitlocker, `
    Remove-ExtraBitLockerProtectors, `
    Export-ResultsSafe, `
    Invoke-BitLockerParallel, `
    Enable-BitLockerRemote,
	Get-BitLockerStatus
