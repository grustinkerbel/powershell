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
            # Machine Recovery Key Count
            # ----------------------------
            $MachineKeyCount = if ($status.Protectors) { $status.Protectors.Count } else { 0 }
        
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
            # Determine Machine Recovery Key Count
            # ----------------------------
            $keyInfo        = Get-CVolumeRecoveryKeyCount -ComputerName $ComputerName
            $MachineKeyCount = if ($keyInfo) { $keyInfo.Count } else { 0 }
            
            # ----------------------------
            # Determine Enable Eligibility
            # ----------------------------
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
                Write-Log "Newest local RecoveryPassword protector: $($NewestProtector.KeyProtectorId)" -ComputerName $ComputerName
            } else {
                Write-Log "No local RecoveryPassword protectors found" -Level "WARN" -ComputerName $ComputerName
            }
        
            # ----------------------------
            # Remove Password Protectors Keep Newest
            # ----------------------------
            if ($CleanupFlag) {
                Remove-ExtraBitLockerProtectors -ComputerName $ComputerName
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
                    Write-Log "Local key already escrowed to AD — no backup needed" -ComputerName $ComputerName
        
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

function Test-BitLockerEscrowStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$RecoveryPassword,

        [Parameter(Mandatory)]
        [array]$ADKeys
    )

    $adPasswords = $ADKeys | ForEach-Object { $_.'msFVE-RecoveryPassword' }

    if ($adPasswords -contains $RecoveryPassword) {
        Write-Log "Local BitLocker key is already escrowed to AD" -ComputerName $ComputerName
        return [PSCustomObject]@{
            Escrowed    = $true
            NeedsBackup = $false
        }
    }

    Write-Log "Local BitLocker key NOT found in AD — backup required" -Level "WARN" -ComputerName $ComputerName

    return [PSCustomObject]@{
        Escrowed    = $false
        NeedsBackup = $true
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
                                -IncludeRecoveryKey:$IncludeRecoveryKey
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
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [string]$MountPoint = "C:",
        [switch]$IncludeRecoveryKey,
        [PSCustomObject]$Snapshot  # optional, pass from parallel block to avoid re-query
    )

    Write-Log "Retrieving BitLocker snapshot for backup" -ComputerName $ComputerName

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

    Write-Log "Starting backup of newest BitLocker recovery key (ID: $RecoveryKeyID)" -ComputerName $ComputerName

    try {
        # Backup the protector remotely
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($MP, $KPID)
            Backup-BitLockerKeyProtector -MountPoint $MP -KeyProtectorId $KPID -ErrorAction Stop | Out-Null
        } -ArgumentList $MountPoint, $NewestProtector.KeyProtectorId -ErrorAction Stop

        # Allow AD replication (could replace with retry logic)
        Start-Sleep -Seconds 15

        # ----------------------------
        # AD Recovery Keys
        # ----------------------------
        $ADKeys = Get-ADBitLockerRecoveryKeys -ComputerName $ComputerName
        $adPasswords = if ($ADKeys) { $ADKeys.RecoveryPassword } else { @() }

        if ($adPasswords -contains $RecoveryPassword) {
            $ADVerified = $true
            Write-Log "Escrowed Recovery key verified in AD" -ComputerName $ComputerName
        }
        else {
            Write-Log "Recovery key NOT found in AD after backup!" -Level "WARN" -ComputerName $ComputerName
        }
    }
    catch {
        Write-Log "ERROR: Failed to back up/verify : $($_.Exception.Message)" -Level "ERROR" -ComputerName $ComputerName
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
	Test-BitLockerEscrowStatus,
	Get-BitLockerSnapshotRemote
