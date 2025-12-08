<#
.SYNOPSIS
    Sets the Windows KMS server, optionally activates Windows, reports the current KMS host,
    or outputs the full KMS report for debugging.
#>

param(
    [string]$ComputerName,
    [string]$ComputerList,
    [switch]$FromAD,
    [string]$ADFilter,
    [switch]$Activate,
    [switch]$Report,
    [switch]$DebugReport
)

# KMS server to set
$KMSHost = "moranis25.nmh.nmhschool.org"

# ------------------------ LOGGING SETUP ------------------------

$LogPath = "C:\Logs"
$LogFile = Join-Path $LogPath "kms_set.log"

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp  $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

Write-Log "=== Script started ==="

# ------------------------ FUNCTIONS ------------------------

function Invoke-KMSUpdate {
    param([string]$Target, [bool]$DoActivate)

    Write-Host "Processing ${Target} ..." -ForegroundColor Cyan
    Write-Log  "Processing $Target"

    if (-not (Test-Connection -ComputerName $Target -Count 1 -Quiet)) {
        Write-Warning "Cannot reach ${Target}. Skipping."
        Write-Log  "[$Target] Unreachable (ping failed)"
        return
    }

    try {
        Invoke-Command -ComputerName $Target -ScriptBlock {
            & cscript.exe C:\Windows\System32\slmgr.vbs //b /skms "$using:KMSHost"
        } -ErrorAction Stop

        Write-Host "Successfully set KMS on ${Target}" -ForegroundColor Green
        Write-Log  "[$Target] KMS host set to $KMSHost"
    }
    catch {
        Write-Warning "Failed to update KMS host on ${Target}. $_"
        Write-Log  "[$Target] ERROR setting KMS host: $_"
        return
    }

    if ($DoActivate) {
        try {
            Invoke-Command -ComputerName $Target -ScriptBlock {
                & cscript.exe C:\Windows\System32\slmgr.vbs //b /ato
            } -ErrorAction Stop

            Write-Host "Successfully activated Windows on ${Target}" -ForegroundColor Green
            Write-Log "[$Target] Activation successful"
        }
        catch {
            Write-Warning "Activation failed on ${Target}. $_"
            Write-Log "[$Target] ERROR during activation: $_"
        }
    }
}

function Invoke-KMSReport {
    param([string]$Target, [switch]$DebugReport)

    Write-Host "Processing ${Target} ..." -ForegroundColor Cyan
    Write-Log "Processing $Target for KMS report"

    if (-not (Test-Connection -ComputerName $Target -Count 1 -Quiet)) {
        Write-Warning "Cannot reach ${Target}. Skipping."
        Write-Log "[$Target] Unreachable (ping failed)"
        return
    }

    try {
        $output = Invoke-Command -ComputerName $Target -ScriptBlock {
            & cscript.exe C:\Windows\System32\slmgr.vbs /dlv //NoLogo
        } -ErrorAction Stop

        if ($DebugReport) {
            Write-Host "Full KMS report for ${Target}:" -ForegroundColor Yellow
            $output | ForEach-Object { Write-Host $_ }
            Write-Log "[$Target] Debug report retrieved (full slmgr /dlv)"
            return
        }

        $kmsLine = $output | Where-Object { $_ -match "KMS machine name" }

        if ($kmsLine) {
            $kmsHost = ($kmsLine -split ":",2)[1].Trim()
            Write-Host "${Target} KMS Host: $kmsHost" -ForegroundColor Green
            Write-Log  "[$Target] Current KMS Host = $kmsHost"
        }
        else {
            Write-Warning "${Target}: Could not find KMS host info."
            Write-Log "[$Target] No KMS host line found in slmgr output"
        }
    }
    catch {
        Write-Warning "Failed to retrieve KMS information from ${Target}. $_"
        Write-Log  "[$Target] ERROR retrieving KMS info: $_"
    }
}

# ------------------------ BUILD COMPUTER LIST ------------------------

$Computers = @()

if ($ComputerName) { $Computers += $ComputerName }

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        $Computers += Get-Content $ComputerList
        Write-Log "Loaded computer list from file: $ComputerList"
    } else {
        Write-Error "Computer list file not found: $ComputerList"
        Write-Log "ERROR: Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($FromAD) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        if ($ADFilter) {
            $adQuery = "Name -like `"${ADFilter}`""
            Write-Log "Querying AD with filter: $adQuery"

            $Computers += Get-ADComputer -Filter $adQuery |
                          Select-Object -ExpandProperty Name

            Write-Log "AD returned $($Computers.Count) computers matching filter"
        }
        else {
            Write-Log "Querying AD for enabled computers"

            $Computers += Get-ADComputer -Filter 'enabled -eq $true' |
                          Select-Object -ExpandProperty Name

            Write-Log "AD returned $($Computers.Count) enabled computers"
        }
    }
    catch {
        Write-Error "Failed to query Active Directory: $_"
        Write-Log "ERROR: AD query failed: $_"
        exit 1
    }
}

if ($Computers.Count -eq 0) {
    Write-Error "No computers were provided."
    Write-Log "ERROR: No computers provided."
    exit 1
}

$Computers = $Computers | Where-Object { $_ -and $_.Trim() -ne "" } | Sort-Object -Unique
Write-Log "Final computer list contains $($Computers.Count) systems"

# ------------------------ EXECUTE ------------------------

foreach ($PC in $Computers) {
    if ($Report -or $DebugReport) {
        Invoke-KMSReport -Target $PC -DebugReport:$DebugReport
    }
    else {
        Invoke-KMSUpdate -Target $PC -DoActivate:$Activate
    }
}

Write-Log "=== Script completed ==="
Write-Host "Done." -ForegroundColor Yellow
