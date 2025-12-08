<#
.SYNOPSIS
    Sets the Windows KMS server, optionally activates Windows, reports the current KMS host,
    or outputs the full KMS report for debugging.

.PARAMETER ComputerName
    Run the command on a single computer.

.PARAMETER ComputerList
    Path to a text file containing one computer name per line.

.PARAMETER FromAD
    Pulls all enabled computer objects from Active Directory.

.PARAMETER ADFilter
    Filter for AD computer names, e.g., SEC*. Only used with -FromAD.

.PARAMETER Activate
    After setting KMS host, also run slmgr.vbs /ato.

.PARAMETER Report
    Report the current KMS host configured on each computer.

.PARAMETER DebugReport
    Return the full raw KMS report (slmgr.vbs /dlv) for debugging and validation.
#>

param(
    [string]$ComputerName,
    [string]$ComputerList,
    [switch]$FromAD,
    [string]$ADFilter,   # <-- NEW: filter for AD computer names
    [switch]$Activate,
    [switch]$Report,
    [switch]$DebugReport
)

# KMS server to set
$KMSHost = "moranis25.nmh.nmhschool.org"

# ------------------------ FUNCTIONS ------------------------

function Invoke-KMSUpdate {
    param([string]$Target, [bool]$DoActivate)

    Write-Host "Processing ${Target} ..." -ForegroundColor Cyan

    if (-not (Test-Connection -ComputerName $Target -Count 1 -Quiet)) {
        Write-Warning "Cannot reach ${Target}. Skipping."
        return
    }

    try {
        Invoke-Command -ComputerName $Target -ScriptBlock {
            & cscript.exe C:\Windows\System32\slmgr.vbs //b /skms "$using:KMSHost"
        } -ErrorAction Stop

        Write-Host "Successfully set KMS on ${Target}" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to update KMS host on ${Target}. $_"
        return
    }

    if ($DoActivate) {
        try {
            Invoke-Command -ComputerName $Target -ScriptBlock {
                & cscript.exe C:\Windows\System32\slmgr.vbs //b /ato
            } -ErrorAction Stop

            Write-Host "Successfully activated Windows on ${Target}" -ForegroundColor Green
        }
        catch {
            Write-Warning "Activation failed on ${Target}. $_"
        }
    }
}

function Invoke-KMSReport {
    param([string]$Target, [switch]$DebugReport)

    Write-Host "Processing ${Target} ..." -ForegroundColor Cyan

    if (-not (Test-Connection -ComputerName $Target -Count 1 -Quiet)) {
        Write-Warning "Cannot reach ${Target}. Skipping."
        return
    }

    try {
        # Capture output of slmgr.vbs
        $output = Invoke-Command -ComputerName $Target -ScriptBlock {
            & cscript.exe C:\Windows\System32\slmgr.vbs /dlv //NoLogo
        } -ErrorAction Stop

        if ($DebugReport) {
            Write-Host "Full KMS report for ${Target}:" -ForegroundColor Yellow
            $output | ForEach-Object { Write-Host $_ }
            return
        }

        # Find line containing "KMS machine name" (either from DNS or plain)
        $kmsLine = $output | Where-Object { $_ -match "KMS machine name" }

        if ($kmsLine) {
            # Correctly extract full host:port string
            $kmsHost = ($kmsLine -split ":",2)[1].Trim()
            Write-Host "${Target} KMS Host: $kmsHost" -ForegroundColor Green
        }
        else {
            Write-Warning "${Target}: Could not find KMS host info."
        }
    }
    catch {
        Write-Warning "Failed to retrieve KMS host from ${Target}. $_"
    }
}

# ------------------------ BUILD COMPUTER LIST ------------------------

$Computers = @()

if ($ComputerName) { $Computers += $ComputerName }

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        $Computers += Get-Content $ComputerList
    } else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($FromAD) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        if ($ADFilter) {
            # PowerShell expands the variable inside the double-quoted string,
            # producing a proper AD filter like: Name -like "SEC*"
            $adQuery = "Name -like `"${ADFilter}`""
            $Computers += Get-ADComputer -Filter $adQuery |
                          Select-Object -ExpandProperty Name
        }
        else {
            $Computers += Get-ADComputer -Filter 'enabled -eq $true' |
                          Select-Object -ExpandProperty Name
        }
    }
    catch {
        Write-Error "Failed to query Active Directory: $_"
        exit 1
    }
}

# Safety check
if ($Computers.Count -eq 0) {
    Write-Error "No computers were provided. Use -ComputerName, -ComputerList, or -FromAD."
    exit 1
}

# Remove duplicates & blanks
$Computers = $Computers | Where-Object { $_ -and $_.Trim() -ne "" } | Sort-Object -Unique

# ------------------------ EXECUTE ------------------------

foreach ($PC in $Computers) {
    if ($Report -or $DebugReport) {
        Invoke-KMSReport -Target $PC -DebugReport:$DebugReport
    }
    else {
        Invoke-KMSUpdate -Target $PC -DoActivate:$Activate
    }
}

Write-Host "Done." -ForegroundColor Yellow
