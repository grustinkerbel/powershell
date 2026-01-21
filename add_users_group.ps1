<#
.SYNOPSIS
Adds a list of users to an Active Directory group, supporting both plain text and CSV imports.

.DESCRIPTION
This script imports a list of users from either a plain text file or a CSV file and adds them to the specified Active Directory group. 
It includes verbose logging, error handling, a dry-run mode, and generates a detailed report at the end. 
The CSV option allows mapping a column as the AD username and includes first/last names in the report.

.PARAMETER UserListPath
Path to the input file containing users. Defaults to 'UserList.txt' in the current directory.

.PARAMETER GroupName
Name of the Active Directory group to which users will be added. Defaults to 'Gets_AdobeCC'.

.PARAMETER CsvUsernameColumn
The column in the CSV file that contains the AD username. Defaults to 'username'. Only used if -UseCsv is specified.

.PARAMETER UseCsv
Switch to indicate the input file is a CSV. If not specified, a plain text file is assumed.

.PARAMETER ReportPath
Path to export the CSV report. Defaults to 'AddUsersReport.csv' in the current directory.

.PARAMETER DryRun
Switch to perform a dry-run. No changes will be made to AD. The report and summary will still be generated.

.EXAMPLE
# Add users from a plain text file with verbose logging
.\Add_AdobeUsers.ps1 -Verbose

.EXAMPLE
# Import users from a CSV in dry-run mode
.\Add_AdobeUsers.ps1 -UserListPath ".\UserList.csv" -UseCsv -DryRun -Verbose

.EXAMPLE
# Actual run with CSV input and custom report location
.\Add_AdobeUsers.ps1 -UseCsv -UserListPath ".\AdobeUsers.csv" -ReportPath ".\AdobeAddReport.csv" -Verbose

.NOTES
- Requires the ActiveDirectory PowerShell module.
- Handles errors and skips users not found or already in the group.
- Generates a report with status: Added, Skipped, Would Add (dry-run), or Failed.
#>

[CmdletBinding()]
param (
    [string]$UserListPath,
    [string]$GroupName = 'Gets_AdobeCC',
    [string]$CsvUsernameColumn = 'username',
    [switch]$UseCsv,
    [string]$ReportPath,
    [switch]$DryRun
)

# -----------------------------
# Defaults
# -----------------------------
if (-not $UserListPath) { $UserListPath = Join-Path $PWD.Path 'UserList.txt' }
if (-not $ReportPath)   { $ReportPath   = Join-Path $PWD.Path 'AddUsersReport.csv' }

Write-Verbose "User list path: $UserListPath"
Write-Verbose "Report path: $ReportPath"

# -----------------------------
# Load AD module
# -----------------------------
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $UserListPath)) {
    throw "Input file not found: $UserListPath"
}

if ($DryRun) {
    Write-Verbose "Running in DRY-RUN mode"
}

# -----------------------------
# Load users
# -----------------------------
if ($UseCsv) {
    Write-Verbose "Importing users from CSV"
    $Users = Import-Csv $UserListPath |
        Where-Object { $_.$CsvUsernameColumn -and $_.$CsvUsernameColumn.Trim() }

    $GetIdentity  = { param($u) $u.$CsvUsernameColumn.Trim() }
    $GetFirstName = { param($u) $u.first_name }
    $GetLastName  = { param($u) $u.last_name }
}
else {
    Write-Verbose "Importing users from text file"
    $Users = Get-Content $UserListPath |
        Where-Object { $_.Trim() }

    $GetIdentity  = { param($u) $u.Trim() }
    $GetFirstName = { '' }
    $GetLastName  = { '' }
}

# -----------------------------
# Cache group members ONCE
# -----------------------------
Write-Verbose "Caching members of group '$GroupName'"
$GroupMembers = Get-ADGroupMember -Identity $GroupName -Recursive |
    Select-Object -ExpandProperty DistinguishedName

# -----------------------------
# Report collection
# -----------------------------
$Report = @()

# -----------------------------
# Process users
# -----------------------------
foreach ($User in $Users) {

    $Username  = & $GetIdentity  $User
    $FirstName = & $GetFirstName $User
    $LastName  = & $GetLastName  $User

    # Defensive default
    $Status   = 'Unknown'
    $ErrorMsg = ''

    Write-Verbose "Processing user: $Username"

    try {
        $AdUser = Get-ADUser -Identity $Username -ErrorAction Stop
        Write-Verbose "Found AD user: $($AdUser.Name)"

        if ($GroupMembers -contains $AdUser.DistinguishedName) {
            Write-Verbose "User already in group"
            $Status = 'Skipped'
        }
        else {
            if ($DryRun) {
                Write-Verbose "DRY-RUN: Would add user"
                $Status = 'Would Add'
            }
            else {
                try {
                    Add-ADGroupMember -Identity $GroupName -Members $AdUser -ErrorAction Stop
                    Write-Verbose "User added successfully"
                    $Status = 'Added'

                    # Keep cache accurate for remainder of run
                    $GroupMembers += $AdUser.DistinguishedName
                }
                catch {
                    throw
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to process user '$Username'"
        Write-Warning $_.Exception.Message
        $Status   = 'Failed'
        $ErrorMsg = $_.Exception.Message
    }

    $Report += [PSCustomObject]@{
        Username  = $Username
        FirstName = $FirstName
        LastName  = $LastName
        Status    = $Status
        Error     = $ErrorMsg
    }
}

# -----------------------------
# Export report
# -----------------------------
$Report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
Write-Host "Report saved to: $ReportPath"

# -----------------------------
# Summary
# -----------------------------
$Total   = @($Report).Count
$Added   = @($Report | Where-Object { $_.Status -in @('Added','Would Add') }).Count
$Skipped = @($Report | Where-Object { $_.Status -eq 'Skipped' }).Count
$Failed  = @($Report | Where-Object { $_.Status -eq 'Failed' }).Count
$Unknown = @($Report | Where-Object { $_.Status -eq 'Unknown' }).Count

Write-Host "`n===== Summary ====="
Write-Host "Total users processed : $Total"
Write-Host "Added / Would Add     : $Added"
Write-Host "Skipped               : $Skipped"
Write-Host "Failed                : $Failed"
Write-Host "Unknown               : $Unknown"
Write-Host "=====================`n"

Write-Verbose "Script completed."
