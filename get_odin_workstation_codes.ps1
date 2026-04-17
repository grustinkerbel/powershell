# Get the directory of this script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Input file containing computer names (one per line)
$ComputerList = Join-Path $ScriptDir "computers.txt"

# Output CSV
$OutputCsv = Join-Path $ScriptDir "OdinCodes.csv"

# Backups will go in the same folder as the CSV
$BackupFolder = $ScriptDir

# Initialize results array
$Results = @()

foreach ($Computer in Get-Content $ComputerList) {
    $UNCPath = "\\$Computer\C$\Odin\workstn.cfg"
    $CodeValue = $null

    # Check if computer is online first
    if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
        if (Test-Path $UNCPath) {
            try {
                # Backup the file into the same folder as the script
                $BackupFile = Join-Path $BackupFolder "$Computer`_backup.cfg"
                Copy-Item -Path $UNCPath -Destination $BackupFile -Force

                # Read file and find line starting with "Code="
                $CodeLine = Get-Content $UNCPath | Where-Object { $_ -match '^Code=' }

                if ($CodeLine) {
                    $CodeValue = $CodeLine -replace '^Code=', ''
                } else {
                    $CodeValue = "Not Found"
                }
            }
            catch {
                $CodeValue = "Error Reading File"
            }
        } else {
            $CodeValue = "File Not Found"
        }
    }
    else {
        $CodeValue = "Offline"
    }

    # Add to results
    $Results += [PSCustomObject]@{
        ComputerName = $Computer
        Code         = $CodeValue
    }
}

# Export to CSV in the same folder as the script
$Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "Done! Results saved to $OutputCsv"
Write-Host "Backups saved in $BackupFolder"
