param (
    [string]$Installer   = "OCS-Windows-Agent-Setup-x64.exe",
    [string]$CertFile    = "cacert.pem",
    [string]$ComputerList,
    [string]$LogFile     = "Deploy-OCS.log"
)

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry
    Write-Host $logEntry
}

function Process-Computer {
    param($ComputerName)

    Write-Log "Starting deployment for $ComputerName"

    # Check if computer is online
    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
        Write-Log "$ComputerName is offline or unreachable." "ERROR"
        return $false
    }

    Write-Log "$ComputerName is online."

    # Define remote path
    $RemotePath = "\\$ComputerName\c$\ProgramData\OCS Inventory NG\Agent"

    # Ensure the folder exists
    if (-not (Test-Path $RemotePath)) {
        Write-Log "Creating folder $RemotePath ..."
        try {
            New-Item -Path $RemotePath -ItemType Directory -Force | Out-Null
            Write-Log "Folder created at $RemotePath"
        }
        catch {
            Write-Log "Failed to create $RemotePath. $_" "ERROR"
            return $false
        }
    }

    # Copy cacert.pem
    try {
        Copy-Item -Path $CertFile -Destination $RemotePath -Force
        Write-Log "Copied $CertFile to $RemotePath"
    }
    catch {
        Write-Log "Failed to copy $CertFile to $RemotePath. $_" "ERROR"
        return $false
    }

    # Run installer with PsExec
    $Arguments = "/S /SERVER=`"https://ocsinventory.nmhschool.org/ocsinventory`" /SSL=1 /NOSPLASH /NOTAG /NOW"
    Write-Log "Deploying OCS agent on $ComputerName ..."
    try {
        & ./psexec.exe "\\$ComputerName" -h -c -f $Installer $Arguments
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) {
            Write-Log "Deployment succeeded on $ComputerName (ExitCode=$exitCode)"
            return $true
        }
        else {
            Write-Log "Deployment failed on $ComputerName (ExitCode=$exitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Deployment threw an exception on $ComputerName. $_" "ERROR"
        return $false
    }
}

if ($ComputerList) {
    if (-not (Test-Path $ComputerList)) {
        Write-Log "Computer list file not found: $ComputerList" "ERROR"
        exit 1
    }

    $Computers = Get-Content $ComputerList
    foreach ($Computer in $Computers) {
        $Computer = $Computer.Trim()
        if (-not $Computer -or $Computer.StartsWith("#")) {
            continue
        }

        if (Process-Computer -ComputerName $Computer) {
            # Comment out successful runs only if exit code was 0
            (Get-Content $ComputerList) | ForEach-Object {
                if ($_ -eq $Computer) { "#$_" } else { $_ }
            } | Set-Content $ComputerList
        }
    }
}
else {
    # Interactive mode
    $ComputerName = Read-Host "Enter the target computer name"
    Process-Computer -ComputerName $ComputerName | Out-Null
}
