<#
.SYNOPSIS
    Deploys the OCS Inventory 3.x Windows agent to computers selected from
    Active Directory (or a text file), several at a time, remembering which
    ones are done. Requires PowerShell 7.

.DESCRIPTION
    TARGET SELECTION
      Filters combine with AND; multiple values inside one filter combine with OR.
      -Name             Computer name(s), wildcards allowed (SEC*, *-LAB-??)
      -OperatingSystem  OS name pattern(s), wildcards allowed ("*Windows 11*")
      -MinOsBuild       Minimum Windows build number (22000 = Windows 11 and up)
      -All              Every computer (no name/OS filter)
      -Exclude          Name(s)/wildcards that must never be touched
      -SearchBase       Limit the AD search to an OU
      -ComputerList     Text file of names instead of querying AD

    SAFETY DEFAULTS (AD mode)
      - Disabled computer accounts are ignored (-IncludeDisabled to include)
      - Server operating systems are ignored (-IncludeServers to include)
      - Computers that haven't logged on to the domain for 60 days are ignored
        (-MaxInactiveDays N to change, 0 to disable)

    CONCURRENCY
      -ThrottleLimit N installs on N computers at the same time (default 10,
      1 = one at a time). Workers only do the remote work; the main thread
      writes the log and the state file, so neither can be corrupted. Each
      computer's log lines appear together when that computer finishes.

    TRACKING AND RETRIES
      Results are stored in a state CSV. Computers that are done (Success or
      AlreadyInstalled) are skipped on later runs. Failures are retried until
      -MaxAttempts (-MaxOfflineAttempts for offline machines) is reached.
      -ResetAttempts retries everything that gave up; -Force reinstalls
      everything, including computers recorded as done.

    OUTPUT
      Log file, a per-run results CSV, a summary at the end, optional e-mail.

.EXAMPLE
    .\Deploy-OCS3.ps1 -OperatingSystem "*Windows 11*" -Name "SEC*" -ListOnly

.EXAMPLE
    .\Deploy-OCS3.ps1 -All -SearchBase "OU=Workstations,DC=nmhschool,DC=org" -Exclude "KIOSK*" -ThrottleLimit 15

.EXAMPLE
    # Unattended (scheduled task) run
    .\Deploy-OCS3.ps1 -All -Yes -PasswordFile C:\Deploy\ocs.cred
#>
#Requires -Version 7.0
[CmdletBinding()]
param (
    # --- Installer / server settings ---
    [string]$Installer   = "OCSInventory-Agent-Setup-3.0.0.exe",
    [string]$ServerUrl   = "https://ocs.nmhschool.org",
    [string]$Username    = "ocsclient",
    [SecureString]$Password,
    # For unattended/scheduled runs: DPAPI-encrypted credential file. If it
    # doesn't exist yet you are prompted once and it is created. It can only be
    # decrypted by the same Windows user on the same machine that created it.
    [string]$PasswordFile,

    # --- Target selection ---
    [string[]]$Name,
    [string[]]$OperatingSystem,
    [int]$MinOsBuild,
    [switch]$All,
    [string[]]$Exclude,
    [string]$SearchBase,
    [switch]$IncludeDisabled,
    [switch]$IncludeServers,
    [int]$MaxInactiveDays = 60,
    [string]$ComputerList,

    # --- Behaviour ---
    [ValidateRange(1, 50)][int]$ThrottleLimit = 10,   # computers installed at the same time
    [switch]$ListOnly,       # show targets and exit, deploy nothing
    [switch]$Force,          # reinstall even if recorded as done / already installed
    [switch]$Yes,            # skip the confirmation prompt
    [int]$MaxAttempts = 3,           # real failures before giving up
    [int]$MaxOfflineAttempts = 10,   # offline attempts before giving up
    [switch]$ResetAttempts,          # ignore attempt limits this run
    [switch]$KeepInstallerLog,       # keep a password-redacted copy of each target's setup log

    # --- Files ---
    [string]$StateFile = (Join-Path $PSScriptRoot "OCS-Deployed.csv"),
    [string]$LogFile   = (Join-Path $PSScriptRoot "Deploy-OCS3.log"),
    [string]$ResultsDir = (Join-Path $PSScriptRoot "Results"),

    # --- Optional e-mail summary ---
    [string]$SmtpServer,
    [string]$MailTo,
    [string]$MailFrom
)

$script:DoneStatuses = @("Success", "AlreadyInstalled")
$script:AgentService = "OCSInventory Agent"
$script:RunStart     = Get-Date

# ----------------------------------------------------------------------------
# Logging (main thread only)
# ----------------------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "OK")][string]$Level = "INFO"
    )
    $entry = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    try { Add-Content -Path $LogFile -Value $entry -ErrorAction Stop }
    catch { Write-Host "Could not write to log file: $_" -ForegroundColor Yellow }

    $color = switch ($Level) {
        "ERROR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" }
    }
    Write-Host $entry -ForegroundColor $color
}

# ----------------------------------------------------------------------------
# State tracking (CSV: one row per computer, latest result wins; main thread only)
# ----------------------------------------------------------------------------
function New-StateRow {
    param($ComputerName, $Status, $Reason, [int]$Attempts, $ExitCode, $LastAttempt, $Installer, $Server)
    [pscustomobject]@{
        ComputerName = $ComputerName
        Status       = $Status
        Reason       = $Reason
        Attempts     = $Attempts
        ExitCode     = $ExitCode
        LastAttempt  = $LastAttempt
        Installer    = $Installer
        Server       = $Server
    }
}

function Get-State {
    $state = @{}
    if (Test-Path $StateFile) {
        try {
            foreach ($row in (Import-Csv -Path $StateFile)) {
                # Normalise so rows written by older versions get the new columns
                $state[$row.ComputerName.ToUpper()] = New-StateRow `
                    -ComputerName $row.ComputerName -Status $row.Status -Reason $row.Reason `
                    -Attempts ([int]$row.Attempts) -ExitCode $row.ExitCode `
                    -LastAttempt $row.LastAttempt -Installer $row.Installer -Server $row.Server
            }
        }
        catch { Write-Log "Could not read state file ${StateFile}: $_" "ERROR" }
    }
    return $state
}

function Save-State {
    param([hashtable]$State)
    try {
        $State.Values | Sort-Object ComputerName |
            Export-Csv -Path $StateFile -NoTypeInformation -Force
    }
    catch { Write-Log "Could not write state file ${StateFile}: $_" "ERROR" }
}

# ----------------------------------------------------------------------------
# Active Directory query
# ----------------------------------------------------------------------------
function ConvertTo-LdapValue {
    # Escape LDAP special characters but keep * as a wildcard.
    param([string]$Value)
    $Value = $Value.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29')
    return $Value.Replace([string][char]0, '\00')
}

function Test-ExcludedName {
    param([string]$ComputerName)
    foreach ($pattern in $Exclude) {
        if ($ComputerName -like $pattern) { return $true }
    }
    return $false
}

function Get-TargetComputers {
    if ($ComputerList) {
        if (-not (Test-Path $ComputerList)) {
            Write-Log "Computer list file not found: $ComputerList" "ERROR"
            return $null
        }
        Write-Log "Reading targets from $ComputerList (AD filters, server and inactivity checks do not apply)"
        $list = @(Get-Content $ComputerList |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith("#") } |
            Where-Object { -not (Test-ExcludedName $_) } |
            ForEach-Object { [pscustomobject]@{ Name = $_; OperatingSystem = "(from list)" } })
        return $list
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory PowerShell module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" "ERROR"
        return $null
    }
    Import-Module ActiveDirectory

    $clauses = @("(objectCategory=computer)")

    if (-not $IncludeDisabled) {
        $clauses += "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    }
    if (-not $IncludeServers) {
        $clauses += "(!(operatingSystem=*Server*))"
    }
    if ($MaxInactiveDays -gt 0) {
        $cutoff = [DateTime]::UtcNow.AddDays(-$MaxInactiveDays).ToFileTimeUtc()
        $clauses += "(lastLogonTimestamp>=$cutoff)"
    }
    if ($Name) {
        $or = ($Name | ForEach-Object { "(name=$(ConvertTo-LdapValue $_))" }) -join ""
        $clauses += "(|$or)"
    }
    if ($OperatingSystem) {
        $or = ($OperatingSystem | ForEach-Object { "(operatingSystem=$(ConvertTo-LdapValue $_))" }) -join ""
        $clauses += "(|$or)"
    }
    foreach ($pattern in $Exclude) {
        $clauses += "(!(name=$(ConvertTo-LdapValue $pattern)))"
    }
    $ldap = "(&" + ($clauses -join "") + ")"
    Write-Log "AD query filter: $ldap"
    if (-not $IncludeServers)   { Write-Log "Server operating systems are excluded (use -IncludeServers to include them)." }
    if ($MaxInactiveDays -gt 0) { Write-Log "Ignoring computers with no domain logon in the last $MaxInactiveDays days (-MaxInactiveDays 0 disables)." }

    $adParams = @{
        LDAPFilter = $ldap
        Properties = @("OperatingSystem", "OperatingSystemVersion")
    }
    if ($SearchBase) { $adParams.SearchBase = $SearchBase; Write-Log "Search base: $SearchBase" }

    try { $found = @(Get-ADComputer @adParams) }
    catch {
        Write-Log "Active Directory query failed: $_" "ERROR"
        return $null
    }

    if ($MinOsBuild) {
        # OperatingSystemVersion looks like "10.0 (22631)"
        $found = @($found | Where-Object {
            $_.OperatingSystemVersion -match '\((\d+)\)' -and [int]$Matches[1] -ge $MinOsBuild
        })
        Write-Log "Applied MinOsBuild >= $MinOsBuild"
    }

    return @($found | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            Name            = $_.Name
            OperatingSystem = "$($_.OperatingSystem) $($_.OperatingSystemVersion)".Trim()
        }
    })
}

# ----------------------------------------------------------------------------
# Worker functions
#
# These run inside parallel runspaces, so they must be self-contained: no
# script-scope variables, no Write-Log, no state access. Everything they need
# arrives in the $Options hashtable, and everything they want to say is
# returned as Messages for the main thread to log.
# ----------------------------------------------------------------------------
function Get-RemoteServiceState {
    # Returns Running | Stopped | NotInstalled | AccessDenied | Unknown
    param([string]$ComputerName, [string]$ServiceName)
    $out = (& sc.exe "\\$ComputerName" query $ServiceName 2>&1 | Out-String)
    if ($out -match 'STATE\s+:\s+\d+\s+RUNNING')        { return "Running" }
    if ($out -match 'SERVICE_NAME')                      { return "Stopped" }
    if ($out -match 'FAILED 1060')                       { return "NotInstalled" }
    if ($out -match '(?i)access is denied|FAILED 5\b')   { return "AccessDenied" }
    return "Unknown"
}

function Start-RemoteService {
    param([string]$ComputerName, [string]$ServiceName)
    & sc.exe "\\$ComputerName" start $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    return (Get-RemoteServiceState -ComputerName $ComputerName -ServiceName $ServiceName)
}

function New-InstallResult {
    param([string]$Status, [string]$Reason = "", $ExitCode = "", [bool]$CountAttempt = $true, $Messages = @())
    [pscustomobject]@{
        Status       = $Status
        Reason       = $Reason
        ExitCode     = $ExitCode
        Done         = ($Status -in @("Success", "AlreadyInstalled"))
        CountAttempt = $CountAttempt
        Messages     = @($Messages)
    }
}

function Save-InstallerLog {
    # Pulls the target's setup log, strips the password, stores it locally and
    # removes the original from the target. Returns a warning string on failure.
    param([string]$ComputerName, [string]$PlainPassword, [string]$LogDir)
    $remote = "\\$ComputerName\c$\Windows\Temp\ocs-setup.log"
    if (-not (Test-Path $remote)) { return $null }
    try {
        if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
        $text = Get-Content -Path $remote -Raw
        if ($PlainPassword) {
            $text = $text -replace [regex]::Escape($PlainPassword), '********'
        }
        $text = $text -replace '(?i)/PASSWORD=\S+', '/PASSWORD=********'
        Set-Content -Path (Join-Path $LogDir "$ComputerName.log") -Value $text
    }
    catch { return "Could not save installer log for ${ComputerName}: $_" }
    finally { Remove-Item -Path $remote -Force -ErrorAction SilentlyContinue }
    return $null
}

function Install-OcsAgent {
    param([string]$ComputerName, [hashtable]$Options)

    $log = [System.Collections.Generic.List[object]]::new()
    $say = { param($Level, $Text) $log.Add([pscustomobject]@{ Level = $Level; Message = $Text }) }

    & $say "INFO" "Starting deployment for $ComputerName"

    # 1. Reachable?
    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
        & $say "ERROR" "$ComputerName is offline or unreachable."
        return New-InstallResult -Status "Offline" -Reason "No ping response" -Messages $log.ToArray()
    }

    # 2. Admin share reachable (needed by psexec)?
    if (-not (Test-Path "\\$ComputerName\ADMIN`$")) {
        & $say "ERROR" "$ComputerName is online but ADMIN`$ is not accessible (permissions, firewall, or file sharing off)."
        return New-InstallResult -Status "AccessDenied" -Reason "ADMIN`$ share not accessible" -Messages $log.ToArray()
    }

    # 3. Is the agent already installed?
    $agent = Get-RemoteServiceState -ComputerName $ComputerName -ServiceName $Options.AgentService
    if ($agent -eq "AccessDenied") {
        & $say "ERROR" "Access denied querying services on $ComputerName."
        return New-InstallResult -Status "AccessDenied" -Reason "Access denied to service manager" -Messages $log.ToArray()
    }
    if ($agent -eq "Unknown") {
        & $say "WARN" "Could not determine whether the agent is installed on $ComputerName; continuing."
    }
    if (-not $Options.Force) {
        if ($agent -eq "Running") {
            & $say "OK" "$ComputerName already has the OCS agent service running. Recording as AlreadyInstalled."
            return New-InstallResult -Status "AlreadyInstalled" -Reason "Service already running" -CountAttempt $false -Messages $log.ToArray()
        }
        if ($agent -eq "Stopped") {
            & $say "WARN" "$ComputerName has the OCS agent service but it is stopped. Trying to start it..."
            if ((Start-RemoteService -ComputerName $ComputerName -ServiceName $Options.AgentService) -eq "Running") {
                & $say "OK" "Service started on $ComputerName."
                return New-InstallResult -Status "AlreadyInstalled" -Reason "Service was stopped; started it" -CountAttempt $false -Messages $log.ToArray()
            }
            & $say "WARN" "Could not start the existing service on $ComputerName; reinstalling."
        }
    }

    # 4. Install. No certificate needed: the server presents a DigiCert-validated cert.
    $installerArgs = @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
        "/URL=$($Options.ServerUrl)",
        "/USERNAME=$($Options.Username)",
        "/PASSWORD=$($Options.Password)",
        "/BYPASS_CERT=0",
        "/SERVICE=1",
        "/NOW=1"
    )
    # Inno Setup records its command line in /LOG output, which would contain the
    # password. So no log is requested unless -KeepInstallerLog is used; in that
    # case the log is copied back with the password redacted and deleted remotely.
    if ($Options.KeepInstallerLog) { $installerArgs += "/LOG=C:\Windows\Temp\ocs-setup.log" }

    try {
        # Arguments are intentionally never logged (they contain the password).
        & $Options.PsExec "\\$ComputerName" -accepteula -nobanner -h -c -f $Options.Installer @installerArgs 2>&1 | Out-Null
        $exitCode = $LASTEXITCODE
    }
    catch {
        & $say "ERROR" "psexec threw an exception on ${ComputerName}: $_"
        return New-InstallResult -Status "InstallerFailed" -Reason "psexec exception: $_" -Messages $log.ToArray()
    }
    finally {
        if ($Options.KeepInstallerLog) {
            $warning = Save-InstallerLog -ComputerName $ComputerName -PlainPassword $Options.Password -LogDir $Options.InstallerLogDir
            if ($warning) { & $say "WARN" $warning }
        }
    }

    if ($exitCode -ne 0) {
        & $say "ERROR" "Install failed on $ComputerName (ExitCode=$exitCode)."
        return New-InstallResult -Status "InstallerFailed" -Reason "Exit code $exitCode" -ExitCode $exitCode -Messages $log.ToArray()
    }

    # 5. Verify the service
    $state = Get-RemoteServiceState -ComputerName $ComputerName -ServiceName $Options.AgentService
    if ($state -eq "Stopped") {
        $state = Start-RemoteService -ComputerName $ComputerName -ServiceName $Options.AgentService
    }
    if ($state -eq "Running") {
        & $say "OK" "Installed on $ComputerName and service is running."
        return New-InstallResult -Status "Success" -ExitCode 0 -Messages $log.ToArray()
    }

    & $say "ERROR" "Installer exited 0 on $ComputerName but the service is not running (state: $state)."
    return New-InstallResult -Status "ServiceNotRunning" -Reason "Installer exit 0, service state: $state" -ExitCode 0 -Messages $log.ToArray()
}

# ----------------------------------------------------------------------------
# Summary / reporting
# ----------------------------------------------------------------------------
function Write-Summary {
    param([System.Collections.ArrayList]$Results)

    $elapsed = (Get-Date) - $script:RunStart
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("OCS agent deployment summary - $(Get-Date -Format 'yyyy-MM-dd HH:mm') (took $([int]$elapsed.TotalMinutes) min)")
    [void]$lines.Add("Server: $ServerUrl   Installer: $(Split-Path $Installer -Leaf)   Parallel: $ThrottleLimit")

    foreach ($g in ($Results | Group-Object Outcome | Sort-Object Name)) {
        [void]$lines.Add(("  {0,-18} {1}" -f $g.Name, $g.Count))
    }

    $problems = @($Results | Where-Object { $_.Outcome -notin @("Success", "AlreadyInstalled", "PreviouslyDone") })
    if ($problems.Count) {
        [void]$lines.Add("Needs attention:")
        foreach ($p in $problems) {
            [void]$lines.Add(("  {0,-20} {1,-17} {2}" -f $p.Computer, $p.Outcome, $p.Reason))
        }
    }

    foreach ($l in $lines) { Write-Log $l }

    # Results CSV for this run
    try {
        if (-not (Test-Path $ResultsDir)) { New-Item -Path $ResultsDir -ItemType Directory -Force | Out-Null }
        $csv = Join-Path $ResultsDir ("Results-{0}.csv" -f $script:RunStart.ToString("yyyyMMdd-HHmmss"))
        $Results | Export-Csv -Path $csv -NoTypeInformation
        Write-Log "Results written to $csv"
    }
    catch { Write-Log "Could not write results CSV: $_" "WARN" }

    # Optional e-mail
    if ($SmtpServer -and $MailTo -and $MailFrom) {
        try {
            $subject = "OCS deployment: {0} installed, {1} need attention" -f `
                @($Results | Where-Object { $_.Outcome -eq "Success" }).Count, $problems.Count
            Send-MailMessage -SmtpServer $SmtpServer -From $MailFrom -To $MailTo `
                -Subject $subject -Body ($lines -join "`r`n") -WarningAction SilentlyContinue -ErrorAction Stop
            Write-Log "Summary e-mailed to $MailTo"
        }
        catch { Write-Log "Could not send summary e-mail: $_" "WARN" }
    }
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
Write-Log "==== Deploy-OCS3 started by $env:USERNAME on $env:COMPUTERNAME ===="

# Pre-flight checks
$script:PsExec = Join-Path $PSScriptRoot "psexec.exe"
if (-not (Test-Path $script:PsExec)) { $script:PsExec = "psexec.exe" }
if (-not $ListOnly) {
    if (-not (Get-Command $script:PsExec -ErrorAction SilentlyContinue)) {
        Write-Log "psexec.exe not found next to the script or in PATH." "ERROR"; exit 1
    }
    # Look for the installer in the current folder, then next to the script
    if (-not (Test-Path $Installer)) {
        $alt = Join-Path $PSScriptRoot $Installer
        if (Test-Path $alt) { $Installer = $alt }
    }
    if (-not (Test-Path $Installer)) {
        Write-Log "Installer not found: $Installer" "ERROR"; exit 1
    }
    $Installer = (Resolve-Path $Installer).Path
}

# If no selection was given, ask for a name/pattern
if (-not ($Name -or $OperatingSystem -or $MinOsBuild -or $All -or $ComputerList)) {
    $answer = Read-Host "Enter a computer name or pattern (e.g. SEC*), or press Enter to cancel"
    if (-not $answer) { Write-Log "No targets selected. Exiting." "WARN"; exit 0 }
    $Name = @($answer)
}

$targets = Get-TargetComputers
if ($null -eq $targets) { exit 1 }
Write-Log "Found $($targets.Count) computer(s) matching the filters."

$results = New-Object System.Collections.ArrayList
$state   = Get-State

# Skip what is already done, and what has used up its attempts
if (-not $Force) {
    $pending = @()
    foreach ($t in $targets) {
        $key = $t.Name.ToUpper()
        $row = $state[$key]

        if ($row -and ($script:DoneStatuses -contains $row.Status)) {
            [void]$results.Add([pscustomobject]@{ Computer = $t.Name; Outcome = "PreviouslyDone"; Reason = $row.Status; ExitCode = "" })
            continue
        }
        if ($row -and -not $ResetAttempts) {
            $limit = if ($row.Status -eq "Offline") { $MaxOfflineAttempts } else { $MaxAttempts }
            if ($row.Attempts -ge $limit) {
                [void]$results.Add([pscustomobject]@{
                    Computer = $t.Name; Outcome = "GaveUp"
                    Reason = "$($row.Attempts) attempts, last: $($row.Status) $($row.Reason)".Trim(); ExitCode = $row.ExitCode })
                continue
            }
        }
        $pending += $t
    }
    $skippedDone = @($results | Where-Object { $_.Outcome -eq "PreviouslyDone" }).Count
    $gaveUpNames = @($results | Where-Object { $_.Outcome -eq "GaveUp" }).Computer
    if ($skippedDone)       { Write-Log "Skipping $skippedDone computer(s) already installed." }
    if ($gaveUpNames.Count) { Write-Log "Skipping $($gaveUpNames.Count) computer(s) that reached their attempt limit (use -ResetAttempts to retry): $($gaveUpNames -join ', ')" "WARN" }
    $targets = $pending
}

if (-not $targets.Count) {
    Write-Log "Nothing to do - no computers pending installation."
    Write-Summary -Results $results
    exit 0
}

Write-Log "$($targets.Count) computer(s) pending installation."
$targets | Format-Table Name, OperatingSystem -AutoSize | Out-String | Write-Host

if ($ListOnly) { Write-Log "-ListOnly specified; no changes made."; exit 0 }

if (-not $Yes) {
    $ok = Read-Host "Deploy OCS agent to these $($targets.Count) computer(s), $ThrottleLimit at a time? (y/N)"
    if ($ok -notmatch '^(y|yes)$') { Write-Log "Cancelled by user." "WARN"; exit 0 }
}

# Password handling: parameter > credential file > prompt
if (-not $Password -and $PasswordFile -and (Test-Path $PasswordFile)) {
    try { $Password = Import-Clixml -Path $PasswordFile }
    catch { Write-Log "Could not read $PasswordFile (created by a different user/machine?): $_" "ERROR"; exit 1 }
}
if (-not $Password) {
    $Password = Read-Host "Enter password for $Username" -AsSecureString
    if ($PasswordFile) {
        try { $Password | Export-Clixml -Path $PasswordFile; Write-Log "Saved encrypted credential to $PasswordFile" }
        catch { Write-Log "Could not save ${PasswordFile}: $_" "WARN" }
    }
}

# Everything the workers need, passed in explicitly
$options = @{
    PsExec           = $script:PsExec
    Installer        = $Installer
    ServerUrl        = $ServerUrl
    Username         = $Username
    Password         = ($Password | ConvertFrom-SecureString -AsPlainText)
    AgentService     = $script:AgentService
    Force            = [bool]$Force
    KeepInstallerLog = [bool]$KeepInstallerLog
    InstallerLogDir  = (Join-Path $PSScriptRoot "InstallerLogs")
}

# Worker functions are handed to each runspace as text and recreated there
$workerFunctions = @{}
foreach ($fn in "Get-RemoteServiceState", "Start-RemoteService", "New-InstallResult", "Save-InstallerLog", "Install-OcsAgent") {
    $workerFunctions[$fn] = (Get-Command $fn -CommandType Function).Definition
}

$total = $targets.Count
$done  = 0
Write-Log "Deploying to $total computer(s), $ThrottleLimit at a time."

$targets |
    ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $functions = $using:workerFunctions
        foreach ($fn in $functions.Keys) {
            Set-Item -Path "function:$fn" -Value ([scriptblock]::Create($functions[$fn]))
        }
        $target = $_
        try {
            $result = Install-OcsAgent -ComputerName $target.Name -Options $using:options
        }
        catch {
            $message = [pscustomobject]@{ Level = "ERROR"; Message = "Unexpected error on $($target.Name): $_" }
            $result = New-InstallResult -Status "InstallerFailed" -Reason "Unexpected error: $_" -Messages @($message)
        }
        [pscustomobject]@{ Target = $target; Result = $result }
    } |
    ForEach-Object {
        # Back on the main thread: one computer at a time, so log and state are safe
        $t      = $_.Target
        $result = $_.Result
        $done++

        foreach ($m in $result.Messages) { Write-Log $m.Message $m.Level }
        Write-Log ("[{0}/{1}] {2}: {3}{4}" -f $done, $total, $t.Name, $result.Status,
            $(if ($result.Reason) { " ($($result.Reason))" } else { "" }))

        $key      = $t.Name.ToUpper()
        $previous = if ($state.ContainsKey($key)) { $state[$key].Attempts } else { 0 }
        $attempts = if ($result.Done) { 0 } elseif ($result.CountAttempt) { $previous + 1 } else { $previous }

        $state[$key] = New-StateRow -ComputerName $t.Name -Status $result.Status -Reason $result.Reason `
            -Attempts $attempts -ExitCode $result.ExitCode `
            -LastAttempt (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") `
            -Installer (Split-Path $Installer -Leaf) -Server $ServerUrl
        Save-State -State $state    # saved after every host so a crash loses nothing

        [void]$results.Add([pscustomobject]@{
            Computer = $t.Name; Outcome = $result.Status; Reason = $result.Reason; ExitCode = $result.ExitCode })
    }

$options.Password = $null
Write-Summary -Results $results

$failed = @($results | Where-Object { $_.Outcome -notin @("Success", "AlreadyInstalled", "PreviouslyDone", "GaveUp") }).Count
Write-Log "==== Finished. State file: $StateFile ===="
if ($failed) { exit 2 }
