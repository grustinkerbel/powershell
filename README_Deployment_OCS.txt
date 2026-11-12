# Deploy-OCS3.ps1

Remotely installs the **OCS Inventory NG 3.x Windows agent** (Inno Setup package) on computers selected from Active Directory. It installs on several computers at once, remembers which ones are done so each is installed only once, and writes a log, a per-run results file and a summary.

- **Server:** `https://ocs.nmhschool.org` (DigiCert-validated certificate, so no certificate file is deployed and validation stays on)
- **Agent account:** `ocsclient` (needs permission to add, update and view inventory)
- **Written for:** PowerShell 7 on a domain-joined admin workstation

> **Status:** the script has had a first pilot test. It has not been run at scale. Always preview with `-ListOnly`, then pilot on a small filter before running against everything.

---

## What it does

For each target computer the script:

1. Pings it. No reply is recorded as `Offline`.
2. Checks that `\\computer\ADMIN$` is reachable. If not, it records `AccessDenied`.
3. Checks for an existing `OCSInventory Agent` service.
   - Running: records `AlreadyInstalled` and moves on.
   - Stopped: tries to start it. It reinstalls only if the start fails.
4. Copies and runs the installer silently through PsExec, with the server URL, credentials, certificate validation on, service mode on, and an immediate inventory (`/NOW=1`).
5. Verifies the service is running afterwards. If the installer exited 0 but the service isn't running, it records `ServiceNotRunning` and retries on a later run.

The main thread writes the log and the tracking file, so up to `-ThrottleLimit` computers can install at the same time without corrupting either.

## Requirements

| Requirement | Notes |
|---|---|
| PowerShell 7+ | Uses `ForEach-Object -Parallel`. The script refuses to start on 5.1. |
| RSAT Active Directory module | Not needed with `-ComputerList`. Install with `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| `psexec.exe` | Sysinternals PsExec, in the same folder as the script or in `PATH`. |
| Installer `.exe` | Default name `OCSInventory-Agent-Setup-3.0.0.exe`, in the current folder or next to the script. Use `-Installer` for a different name. |
| Account running the script | Local administrator on the target computers. |
| Network and firewall on targets | ICMP echo allowed, SMB (admin share) reachable, remote service management (RPC) reachable. |

## Quick start

```powershell
# 1. Preview: which computers would be targeted? (changes nothing)
.\Deploy-OCS3.ps1 -OperatingSystem "*Windows 11*" -Name "SEC*" -ListOnly

# 2. Pilot on a small batch
.\Deploy-OCS3.ps1 -Name "SEC-PC0*" -ThrottleLimit 3

# 3. Everything in an OU, excluding some machines
.\Deploy-OCS3.ps1 -All -SearchBase "OU=Workstations,DC=nmhschool,DC=org" -Exclude "KIOSK*" -ThrottleLimit 10
```

Without `-Yes`, the script shows the target list and asks for confirmation. If you give no selection options at all, it asks for a computer name or pattern.

## Choosing targets

Different filters combine with **AND**. Multiple values inside one filter combine with **OR**.

| Parameter | Purpose |
|---|---|
| `-Name` | Computer name(s); wildcards allowed (`SEC*`, `*-LAB-??`). `-Name "SEC*","LAB*"` matches either. |
| `-OperatingSystem` | OS name pattern(s), e.g. `"*Windows 11*"`. |
| `-MinOsBuild` | Minimum Windows build number. `22000` means Windows 11 and later. |
| `-All` | Every computer, with no name or OS filter. |
| `-Exclude` | Name(s) or wildcards that are never touched. Also applies to `-ComputerList`. |
| `-ExcludeFile` | Text file of names or wildcards to never touch, one per line (blank lines and `#` comments ignored). Combined with `-Exclude`. The script refuses to run if the file is given but missing. Best for scheduled tasks. |
| `-SearchBase` | Limit the search to an OU (distinguished name). |
| `-ComputerList` | Read names from a text file (one per line, `#` for comments) instead of querying AD. AD filters, server and inactivity checks don't apply, but `-Exclude` still does. |
| `-IncludeDisabled` | Include disabled computer accounts (ignored by default). |
| `-IncludeServers` | Include server operating systems (ignored by default). |
| `-MaxInactiveDays` | Ignore computers with no domain logon in this many days. Default `60`; `0` turns it off. |

Examples:

```powershell
# All Windows 11 computers whose name starts with SEC
.\Deploy-OCS3.ps1 -OperatingSystem "*Windows 11*" -Name "SEC*"

# Build-number based (more reliable than the OS string, see Known limitations)
.\Deploy-OCS3.ps1 -MinOsBuild 22000 -Name "SEC*"
```

## Running options

| Parameter | Default | Purpose |
|---|---|---|
| `-ThrottleLimit` | `10` | Computers installed at the same time (1 to 50). `1` runs one at a time. |
| `-ListOnly` | off | Show the target list and exit. Needs no installer or PsExec. |
| `-Yes` | off | Skip the confirmation prompt (needed for unattended runs). |
| `-Force` | off | Reinstall even if a computer is recorded as done or already has the agent running. |
| `-MaxAttempts` | `3` | Real failures before a computer is given up on. |
| `-MaxOfflineAttempts` | `10` | Offline attempts before a computer is given up on. |
| `-ResetAttempts` | off | Retry computers that hit their attempt limit. |
| `-KeepInstallerLog` | off | Keep a password-redacted copy of each target's setup log (see Security). |
| `-Upgrade` | off | Reinstall computers whose installed agent is older than the installer (see Upgrading). |
| `-TargetVersion` | from installer | Version to compare against in `-Upgrade` mode, e.g. `3.0.1`. |
| `-Installer` | `OCSInventory-Agent-Setup-3.0.0.exe` | Installer file name or path. |
| `-ServerUrl` | `https://ocs.nmhschool.org` | OCS server URL. |
| `-Username` | `ocsclient` | Account the agent uses to talk to the server. |

### Upgrading an installed agent

By default a computer that already has the agent service running is recorded as `AlreadyInstalled` and left alone. To roll out a newer agent, put the new installer next to the script and add `-Upgrade`:

```powershell
# Preview what would be upgraded
.\Deploy-OCS3.ps1 -All -Upgrade -ListOnly

# Upgrade, using the new installer
.\Deploy-OCS3.ps1 -All -Upgrade -Installer OCSInventory-Agent-Setup-3.0.1.exe -TargetVersion 3.0.1
```

How it works:

1. The target version comes from `-TargetVersion`, or else from the installer's file properties. If neither gives a version, the script stops and asks for `-TargetVersion`.
2. For each computer with the agent service present, it finds the service's executable, reads its file version over the admin share and compares.
3. Older than the target: the installer runs again, over the top of the existing install (the setup replaces the previous version and rewrites `config.json` from the parameters passed; inventory data is kept, per the OCS docs). The result is `Upgraded`.
4. Same or newer: nothing is installed. A stopped service is started.
5. Computers recorded as done are re-checked on later runs until their recorded version reaches the target, so a rollout can be run repeatedly as machines come online.

Safeguards:

- If the installed version can't be read, the computer is recorded as `VersionUnknown` and **not** touched. Use `-Force` to reinstall it anyway.
- If the installer runs but the agent's version still isn't at the target afterwards, the result is `UpgradeNotConfirmed`. It counts toward `-MaxAttempts`, so a version-number mismatch can't cause endless reinstalls.
- `-Force` ignores versions and reinstalls every selected computer.

The script logs the version it finds on each computer. **On your first upgrade run, check a few computers' logged versions against the version you expect**, because the check reads the agent executable's file version and that may not match the installer's version number exactly.

### Password

The password is not stored in the script. Resolution order:

1. `-Password` (a SecureString), if given.
2. `-PasswordFile`, if the file exists. It is a DPAPI-encrypted file that only the **same Windows user on the same machine** that created it can read. See "Running unattended" for how to create it.
3. A prompt. If `-PasswordFile` was given but doesn't exist yet, the answer is saved there for next time. This only happens on a run that reaches the install step (there must be computers to install on).

## Tracking: how "install once" works

Results are stored in `OCS-Deployed.csv` (next to the script) and saved after every computer, so an interruption loses nothing. Columns: `ComputerName, Status, Reason, Attempts, ExitCode, LastAttempt, Installer, Server, Version`.

| Status | Meaning | Retried on later runs? |
|---|---|---|
| `Success` | Installed and service running | No |
| `AlreadyInstalled` | Agent service was already present (and running or started) | No |
| `Upgraded` | `-Upgrade` replaced an older agent and it is running at the target version | No |
| `VersionUnknown` | `-Upgrade` couldn't read the installed version, so nothing was changed | Yes, up to `-MaxAttempts` |
| `UpgradeNotConfirmed` | Installer ran but the agent's version is still below the target | Yes, up to `-MaxAttempts` |
| `Offline` | No ping reply | Yes, up to `-MaxOfflineAttempts` |
| `AccessDenied` | `ADMIN$` or the service manager wasn't reachable | Yes, up to `-MaxAttempts` |
| `InstallerFailed` | PsExec or installer returned an error | Yes, up to `-MaxAttempts` |
| `ServiceNotRunning` | Installer exited 0 but the service isn't running | Yes, up to `-MaxAttempts` |

Computers that reach their attempt limit are reported as `GaveUp` and skipped until you use `-ResetAttempts` (or fix the cause and use `-Force`). To make one computer eligible again, delete its row from the CSV.

## Output files

All are created next to the script.

| File or folder | Contents |
|---|---|
| `Deploy-OCS3.log` | Timestamped log of every run: start and end markers, the exact AD filter, each computer's messages, and the summary. The password is never written to it. |
| `OCS-Deployed.csv` | The tracking file described above. |
| `Results\Results-<timestamp>.csv` | One row per computer for that run, including skipped ones. |
| `InstallerLogs\<computer>.log` | Only with `-KeepInstallerLog`. Password-redacted setup log from the target. |

Each run ends with a tally by outcome and a "Needs attention" list. To get it by email, add `-SmtpServer`, `-MailFrom` and `-MailTo` (it uses `Send-MailMessage`, so the SMTP server must accept unauthenticated relay from the machine running the script).

**Exit codes:** `0` = no failures, `1` = startup problem (missing PsExec or installer, AD query failed, and so on), `2` = at least one computer failed in this run.

## Running unattended

Create the credential file once, **while logged in as the account the scheduled task will run under**:

```powershell
Read-Host "ocsclient password" -AsSecureString | Export-Clixml -Path C:\Deploy\ocs.cred
```

Check it with `Import-Clixml C:\Deploy\ocs.cred` (it should print a `SecureString`, not the password). To sign in as the task account without logging off, use `runas /user:DOMAIN\taskaccount pwsh.exe` and run the command in that window. Run the same command again to change the password.

Then schedule the task (Task Scheduler, PowerShell 7, `pwsh.exe`):

```powershell
pwsh.exe -File C:\Deploy\Deploy-OCS3.ps1 -All -Yes -PasswordFile C:\Deploy\ocs.cred -SmtpServer mail.example.org -MailFrom ocs@example.org -MailTo you@example.org
```

For exclusions, add `-ExcludeFile C:\Deploy\exclude.txt` to the task instead of a list on the command line. The file is read on every run, so you can edit it without touching the task. Example `exclude.txt`:

```
# Never touch these
KIOSK*
SERVER-*
SEC-PC12
```

Because of the tracking file, each run only touches computers that aren't done yet, so machines that were off get picked up on a later run.

## Security notes

- **The password is visible while an install runs.** PsExec passes the installer arguments on a command line, so the `ocsclient` password can be seen briefly on the target's process list and on the machine running the script. Give `ocsclient` only the add, update and view inventory permissions, and rotate its password if it has been shared in chat or email.
- **Inno Setup setup logs contain the command line.** For that reason the script does not request a setup log unless you use `-KeepInstallerLog`. In that case the log is copied back with the password redacted and the original is deleted from the target.
- The credential file from `-PasswordFile` is encrypted for one Windows user on one machine. Keep it out of shared folders and source control.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `ActiveDirectory PowerShell module not found` | Install RSAT (command above) or use `-ComputerList`. |
| `psexec.exe not found` / `Installer not found` | Put them next to the script, or put PsExec in `PATH` and use `-Installer` with a full path. |
| Many `Offline` | Computers are powered off or ICMP is blocked. They are retried on later runs. |
| `AccessDenied` | Not a local admin on the target, admin share disabled, or firewall blocking SMB and RPC. |
| `InstallerFailed` with an exit code | Run on a single computer with `-KeepInstallerLog -ThrottleLimit 1` and read `InstallerLogs\<computer>.log`. |
| `ServiceNotRunning` | Check the service and `C:\ProgramData\OCSInventory-Agent\config.json` on the target. |
| Password file can't be read | It was created by a different user or on a different machine. Delete it and recreate it. |
| Nothing appears for a while | In parallel mode, a computer's log lines show up when that computer finishes. |

## Known limitations

- **Success means "service running", not "reported to the server".** The script doesn't check that the machine has checked in on the OCS server. Confirm the first few in the OCS console.
- **Windows 11 detection:** AD sometimes reports Windows 11 machines with a Windows 10 OS string. If `-OperatingSystem "*Windows 11*"` misses machines, use `-MinOsBuild 22000`.
- **Inactivity cutoff:** AD's `lastLogonTimestamp` can lag by up to about two weeks, which is fine for the default 60-day cutoff but not for very short ones.
- **Legacy agents:** the script does not detect, remove or manage the old OCS 2.x agent. Version 3 runs alongside it, and handling 2.x is planned for a later stage.
- **Interrupting a run (Ctrl+C):** installs already in progress on targets finish, but aren't written to the tracking file. The next run's existing-agent check records them as `AlreadyInstalled`.
- **Server load:** `/NOW=1` makes each machine send an inventory right after install. Lower `-ThrottleLimit` if the OCS server struggles.
- **Version detection (`-Upgrade`):** it reads the file version of the agent service's executable. If the agent runs through a wrapper or its file version doesn't follow the installer's version number, use `-TargetVersion` and check the logged versions on a few machines first.
- Not yet implemented: post-install verification against the OCS server and a lock to prevent two overlapping scheduled runs.
