<#
.SYNOPSIS
  Root Domain Controller Health Scored Checklist with Reporting
.DESCRIPTION
  Runs health checks, outputs PASS/FAIL, and saves results to CSV and HTML.
.NOTES
  Run as Administrator on the root domain controller.
#>

function Write-Result($testName, $condition, [ref]$results) {
    $status = if ($condition) { "PASS" } else { "FAIL" }
    Write-Host "[$status] $testName" -ForegroundColor ($(if ($status -eq "PASS") { "Green" } else { "Red" }))
    $results.Value += [PSCustomObject]@{
        Test   = $testName
        Status = $status
        Time   = (Get-Date)
    }
}

# Initialize results array
$results = @()

Write-Host "=== Root DC Health Scored Checklist ===" -ForegroundColor Cyan

# 1. dcdiag basic test
$dcdiag = (dcdiag /test:Advertising /test:Services /test:SystemLog | Out-String)
Write-Result "dcdiag basic tests" ($dcdiag -notmatch "fail|error") ([ref]$results)

# 2. Replication summary
$repl = (repadmin /replsummary | Out-String)
Write-Result "Replication healthy" ($repl -notmatch "fails") ([ref]$results)

# 3. FSMO role holders
$fsmo = (netdom query fsmo | Out-String)
Write-Result "FSMO roles reachable" ($fsmo -match "Schema Master") ([ref]$results)

# 4. SYSVOL and NETLOGON shares
$shares = (net share | Out-String)
Write-Result "SYSVOL share present" ($shares -match "SYSVOL") ([ref]$results)
Write-Result "NETLOGON share present" ($shares -match "NETLOGON") ([ref]$results)

# 5. DNS resolution
try { Resolve-DnsName $env:USERDNSDOMAIN -ErrorAction Stop | Out-Null; $dnsDomain = $true } catch { $dnsDomain = $false }
Write-Result "DNS domain resolves" $dnsDomain ([ref]$results)

try { Resolve-DnsName $env:COMPUTERNAME -ErrorAction Stop | Out-Null; $dnsHost = $true } catch { $dnsHost = $false }
Write-Result "DNS hostname resolves" $dnsHost ([ref]$results)

# 6. Time synchronization
$time = (w32tm /query /status | Out-String)
Write-Result "Time service running" ($time -match "Source") ([ref]$results)

# 7. Event logs (last 50 errors/warnings)
$dsErrors = Get-EventLog -LogName "Directory Service" -EntryType Error,Warning -Newest 50
Write-Result "Directory Service clean" ($dsErrors.Count -eq 0) ([ref]$results)

$dnsErrors = Get-EventLog -LogName "DNS Server" -EntryType Error,Warning -Newest 50
Write-Result "DNS Server clean" ($dnsErrors.Count -eq 0) ([ref]$results)

$dfsrErrors = Get-EventLog -LogName "DFS Replication" -EntryType Error,Warning -Newest 50
Write-Result "DFS Replication clean" ($dfsrErrors.Count -eq 0) ([ref]$results)

Write-Host "`n=== Checklist Complete ===" -ForegroundColor Cyan

# Export results
$csvPath = "$env:USERPROFILE\Desktop\RootDC_Checklist.csv"
$htmlPath = "$env:USERPROFILE\Desktop\RootDC_Checklist.html"

$results | Export-Csv -Path $csvPath -NoTypeInformation
$results | ConvertTo-Html -Title "Root DC Health Checklist" | Out-File $htmlPath

Write-Host "Results exported to:" -ForegroundColor Cyan
Write-Host "CSV: $csvPath"
Write-Host "HTML: $htmlPath"
