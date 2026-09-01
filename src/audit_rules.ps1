<#
.SYNOPSIS
Read-only audit of Exchange Online transport rules for a DMARC program.

.DESCRIPTION
Enumerates every transport rule and answers the questions that matter before
you enforce DMARC:

  - Which rules bypass filtering (lower SCL or allow senders), and do they
    require authentication to pass first? An allow rule gated on dmarc=pass is
    safe. An allow rule with no authentication condition delivers forgeries.
  - Which rules match on forgeable input? Anything keyed to a string in a
    Received header can be triggered by any sender who types that string.
  - Which "block" rules are actually in Audit mode, logging instead of acting?
  - How big have exception lists grown? Every excepted address is one an
    attacker can spoof straight past the rule.
  - Which rules had zero hits in the window? Dead rules are free cleanup.

Requires an interactive Exchange Online session:
    Connect-ExchangeOnline -UserPrincipalName you@yourdomain.example
    ./audit_rules.ps1 -Days 10 -ExportPath ./rule-audit

Makes no changes. Read-only cmdlets throughout.
#>
param(
    [int]$Days = 10,
    [string]$ExportPath = ""
)

$ErrorActionPreference = 'Continue'
$start = (Get-Date).AddDays(-$Days)
$end = Get-Date

Write-Host "Transport rule audit - window: $start .. $end" -ForegroundColor Cyan

$rules = Get-TransportRule -ResultSize Unlimited
Write-Host ("{0} rules total`n" -f $rules.Count)

$findings = @()
foreach ($r in $rules) {
    $isAllow = ($null -ne $r.SetSCL -and [int]$r.SetSCL -le 0)
    $isBlock = ($null -ne $r.SetSCL -and [int]$r.SetSCL -ge 5) -or $r.Quarantine -or $r.DeleteMessage
    $authGated = $false
    foreach ($p in @($r.HeaderMatchesPatterns) + @($r.HeaderContainsWords)) {
        if ("$p" -match 'dmarc=pass') { $authGated = $true }
    }
    $forgeable = $false
    if ($r.HeaderContainsMessageHeader -match 'Received' -or
        ($r.HeaderContainsWords -and -not $r.HeaderContainsMessageHeader)) {
        # header-string conditions whose header is attacker-writable
        $forgeable = $true
    }
    $exceptions = @($r.ExceptIfFrom).Count + @($r.ExceptIfSenderDomainIs).Count +
                  @($r.ExceptIfSubjectContainsWords).Count

    $issues = @()
    if ($isAllow -and -not $authGated) { $issues += "ALLOW-WITHOUT-AUTH: bypasses filtering with no authentication condition" }
    if ($isAllow -and $forgeable)      { $issues += "FORGEABLE-CONDITION: allow keyed to attacker-writable header content" }
    if ($isBlock -and $r.Mode -ne 'Enforce') { $issues += "AUDIT-MODE-BLOCK: named/acts like a block but Mode=$($r.Mode) - it does nothing" }
    if ($exceptions -ge 20)            { $issues += "LARGE-EXCEPTION-LIST: $exceptions entries - each one is spoofable past this rule" }

    $findings += [pscustomobject]@{
        Name = $r.Name; State = $r.State; Mode = $r.Mode; Priority = $r.Priority
        SCL = $r.SetSCL; AuthGated = $authGated; Exceptions = $exceptions
        Issues = ($issues -join ' | ')
    }
}

Write-Host "=== Findings ===" -ForegroundColor Yellow
$flagged = $findings | Where-Object { $_.Issues }
foreach ($f in $flagged) {
    Write-Host ("`n  {0}  [prio {1}, {2}, SCL {3}]" -f $f.Name, $f.Priority, $f.State, $f.SCL)
    Write-Host ("    {0}" -f $f.Issues) -ForegroundColor Red
}
if (-not $flagged) { Write-Host "  none - unusually clean" }

Write-Host "`n=== Hit counts (dead-rule check, last $Days days) ===" -ForegroundColor Yellow
$hits = @{}
foreach ($r in $rules) {
    $total = 0
    try {
        for ($p = 1; $p -le 6; $p++) {
            $batch = @(Get-MailDetailTransportRuleReport -TransportRule $r.Name `
                        -StartDate $start -EndDate $end -PageSize 5000 -Page $p -ErrorAction Stop)
            $total += $batch.Count
            if ($batch.Count -lt 5000) { break }
        }
        $hits[$r.Name] = $total
    } catch { $hits[$r.Name] = -1 }
}
$dead = $rules | Where-Object { $hits[$_.Name] -eq 0 -and $_.State -eq 'Enabled' }
Write-Host ("  enabled rules with ZERO hits: {0}" -f @($dead).Count)
$dead | ForEach-Object { Write-Host ("    {0}" -f $_.Name) }

if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath | Out-Null }
    $findings | ForEach-Object { $_ | Add-Member -NotePropertyName Hits -NotePropertyValue $hits[$_.Name] -PassThru } |
        Export-Csv (Join-Path $ExportPath "transport_rule_audit.csv") -NoTypeInformation
    Write-Host "`nCSV written to $ExportPath" -ForegroundColor Green
}

Write-Host "`nRemember: a rule gated on dmarc=pass cannot rescue a forgery. Everything else on the findings list can." -ForegroundColor Cyan
