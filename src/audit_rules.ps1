<#
.SYNOPSIS
Read-only audit of Exchange Online transport rules for a DMARC program.

.DESCRIPTION
Enumerates every transport rule and answers the questions that matter before
you enforce DMARC:

  - Which rules bypass filtering (lower SCL or allow senders), and do they
    require authentication to pass first? An allow rule gated on dmarc=pass,
    compauth=pass, or any Authentication-Results header match is safe. An
    allow rule gated only on SenderIpRanges is reported separately as
    ip-gated: better than nothing, weaker than authentication, because a
    shared sending platform puts many tenants behind the same IPs. An allow
    rule with no gate at all delivers forgeries.
  - Which rules match on forgeable input? Anything keyed to a string in a
    Received header can be triggered by any sender who types that string.
  - Which "block" rules are actually in Audit mode, logging instead of acting?
  - How big have exception lists grown? Every excepted address is one an
    attacker can spoof straight past the rule.
  - Which rules had zero hits in the window? Dead rules are free cleanup.

Requires an interactive Exchange Online session:
    Connect-ExchangeOnline -UserPrincipalName you@yourdomain.example
    ./audit_rules.ps1 -Days 10 -ExportPath ./rule-audit
    ./audit_rules.ps1 -Json -SkipHits > rules.json

-Json writes one document to stdout (the per-rule table plus findings in the
shared shape: id, severity, area, title, evidence, action, verified) and
nothing else. -SkipHits skips the per-rule hit-count report, which is the
slow part. A disabled rule keeps its finding but at severity info, because it
does nothing today. Exit codes: 0 clean, 1 findings at severity major or
blocking, 2 not connected or bad input.

Makes no changes. Read-only cmdlets throughout.
#>
param(
    [int]$Days = 10,
    [string]$ExportPath = "",
    [switch]$Json,
    [switch]$SkipHits
)

$ErrorActionPreference = 'Continue'

if (-not (Get-Command Get-TransportRule -ErrorAction SilentlyContinue)) {
    Write-Host "Not connected. Run Connect-ExchangeOnline first (read-only cmdlets only are used)"
    exit 2
}
if ($Days -lt 1) {
    Write-Host "-Days must be 1 or more"
    exit 2
}

$start = (Get-Date).AddDays(-$Days)
$end = Get-Date

function Write-Note {
    # human output; silent under -Json so stdout carries only the document
    param([string]$Text, [string]$Color = "")
    if ($Json) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

$script:out = @()
function Add-Finding {
    param([string]$Id, [string]$Severity, [string]$Title, [string]$Evidence, [string]$Action,
          [bool]$Verified = $true, [string]$Rule = "")
    $script:out += [pscustomobject][ordered]@{
        id = $Id; severity = $Severity; area = 'rules'; title = $Title
        evidence = $Evidence; action = $Action; verified = $Verified; rule = $Rule
    }
}

function Get-LiveSeverity {
    # a disabled rule does nothing today: keep it on the list, do not fail the run for it
    param([string]$Severity, $State)
    if ("$State" -eq 'Enabled') { return $Severity }
    return 'info'
}

function Get-Count {
    # entries in a multi-valued property, ignoring null and empty (a missing property is 0, not 1)
    param($Value)
    return @($Value | Where-Object { $null -ne $_ -and "$_" -ne '' }).Count
}

Write-Note "Transport rule audit - window: $start .. $end" Cyan

$rules = @(Get-TransportRule -ResultSize Unlimited)
Write-Note ("{0} rules total`n" -f $rules.Count)

# condition and exception values that can carry an authentication verdict...
$authValueProps = 'HeaderMatchesPatterns', 'HeaderContainsWords',
                  'ExceptIfHeaderMatchesPatterns', 'ExceptIfHeaderContainsWords'
# ...and the properties naming which header those values are matched against
$authHeaderProps = 'HeaderMatchesMessageHeader', 'HeaderContainsMessageHeader',
                   'ExceptIfHeaderMatchesMessageHeader', 'ExceptIfHeaderContainsMessageHeader'

$findings = @()
foreach ($r in $rules) {
    $isAllow = ($null -ne $r.SetSCL -and [int]$r.SetSCL -le 0)
    $isBlock = ($null -ne $r.SetSCL -and [int]$r.SetSCL -ge 5) -or $r.Quarantine -or $r.DeleteMessage
    $st = "$($r.State)"

    # auth gate: a dmarc=pass / compauth=pass value, or any match against the Authentication-Results header
    $authGate = @()
    foreach ($p in $authValueProps) {
        foreach ($v in @($r.$p)) {
            if ("$v" -match '(dmarc|compauth)=[^;]*pass') { $authGate += ("{0}: {1}" -f $p, $v) }
        }
    }
    foreach ($p in $authHeaderProps) {
        if ("$($r.$p)" -match 'Authentication-Results') { $authGate += ("{0}: {1}" -f $p, $r.$p) }
    }
    $authGated = ($authGate.Count -gt 0)

    # ip gate: sender IP ranges on a condition or an exception
    $ipRanges = @(@($r.SenderIpRanges) + @($r.ExceptIfSenderIpRanges) | Where-Object { $_ } | ForEach-Object { "$_" })
    $ipGated = ($ipRanges.Count -gt 0)

    $forgeable = $false
    if ($r.HeaderContainsMessageHeader -match 'Received' -or
        ($r.HeaderContainsWords -and -not $r.HeaderContainsMessageHeader)) {
        # header-string conditions whose header is attacker-writable
        $forgeable = $true
    }
    $exceptions = (Get-Count $r.ExceptIfFrom) + (Get-Count $r.ExceptIfSenderDomainIs) +
                  (Get-Count $r.ExceptIfSubjectContainsWords) +
                  (Get-Count $r.ExceptIfFromAddressContainsWords) + (Get-Count $r.ExceptIfFromAddressMatchesPatterns)

    $issues = @()
    if ($isAllow -and -not $authGated) {
        if ($ipGated) {
            $issues += "ALLOW-IP-GATED-ONLY: bypasses filtering keyed to sender IP, no authentication condition (weaker than auth)"
            Add-Finding 'RULES-005' (Get-LiveSeverity 'minor' $st) "Allow rule gated on sender IP only: $($r.Name)" `
                ("SetSCL={0}; SenderIpRanges={1}; State={2}" -f $r.SetSCL, ($ipRanges -join ','), $st) `
                "Add an Authentication-Results condition (dmarc=pass or compauth=pass) alongside the IP range, or confirm the range is dedicated to this sender and not a shared platform" $true $r.Name
        } else {
            $issues += "ALLOW-WITHOUT-AUTH: bypasses filtering with no authentication condition"
            Add-Finding 'RULES-001' (Get-LiveSeverity 'major' $st) "Allow rule without authentication gate: $($r.Name)" `
                ("SetSCL={0}; no dmarc=pass, compauth=pass or Authentication-Results condition; State={1}" -f $r.SetSCL, $st) `
                "Gate the rule on Authentication-Results header contains dmarc=pass; if the sender genuinely cannot authenticate, a spoof allow scoped to its sending infrastructure is the narrower bypass" $true $r.Name
        }
    }
    if ($isAllow -and $forgeable) {
        $issues += "FORGEABLE-CONDITION: allow keyed to attacker-writable header content"
        Add-Finding 'RULES-002' (Get-LiveSeverity 'major' $st) "Allow rule keyed to forgeable header content: $($r.Name)" `
            ("HeaderContainsMessageHeader={0}; HeaderContainsWords={1}; State={2}" -f $r.HeaderContainsMessageHeader, (@($r.HeaderContainsWords) -join ','), $st) `
            "Match on the Authentication-Results header instead; Received and custom headers can be written by any sender" $true $r.Name
    }
    if ($isBlock -and $r.Mode -ne 'Enforce') {
        $issues += "AUDIT-MODE-BLOCK: named/acts like a block but Mode=$($r.Mode) - it does nothing"
        Add-Finding 'RULES-003' (Get-LiveSeverity 'major' $st) "Block rule in audit mode: $($r.Name)" `
            ("Mode={0}; SetSCL={1}; Quarantine={2}; DeleteMessage={3}; State={4}" -f $r.Mode, $r.SetSCL, $r.Quarantine, $r.DeleteMessage, $st) `
            "Switch Mode to Enforce once the audit log shows only intended hits, or delete the rule if it is superseded" $true $r.Name
    }
    if ($exceptions -ge 20) {
        $issues += "LARGE-EXCEPTION-LIST: $exceptions entries - each one is spoofable past this rule"
        Add-Finding 'RULES-004' (Get-LiveSeverity 'minor' $st) "Large exception list: $($r.Name)" `
            ("{0} excepted addresses, domains or subjects; State={1}" -f $exceptions, $st) `
            "Prune entries that no longer send; move the rest behind an authentication condition so an exception only fires for mail that passed" $true $r.Name
    }

    $scl = $null
    if ($null -ne $r.SetSCL) { $scl = "$($r.SetSCL)" }
    $findings += [pscustomobject][ordered]@{
        Name = "$($r.Name)"; State = $st; Mode = "$($r.Mode)"; Priority = $r.Priority
        SCL = $scl; AuthGated = $authGated; IpGated = $ipGated; Exceptions = $exceptions
        AuthGate = ($authGate -join ' | '); IpRanges = ($ipRanges -join ',')
        Issues = ($issues -join ' | ')
    }
}

Write-Note "=== Findings ===" Yellow
$flagged = @($findings | Where-Object { $_.Issues })
foreach ($f in $flagged) {
    Write-Note ("`n  {0}  [prio {1}, {2}, SCL {3}]" -f $f.Name, $f.Priority, $f.State, $f.SCL)
    Write-Note ("    {0}" -f $f.Issues) Red
}
if ($flagged.Count -eq 0) { Write-Note "  none - unusually clean" }

$hits = @{}
if ($SkipHits) {
    Write-Note "`n=== Hit counts skipped (-SkipHits) ===" Yellow
} else {
    Write-Note "`n=== Hit counts (dead-rule check, last $Days days) ===" Yellow
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
    $dead = @($rules | Where-Object { $hits[$_.Name] -eq 0 -and $_.State -eq 'Enabled' })
    Write-Note ("  enabled rules with ZERO hits: {0}" -f $dead.Count)
    foreach ($d in $dead) {
        Write-Note ("    {0}" -f $d.Name)
        Add-Finding 'RULES-006' 'info' "Enabled rule with zero hits in $Days days: $($d.Name)" `
            ("hits=0 over {0} days" -f $Days) `
            "Confirm the rule is still needed; a dead rule is free cleanup and one less exception path to audit" $true $d.Name
    }
    $unknown = @($rules | Where-Object { $hits[$_.Name] -eq -1 })
    if ($unknown.Count -gt 0) {
        Write-Note ("  hit counts unavailable for {0} rules (report cmdlet failed)" -f $unknown.Count)
        Add-Finding 'RULES-007' 'info' ("Hit counts unavailable for {0} rules" -f $unknown.Count) `
            (($unknown | ForEach-Object { $_.Name }) -join ', ') `
            "Get-MailDetailTransportRuleReport failed or is not licensed; the dead-rule check is not verified for these" $false
    }
}
foreach ($f in $findings) {
    $h = $null
    if ($hits.ContainsKey($f.Name)) { $h = $hits[$f.Name] }
    $f | Add-Member -NotePropertyName Hits -NotePropertyValue $h
}

if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath | Out-Null }
    $findings | Export-Csv (Join-Path $ExportPath "transport_rule_audit.csv") -NoTypeInformation -Encoding UTF8
    $out | Export-Csv (Join-Path $ExportPath "transport_rule_findings.csv") -NoTypeInformation -Encoding UTF8
    Write-Note "`nCSV written to $ExportPath" Green
}

$rank = @{ info = 0; minor = 1; major = 2; blocking = 3 }
$worst = $null
foreach ($f in $out) {
    if ($null -eq $worst -or $rank[$f.severity] -gt $rank[$worst]) { $worst = $f.severity }
}
$actionable = @($out | Where-Object { $_.severity -eq 'major' -or $_.severity -eq 'blocking' }).Count
$code = 0
if ($actionable -gt 0) { $code = 1 }

if ($Json) {
    $doc = [ordered]@{
        tool = 'audit_rules'
        window = [ordered]@{ days = $Days; start = $start.ToString('s'); end = $end.ToString('s'); hits_checked = (-not $SkipHits) }
        rules = @($findings)
        findings = @($out)
        summary = [ordered]@{ rules = $rules.Count; flagged = $flagged.Count; findings = $out.Count
                              actionable = $actionable; worst = $worst; exit_code = $code }
        exit_code = $code
    }
    ConvertTo-Json -InputObject $doc -Depth 6
} else {
    Write-Note ("`n{0} findings, {1} major or blocking" -f $out.Count, $actionable)
    Write-Note "`nRemember: a rule gated on dmarc=pass cannot rescue a forgery. Everything else on the findings list can." Cyan
}
exit $code
