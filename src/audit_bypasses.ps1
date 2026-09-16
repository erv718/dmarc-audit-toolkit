<#
.SYNOPSIS
Read-only inventory of every non-transport-rule bypass in Exchange Online that
can hand a forgery past DMARC.

.DESCRIPTION
audit_rules.ps1 covers transport rules. This script covers everything else
that can deliver an unauthenticated message, because at enforcement the
question is not "is DMARC on" but "what still overrides it":

  - Anti-spam policy allow lists (Get-HostedContentFilterPolicy).
    AllowedSenders and AllowedSenderDomains skip spam filtering on the
    strength of an address alone, and the address is the one thing a forger
    controls. Reported as ALLOW-WITHOUT-AUTH, with counts and top entries.
  - Tenant Allow/Block List (Get-TenantAllowBlockListItems). Sender allows
    are honored only for mail that passes authentication, so they bypass the
    spam verdict but not DMARC. URL and file-hash allows are inventory only.
  - Spoof allows (Get-TenantAllowBlockListSpoofItems). Each one is an
    explicit instruction to deliver mail that fails spoof and DMARC checks.
    Every entry is listed; an Internal one (your own domain) is major.
  - Inbound connectors (Get-InboundConnector). TreatMessagesAsInternal and
    unpinned on-premises connectors move external mail inside the trust
    boundary; Enhanced Filtering skip lists (EFSkipLastIP, EFSkipIPs) decide
    which hop counts as the source for SPF and DMARC.
  - Anti-phish policies (Get-AntiPhishPolicy). Spoof intelligence, whether
    the sender's DMARC policy is honored, the DMARC actions, unauthenticated
    sender indicators, impersonation protection and its exclusion lists.
  - Accepted domains (Get-AcceptedDomain). InternalRelay and ExternalRelay
    domains re-emit mail for unknown recipients from your own tenant, which
    is the relay echo that inflates naive failure counts.

Every section is wrapped in try/catch: a cmdlet that is missing from your
licence or role is reported as a not-verified finding instead of aborting
the run.

Requires an interactive Exchange Online session:
    Connect-ExchangeOnline -UserPrincipalName you@yourdomain.example
    ./audit_bypasses.ps1 -ExportPath ./bypass-audit
    ./audit_bypasses.ps1 -Json > bypasses.json

-Json writes one document to stdout (inventory tables plus findings in the
shared shape: id, severity, area, title, evidence, action, verified) and
nothing else. -Top caps how many list entries are quoted per finding.
Exit codes: 0 clean, 1 findings at severity major or blocking, 2 not
connected or bad input.

Makes no changes. Read-only cmdlets throughout.
#>
param(
    [string]$ExportPath = "",
    [switch]$Json,
    [int]$Top = 10
)

$ErrorActionPreference = 'Continue'

if (-not (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue)) {
    Write-Host "Not connected. Run Connect-ExchangeOnline first (read-only cmdlets only are used)"
    exit 2
}
if ($Top -lt 1) {
    Write-Host "-Top must be 1 or more"
    exit 2
}

function Write-Note {
    # human output; silent under -Json so stdout carries only the document
    param([string]$Text, [string]$Color = "")
    if ($Json) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

$script:out = @()
$script:skipped = @()
function Add-Finding {
    param([string]$Id, [string]$Severity, [string]$Title, [string]$Evidence, [string]$Action,
          [bool]$Verified = $true, [string]$Object = "")
    $script:out += [pscustomobject][ordered]@{
        id = $Id; severity = $Severity; area = 'rules'; title = $Title
        evidence = $Evidence; action = $Action; verified = $Verified; object = $Object
    }
}

function Invoke-Section {
    # runs one read-only query; a failure becomes a not-verified finding and an empty result, never a crash
    param([string]$Label, [scriptblock]$Query)
    try {
        return ,@(& $Query)
    } catch {
        $script:skipped += $Label
        Add-Finding 'RULES-118' 'info' "$Label not checked" `
            ("cmdlet failed or unavailable: " + $_.Exception.Message) `
            "Re-run with a role that includes this cmdlet, or confirm the feature is licensed on this tenant" $false $Label
        return ,@()
    }
}

function Get-Strings {
    # a multi-valued property as plain strings, nulls and blanks dropped
    param($Value)
    return ,@($Value | Where-Object { $null -ne $_ } | ForEach-Object { "$_" } | Where-Object { $_ -ne '' })
}

function Format-Top {
    # first N entries joined, with a count of the rest
    param($Items, [int]$N)
    $a = @($Items | Where-Object { $null -ne $_ -and "$_" -ne '' })
    if ($a.Count -eq 0) { return "(none)" }
    $s = (@($a | Select-Object -First $N) -join ', ')
    if ($a.Count -gt $N) { $s += (" ... +{0} more" -f ($a.Count - $N)) }
    return $s
}

Write-Note "Bypass inventory - everything outside transport rules that can override a DMARC verdict" Cyan

# --- anti-spam policy allow lists -------------------------------------------
Write-Note "`n=== Anti-spam policy allow lists (Get-HostedContentFilterPolicy) ===" Yellow
$spamRuleState = @{}
$spamRules = Invoke-Section 'HostedContentFilterRule' { Get-HostedContentFilterRule -ErrorAction Stop }
foreach ($sr in $spamRules) { $spamRuleState["$($sr.HostedContentFilterPolicy)"] = "$($sr.State)" }
$spamPolicies = Invoke-Section 'HostedContentFilterPolicy' { Get-HostedContentFilterPolicy -ErrorAction Stop }
$spamRows = @()
foreach ($p in $spamPolicies) {
    $name = "$($p.Name)"
    $senders = Get-Strings $p.AllowedSenders
    $domains = Get-Strings $p.AllowedSenderDomains
    $assigned = 'default'
    if (-not $p.IsDefault) {
        $assigned = 'unassigned'
        if ($spamRuleState.ContainsKey($name)) { $assigned = $spamRuleState[$name] }
    }
    $live = ($assigned -eq 'default' -or $assigned -eq 'Enabled')
    $sev = 'major'
    if (-not $live) { $sev = 'info' }
    if ($domains.Count -gt 0) {
        Add-Finding 'RULES-101' $sev ("ALLOW-WITHOUT-AUTH: anti-spam policy allows {0} sender domains by address: {1}" -f $domains.Count, $name) `
            ("AllowedSenderDomains ({0}): {1}; assignment={2}" -f $domains.Count, (Format-Top $domains $Top), $assigned) `
            "A domain allow here skips spam filtering for anyone who writes that domain in the From header. Remove it; if the sender needs a bypass, use a transport rule gated on dmarc=pass, and if it cannot authenticate, a spoof allow scoped to its sending infrastructure" $true $name
    }
    if ($senders.Count -gt 0) {
        Add-Finding 'RULES-102' $sev ("ALLOW-WITHOUT-AUTH: anti-spam policy allows {0} sender addresses: {1}" -f $senders.Count, $name) `
            ("AllowedSenders ({0}): {1}; assignment={2}" -f $senders.Count, (Format-Top $senders $Top), $assigned) `
            "An address allow here is matched on the forgeable From address. Remove it or replace it with an authentication-gated transport rule" $true $name
    }
    $spamRows += [pscustomobject][ordered]@{
        Policy = $name; IsDefault = [bool]$p.IsDefault; Assignment = $assigned
        AllowedSenders = $senders.Count; AllowedSenderDomains = $domains.Count
        TopSenders = (Format-Top $senders $Top); TopDomains = (Format-Top $domains $Top)
    }
    Write-Note ("  {0} [{1}]: {2} allowed senders, {3} allowed domains" -f $name, $assigned, $senders.Count, $domains.Count)
}

# --- tenant allow/block list -------------------------------------------------
Write-Note "`n=== Tenant Allow/Block List allow entries ===" Yellow
$tabl = [ordered]@{ Sender = 0; Url = 0; FileHash = 0 }
foreach ($lt in 'Sender', 'Url', 'FileHash') {
    $items = Invoke-Section "TenantAllowBlockListItems/$lt" { Get-TenantAllowBlockListItems -ListType $lt -Allow -ErrorAction Stop }
    $values = @($items | ForEach-Object { "$($_.Value)" })
    $tabl[$lt] = $values.Count
    Write-Note ("  {0} allows: {1}" -f $lt, $values.Count)
    if ($values.Count -eq 0) { continue }
    if ($lt -eq 'Sender') {
        $sim = @($items | Where-Object { "$($_.ListSubType)" -eq 'AdvancedDelivery' }).Count
        $noExpiry = @($items | Where-Object { $null -eq $_.ExpirationDate }).Count
        Add-Finding 'RULES-103' 'minor' ("Tenant Allow/Block List: {0} sender allow entries" -f $values.Count) `
            ("entries: {0}; without expiry: {1}; phishing-simulation (AdvancedDelivery) entries: {2}" -f (Format-Top $values $Top), $noExpiry, $sim) `
            "Per Microsoft's documented behaviour a sender allow applies only to mail that passes authentication, so it bypasses the spam verdict, not DMARC. Still review entries with no expiry and remove the ones whose submission is closed" $true 'TenantAllowBlockList/Sender'
    } else {
        Add-Finding 'RULES-104' 'info' ("Tenant Allow/Block List: {0} {1} allow entries" -f $values.Count, $lt) `
            (Format-Top $values $Top) `
            "Not an authentication bypass; inventory only. Expire entries that no longer need an override" $true "TenantAllowBlockList/$lt"
    }
}

# --- spoof allows: explicit DMARC bypasses ----------------------------------
Write-Note "`n=== Spoof allow entries (Get-TenantAllowBlockListSpoofItems -Action Allow) ===" Yellow
$spoof = Invoke-Section 'TenantAllowBlockListSpoofItems' { Get-TenantAllowBlockListSpoofItems -Action Allow -ErrorAction Stop }
$spoofRows = @()
foreach ($s in $spoof) {
    $type = "$($s.SpoofType)"
    $sev = 'minor'
    $id = 'RULES-106'
    if ($type -eq 'Internal') { $sev = 'major'; $id = 'RULES-105' }
    Add-Finding $id $sev ("Spoof allow: {0} from {1} ({2})" -f $s.SpoofedUser, $s.SendingInfrastructure, $type) `
        ("SpoofedUser={0}; SendingInfrastructure={1}; SpoofType={2}; Action={3}" -f $s.SpoofedUser, $s.SendingInfrastructure, $type, $s.Action) `
        "This entry delivers mail that fails spoof and DMARC checks from that infrastructure. Keep it only while the sender is being fixed (DKIM for your domain); remove it once aggregate reports show the source passing" $true ("{0}|{1}" -f $s.SpoofedUser, $s.SendingInfrastructure)
    $spoofRows += [pscustomobject][ordered]@{
        SpoofedUser = "$($s.SpoofedUser)"; SendingInfrastructure = "$($s.SendingInfrastructure)"
        SpoofType = $type; Action = "$($s.Action)"
    }
    Write-Note ("  {0}  <-  {1}  [{2}]" -f $s.SpoofedUser, $s.SendingInfrastructure, $type) Red
}
if ($spoof.Count -eq 0) { Write-Note "  none" }

# --- inbound connectors -------------------------------------------------------
Write-Note "`n=== Inbound connectors (Get-InboundConnector) ===" Yellow
$connectors = Invoke-Section 'InboundConnector' { Get-InboundConnector -ErrorAction Stop }
$connRows = @()
foreach ($c in $connectors) {
    $name = "$($c.Name)"
    $ips = Get-Strings $c.SenderIPAddresses
    $doms = Get-Strings $c.SenderDomains
    $skipIps = Get-Strings $c.EFSkipIPs
    $efUsers = Get-Strings $c.EFUsers
    $enabled = [bool]$c.Enabled
    $type = "$($c.ConnectorType)"
    $cert = "$($c.TlsSenderCertificateName)"
    $pinned = ($ips.Count -gt 0 -or $cert -ne '')
    $sevMajor = 'major'
    $sevMinor = 'minor'
    if (-not $enabled) { $sevMajor = 'info'; $sevMinor = 'info' }
    $issues = @()
    if ($c.TreatMessagesAsInternal) {
        $issues += 'TREATS-AS-INTERNAL'
        Add-Finding 'RULES-107' $sevMajor "Connector treats external mail as internal: $name" `
            ("ConnectorType={0}; Enabled={1}; SenderDomains={2}; SenderIPAddresses={3}; certificate={4}" -f $type, $enabled, (Format-Top $doms $Top), (Format-Top $ips $Top), $cert) `
            "Mail on this connector skips the external-sender treatment (spoof checks, external tagging). Confirm every listed source is your own on-premises or gateway infrastructure; if it is a third party, turn TreatMessagesAsInternal off" $true $name
    }
    if ($c.EFSkipLastIP -or $skipIps.Count -gt 0) {
        $issues += 'EF-SKIP'
        Add-Finding 'RULES-108' 'info' "Enhanced Filtering skip list on connector: $name" `
            ("EFSkipLastIP={0}; EFSkipIPs={1}; EFUsers={2}" -f [bool]$c.EFSkipLastIP, (Format-Top $skipIps $Top), $efUsers.Count) `
            "Correct for a gateway in front of EOP: SPF and DMARC are evaluated on the hop before the skipped IPs. Verify the skip list holds only the gateway's IPs; an over-broad list lets any earlier hop be trusted as the origin" $true $name
    }
    if ($type -eq 'OnPremises' -and -not $pinned) {
        $issues += 'UNPINNED-ONPREM'
        Add-Finding 'RULES-109' $sevMinor "On-premises connector not pinned to IP or certificate: $name" `
            ("ConnectorType={0}; Enabled={1}; SenderIPAddresses=(none); TlsSenderCertificateName=(none); RestrictDomainsToIPAddresses={2}; CloudServicesMailEnabled={3}" -f $type, $enabled, [bool]$c.RestrictDomainsToIPAddresses, [bool]$c.CloudServicesMailEnabled) `
            "Anything reaching EOP can claim to be your on-premises hop and inherit its trust, including a pre-stamped SCL. Pin the connector to the gateway IPs or its TLS certificate" $true $name
    }
    $connRows += [pscustomobject][ordered]@{
        Name = $name; ConnectorType = $type; Enabled = $enabled
        SenderDomains = ($doms -join ','); SenderIPAddresses = ($ips -join ',')
        RestrictDomainsToIPAddresses = [bool]$c.RestrictDomainsToIPAddresses
        RestrictDomainsToCertificate = [bool]$c.RestrictDomainsToCertificate
        TlsSenderCertificateName = $cert; TreatMessagesAsInternal = [bool]$c.TreatMessagesAsInternal
        EFSkipLastIP = [bool]$c.EFSkipLastIP; EFSkipIPs = ($skipIps -join ','); EFUsers = $efUsers.Count
        CloudServicesMailEnabled = [bool]$c.CloudServicesMailEnabled
        Issues = ($issues -join ' | ')
    }
    $line = ("  {0} [{1}, enabled={2}] ips={3} domains={4}" -f $name, $type, $enabled, $ips.Count, $doms.Count)
    if ($issues.Count -gt 0) { Write-Note ($line + "  " + ($issues -join ' | ')) Red } else { Write-Note $line }
}
if ($connectors.Count -eq 0) { Write-Note "  none" }

# --- anti-phish policies ----------------------------------------------------
Write-Note "`n=== Anti-phish policies (Get-AntiPhishPolicy) ===" Yellow
$phish = Invoke-Section 'AntiPhishPolicy' { Get-AntiPhishPolicy -ErrorAction Stop }
$phishRows = @()
foreach ($p in $phish) {
    $name = "$($p.Name)"
    $enabled = [bool]$p.Enabled
    $isDefault = [bool]$p.IsDefault
    $maj = 'major'
    $min = 'minor'
    if (-not $enabled) { $maj = 'info'; $min = 'info' }
    $honor = $null
    $honorProp = $p.PSObject.Properties['HonorDmarcPolicy']
    if ($null -ne $honorProp) { $honor = [bool]$honorProp.Value }
    $users = Get-Strings $p.TargetedUsersToProtect
    $exS = Get-Strings $p.ExcludedSenders
    $exD = Get-Strings $p.ExcludedDomains
    $exTotal = $exS.Count + $exD.Count
    $issues = @()
    if (-not $enabled) {
        $issues += 'POLICY-DISABLED'
        Add-Finding 'RULES-120' 'info' "Anti-phish policy disabled: $name" ("Enabled={0}; IsDefault={1}" -f $enabled, $isDefault) `
            "Findings for this policy are informational until it is enabled and assigned" $true $name
    }
    if (-not $p.EnableSpoofIntelligence) {
        $issues += 'SPOOF-INTEL-OFF'
        Add-Finding 'RULES-110' $maj "Spoof intelligence off: $name" "EnableSpoofIntelligence=False" `
            "Turn spoof intelligence on. With it off, unauthenticated senders are not evaluated and the DMARC actions in this policy never fire" $true $name
    }
    if ($null -ne $honor -and -not $honor) {
        $issues += 'DMARC-NOT-HONORED'
        Add-Finding 'RULES-111' $maj "Sender DMARC policy not honored: $name" `
            ("HonorDmarcPolicy=False; DmarcRejectAction={0}; DmarcQuarantineAction={1}" -f $p.DmarcRejectAction, $p.DmarcQuarantineAction) `
            "Enable HonorDmarcPolicy so p=reject and p=quarantine published by other domains are applied as published; without it the tenant substitutes spoof intelligence's own verdict" $true $name
    }
    if (-not $p.EnableUnauthenticatedSender -or -not $p.EnableViaTag) {
        $issues += 'UNAUTH-INDICATORS-OFF'
        Add-Finding 'RULES-112' $min "Unauthenticated sender indicators off: $name" `
            ("EnableUnauthenticatedSender={0}; EnableViaTag={1}" -f [bool]$p.EnableUnauthenticatedSender, [bool]$p.EnableViaTag) `
            "Turn both on; users lose the question-mark avatar and the via tag that mark mail that did not authenticate" $true $name
    }
    if (-not $p.EnableMailboxIntelligence -or -not $p.EnableMailboxIntelligenceProtection) {
        $issues += 'MAILBOX-INTEL-OFF'
        Add-Finding 'RULES-113' $min "Mailbox intelligence protection off: $name" `
            ("EnableMailboxIntelligence={0}; EnableMailboxIntelligenceProtection={1}" -f [bool]$p.EnableMailboxIntelligence, [bool]$p.EnableMailboxIntelligenceProtection) `
            "Requires Defender for Office 365 Plan 1. If licensed, enable both so contact-graph impersonation gets an action, not just a signal" $true $name
    }
    if (-not $p.EnableTargetedUserProtection -or $users.Count -eq 0) {
        $issues += 'USER-IMPERSONATION-OFF'
        Add-Finding 'RULES-114' $min "User impersonation protection off or empty: $name" `
            ("EnableTargetedUserProtection={0}; TargetedUsersToProtect={1}" -f [bool]$p.EnableTargetedUserProtection, $users.Count) `
            "Requires Defender for Office 365 Plan 1. List executives and payment approvers: the display names a forger borrows once your domain is at p=reject and the exact-domain spoof stops working" $true $name
    }
    if (-not $p.EnableOrganizationDomainsProtection) {
        $issues += 'DOMAIN-IMPERSONATION-OFF'
        Add-Finding 'RULES-119' $min "Organization domain impersonation protection off: $name" `
            "EnableOrganizationDomainsProtection=False" `
            "Requires Defender for Office 365 Plan 1. Enable it so lookalikes of your accepted domains are caught; DMARC does nothing for lookalike domains" $true $name
    }
    if ($exTotal -gt 0) {
        $issues += 'IMPERSONATION-EXCLUSIONS'
        $sev = $min
        if ($exTotal -ge 20 -and $enabled) { $sev = $maj }
        Add-Finding 'RULES-115' $sev ("Impersonation protection exclusions ({0}): {1}" -f $exTotal, $name) `
            ("ExcludedSenders ({0}): {1}; ExcludedDomains ({2}): {3}" -f $exS.Count, (Format-Top $exS $Top), $exD.Count, (Format-Top $exD $Top)) `
            "Each exclusion is matched on the address a forger controls. Prune the list, and prefer fixing the excluded sender's authentication over excluding it" $true $name
    }
    Add-Finding 'RULES-116' 'info' "DMARC actions in policy: $name" `
        ("DmarcRejectAction={0}; DmarcQuarantineAction={1}; AuthenticationFailAction={2}; HonorDmarcPolicy={3}; Enabled={4}" -f $p.DmarcRejectAction, $p.DmarcQuarantineAction, $p.AuthenticationFailAction, $honor, $enabled) `
        "Recorded for the report. Reject and Quarantine match what senders publish; softer actions keep forgeries in mailboxes" $true $name
    $phishRows += [pscustomobject][ordered]@{
        Policy = $name; Enabled = $enabled; IsDefault = $isDefault
        EnableSpoofIntelligence = [bool]$p.EnableSpoofIntelligence; HonorDmarcPolicy = $honor
        DmarcRejectAction = "$($p.DmarcRejectAction)"; DmarcQuarantineAction = "$($p.DmarcQuarantineAction)"
        AuthenticationFailAction = "$($p.AuthenticationFailAction)"
        EnableUnauthenticatedSender = [bool]$p.EnableUnauthenticatedSender; EnableViaTag = [bool]$p.EnableViaTag
        EnableMailboxIntelligence = [bool]$p.EnableMailboxIntelligence
        EnableMailboxIntelligenceProtection = [bool]$p.EnableMailboxIntelligenceProtection
        EnableTargetedUserProtection = [bool]$p.EnableTargetedUserProtection; TargetedUsersToProtect = $users.Count
        EnableOrganizationDomainsProtection = [bool]$p.EnableOrganizationDomainsProtection
        ExcludedSenders = $exS.Count; ExcludedDomains = $exD.Count
        Issues = ($issues -join ' | ')
    }
    $line = ("  {0} [enabled={1}, default={2}] spoofIntel={3} honorDmarc={4} reject={5} quarantine={6}" -f $name, $enabled, $isDefault, [bool]$p.EnableSpoofIntelligence, $honor, $p.DmarcRejectAction, $p.DmarcQuarantineAction)
    if ($issues.Count -gt 0) { Write-Note ($line + "  " + ($issues -join ' | ')) Red } else { Write-Note $line }
}
if ($phish.Count -eq 0) { Write-Note "  none" }

# --- accepted domains: relay echo sources ------------------------------------
Write-Note "`n=== Accepted domains (Get-AcceptedDomain) ===" Yellow
$domainsAll = Invoke-Section 'AcceptedDomain' { Get-AcceptedDomain -ErrorAction Stop }
$relayRows = @()
foreach ($d in $domainsAll) {
    $t = "$($d.DomainType)"
    $dn = "$($d.DomainName)"
    if ($t -eq 'InternalRelay' -or $t -eq 'ExternalRelay') {
        Add-Finding 'RULES-117' 'minor' ("{0} accepted domain: {1}" -f $t, $dn) ("DomainType={0}; Default={1}" -f $t, [bool]$d.Default) `
            "Mail for recipients the tenant does not know is relayed onward from your own IPs and shows up as a second, failing leg for the same Message-ID: the relay echo dedupe.py collapses. Make the domain Authoritative once every recipient lives in the tenant, or make sure the relay target is in your SPF and signs with DKIM" $true $dn
        $relayRows += [pscustomobject][ordered]@{ DomainName = $dn; DomainType = $t; Default = [bool]$d.Default }
        Write-Note ("  {0}  [{1}]" -f $dn, $t) Red
    }
}
Write-Note ("  {0} accepted domains, {1} relay" -f $domainsAll.Count, $relayRows.Count)

# --- roll-up -------------------------------------------------------------------
$rank = @{ info = 0; minor = 1; major = 2; blocking = 3 }
$worst = $null
foreach ($f in $out) {
    if ($null -eq $worst -or $rank[$f.severity] -gt $rank[$worst]) { $worst = $f.severity }
}
$actionable = @($out | Where-Object { $_.severity -eq 'major' -or $_.severity -eq 'blocking' }).Count
$code = 0
if ($actionable -gt 0) { $code = 1 }

Write-Note "`n=== Findings ===" Yellow
foreach ($f in $out) {
    $tag = ''
    if (-not $f.verified) { $tag = ' (not verified)' }
    $color = ''
    if ($f.severity -eq 'major' -or $f.severity -eq 'blocking') { $color = 'Red' }
    Write-Note ("  [{0}] {1} {2}{3}" -f $f.severity, $f.id, $f.title, $tag) $color
}
Write-Note ("`n{0} findings, {1} major or blocking; {2} sections not checked" -f $out.Count, $actionable, $skipped.Count)

if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath | Out-Null }
    $out | Export-Csv (Join-Path $ExportPath "bypass_findings.csv") -NoTypeInformation -Encoding UTF8
    $spoofRows | Export-Csv (Join-Path $ExportPath "spoof_allows.csv") -NoTypeInformation -Encoding UTF8
    $connRows | Export-Csv (Join-Path $ExportPath "inbound_connectors.csv") -NoTypeInformation -Encoding UTF8
    $phishRows | Export-Csv (Join-Path $ExportPath "antiphish_policies.csv") -NoTypeInformation -Encoding UTF8
    $spamRows | Export-Csv (Join-Path $ExportPath "spam_policy_allows.csv") -NoTypeInformation -Encoding UTF8
    Write-Note "`nCSV written to $ExportPath" Green
}

if ($Json) {
    $doc = [ordered]@{
        tool = 'audit_bypasses'
        top = $Top
        counts = [ordered]@{
            spam_policies = $spamRows.Count
            tabl_sender_allows = $tabl['Sender']; tabl_url_allows = $tabl['Url']; tabl_filehash_allows = $tabl['FileHash']
            spoof_allows = $spoofRows.Count; inbound_connectors = $connRows.Count
            antiphish_policies = $phishRows.Count; accepted_domains = $domainsAll.Count; relay_domains = $relayRows.Count
        }
        spam_policies = @($spamRows)
        spoof_allows = @($spoofRows)
        inbound_connectors = @($connRows)
        antiphish_policies = @($phishRows)
        relay_domains = @($relayRows)
        findings = @($out)
        skipped = @($skipped)
        summary = [ordered]@{ findings = $out.Count; actionable = $actionable; worst = $worst
                              skipped = $skipped.Count; exit_code = $code }
        exit_code = $code
    }
    ConvertTo-Json -InputObject $doc -Depth 6
} else {
    Write-Note "`nRemember: every entry above is a place a forgery can still land after p=reject. The spoof allow list is the one to read line by line." Cyan
}
exit $code
