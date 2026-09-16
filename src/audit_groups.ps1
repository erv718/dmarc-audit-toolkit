<#
.SYNOPSIS
Read-only audit of the distribution-list and forwarding risks that bite when
DMARC reaches enforcement.

.DESCRIPTION
Groups and forwards re-emit other people's mail from your tenant. That is
harmless at p=none and a delivery failure at p=reject, because the re-sent
copy leaves with the original From header and your IP: SPF no longer
aligns, and DKIM survives only if nothing touched the body on the way
through. This script finds the paths where that happens:

  - Groups (Get-DistributionGroup, Get-DynamicDistributionGroup,
    Get-UnifiedGroup). RequireSenderAuthenticationEnabled = False means the
    group accepts mail from outside the tenant, so anyone can post to it
    with a forged sender. Groups whose members include external recipients
    (Get-DistributionGroupMember with RecipientTypeDetails MailContact or
    MailUser, guests for M365 groups) redistribute to external mailboxes and
    carry the alignment break above. A group that is both open and
    redistributes external is your tenant acting as an open relay for
    DMARC-failing mail. Nested groups are not expanded.
  - Mailbox forwarding (Get-Mailbox with ForwardingSmtpAddress or
    ForwardingAddress set). External targets are flagged; internal ones are
    listed so the inventory is complete.
  - Inbox rules with ForwardTo, ForwardAsAttachmentTo or RedirectTo. This is
    one call per mailbox and slow on a large tenant, so it is opt-in with
    -IncludeInboxRules. Only external targets are flagged.
  - Remote domains (Get-RemoteDomain AutoForwardEnabled) and the outbound
    spam policy AutoForwardingMode, which is the tenant-wide switch.

Every section is wrapped in try/catch: a cmdlet that is missing from your
licence or role is reported as a not-verified finding instead of aborting
the run. Membership is read per group; -SkipMembers skips that for a fast
first pass.

Requires an interactive Exchange Online session:
    Connect-ExchangeOnline -UserPrincipalName you@yourdomain.example
    ./audit_groups.ps1 -ExportPath ./group-audit
    ./audit_groups.ps1 -IncludeInboxRules -Json > groups.json

-Json writes one document to stdout (group and forwarding tables plus
findings in the shared shape: id, severity, area, title, evidence, action,
verified) and nothing else. -Top caps how many rows the console listing
shows per section; the JSON and CSV carry everything. Exit codes: 0 clean,
1 findings at severity major or blocking, 2 not connected or bad input.

Makes no changes. Read-only cmdlets throughout.
#>
param(
    [string]$ExportPath = "",
    [switch]$Json,
    [int]$Top = 25,
    [switch]$IncludeInboxRules,
    [switch]$SkipMembers
)

$ErrorActionPreference = 'Continue'

if (-not (Get-Command Get-DistributionGroup -ErrorAction SilentlyContinue)) {
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
        id = $Id; severity = $Severity; area = 'groups'; title = $Title
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
        Add-Finding 'GROUPS-009' 'info' "$Label not checked" `
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

Write-Note "Group and forwarding audit - the alignment breaks that appear at enforcement" Cyan

# accepted domains decide internal vs external for every address below
$accepted = Invoke-Section 'AcceptedDomain' { Get-AcceptedDomain -ErrorAction Stop }
$internalDomains = @{}
foreach ($d in $accepted) { $internalDomains["$($d.DomainName)".ToLower()] = $true }

function Test-External {
    # true when the address sits outside every accepted domain; with no domain list we err toward external
    param([string]$Address)
    $a = "$Address" -replace '^smtp:', ''
    if ($a -notmatch '@') { return $false }
    $dom = $a.Split('@')[-1].Trim().ToLower()
    return (-not $internalDomains.ContainsKey($dom))
}

# --- groups ---------------------------------------------------------------------
function Get-ExternalMembers {
    # addresses of members outside the tenant; $null when membership could not be read
    param($Group, [string]$Kind)
    $members = @()
    try {
        if ($Kind -eq 'DistributionGroup') {
            $members = @(Get-DistributionGroupMember -Identity "$($Group.Identity)" -ResultSize Unlimited -ErrorAction Stop)
        } elseif ($Kind -eq 'DynamicDistributionGroup') {
            if (Get-Command Get-DynamicDistributionGroupMember -ErrorAction SilentlyContinue) {
                $members = @(Get-DynamicDistributionGroupMember -Identity "$($Group.Identity)" -ResultSize Unlimited -ErrorAction Stop)
            } else {
                $members = @(Get-Recipient -RecipientPreviewFilter "$($Group.RecipientFilter)" -ResultSize Unlimited -ErrorAction Stop)
            }
        } else {
            $members = @(Get-UnifiedGroupLinks -Identity "$($Group.Identity)" -LinkType Members -ResultSize Unlimited -ErrorAction Stop)
        }
    } catch { return $null }
    $ext = @()
    foreach ($m in $members) {
        # MailContact, MailUser and GuestMailUser all live outside the tenant
        if ("$($m.RecipientTypeDetails)" -match 'MailContact|MailUser') { $ext += "$($m.PrimarySmtpAddress)" }
    }
    return ,$ext
}

$script:groupRows = @()
function Test-Group {
    param($Group, [string]$Kind)
    $name = "$($Group.DisplayName)"
    if (-not $name) { $name = "$($Group.Name)" }
    $addr = "$($Group.PrimarySmtpAddress)"
    $open = ($Group.RequireSenderAuthenticationEnabled -eq $false)
    $ext = $null
    $memberCheck = 'skipped'
    if (-not $SkipMembers) {
        $ext = Get-ExternalMembers $Group $Kind
        if ($null -eq $ext) { $memberCheck = 'failed' } else { $memberCheck = 'ok' }
    }
    $extCount = 0
    if ($null -ne $ext) { $extCount = $ext.Count }
    $restrict = (Get-Strings $Group.AcceptMessagesOnlyFrom).Count +
                (Get-Strings $Group.AcceptMessagesOnlyFromDLMembers).Count +
                (Get-Strings $Group.AcceptMessagesOnlyFromSendersOrMembers).Count
    $issues = @()
    if ($open -and $extCount -gt 0) {
        $issues += 'OPEN-AND-REDISTRIBUTES-EXTERNAL'
        Add-Finding 'GROUPS-003' 'major' "Open to external senders and redistributes to external members: $addr" `
            ("{0}; RequireSenderAuthenticationEnabled=False; sender restrictions={1}; external members ({2}): {3}" -f $Kind, $restrict, $extCount, (Format-Top $ext $Top)) `
            "Anyone outside can post to this group and your tenant re-sends it to external mailboxes with the original From and your IP. At enforcement the outside receiver drops the copy, and until then your IPs are the visible source of the forgery. Require sender authentication, or remove the external members" $true $addr
    } elseif ($open) {
        $issues += 'OPEN-TO-EXTERNAL'
        Add-Finding 'GROUPS-001' 'minor' "Open to external senders (spoofable): $addr" `
            ("{0}; RequireSenderAuthenticationEnabled=False; sender restrictions={1}; member check={2}" -f $Kind, $restrict, $memberCheck) `
            "Anyone can mail this group with a forged sender; sender restriction lists are matched on the forgeable address. Require sender authentication unless the group is a deliberate public intake, and then watch it in the spoof reports" $true $addr
    } elseif ($extCount -gt 0) {
        $issues += 'REDISTRIBUTES-EXTERNAL'
        Add-Finding 'GROUPS-002' 'minor' "Redistributes to external - alignment break risk at enforcement: $addr" `
            ("{0}; external members ({1}): {2}" -f $Kind, $extCount, (Format-Top $ext $Top)) `
            "Third-party mail sent to this group leaves your tenant for the external members with the original From and your IP; SPF fails and only an intact DKIM signature keeps it deliverable at p=reject. Confirm the external members are intended and avoid disclaimers or footers on this path, which break DKIM" $true $addr
    }
    if ($memberCheck -eq 'failed') {
        $issues += 'MEMBERS-NOT-READ'
        Add-Finding 'GROUPS-009' 'info' "Membership not read: $addr" "$Kind membership cmdlet failed" `
            "Re-run with a role that can read membership, or check the group by hand" $false $addr
    }
    $script:groupRows += [pscustomobject][ordered]@{
        Name = $name; Address = $addr; Kind = $Kind
        RequireSenderAuthentication = (-not $open); SenderRestrictions = $restrict
        ExternalMembers = $extCount; ExternalMemberSample = (Format-Top $ext $Top)
        MemberCheck = $memberCheck; Issues = ($issues -join ' | ')
    }
}

Write-Note "`n=== Groups ===" Yellow
$dgs = Invoke-Section 'DistributionGroup' { Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop }
foreach ($g in $dgs) { Test-Group $g 'DistributionGroup' }
$ddgs = Invoke-Section 'DynamicDistributionGroup' { Get-DynamicDistributionGroup -ResultSize Unlimited -ErrorAction Stop }
foreach ($g in $ddgs) { Test-Group $g 'DynamicDistributionGroup' }
$ugs = Invoke-Section 'UnifiedGroup' { Get-UnifiedGroup -ResultSize Unlimited -ErrorAction Stop }
foreach ($g in $ugs) { Test-Group $g 'UnifiedGroup' }

$flaggedGroups = @($groupRows | Where-Object { $_.Issues })
Write-Note ("  {0} groups ({1} distribution, {2} dynamic, {3} M365), {4} flagged, membership check: {5}" -f $groupRows.Count, $dgs.Count, $ddgs.Count, $ugs.Count, $flaggedGroups.Count, (-not $SkipMembers))
foreach ($g in @($flaggedGroups | Select-Object -First $Top)) {
    Write-Note ("    {0}  [{1}]  {2}" -f $g.Address, $g.Kind, $g.Issues) Red
}
if ($flaggedGroups.Count -gt $Top) { Write-Note ("    ... {0} more, use -Json or -ExportPath for the full list" -f ($flaggedGroups.Count - $Top)) }

# --- mailbox forwarding ---------------------------------------------------------
Write-Note "`n=== Mailbox forwarding (Get-Mailbox ForwardingSmtpAddress / ForwardingAddress) ===" Yellow
$fwdBoxes = Invoke-Section 'Mailbox forwarding' { Get-Mailbox -ResultSize Unlimited -Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null' -ErrorAction Stop }
$recipCache = @{}
function Resolve-Forward {
    # ForwardingAddress is a directory object; look each distinct target up once
    param([string]$Identity)
    if ($recipCache.ContainsKey($Identity)) { return $recipCache[$Identity] }
    $r = $null
    try {
        $x = Get-Recipient -Identity $Identity -ErrorAction Stop
        $r = [pscustomobject]@{ Address = "$($x.PrimarySmtpAddress)"; Type = "$($x.RecipientTypeDetails)" }
    } catch { }
    $recipCache[$Identity] = $r
    return $r
}
$fwdRows = @()
foreach ($m in $fwdBoxes) {
    $box = "$($m.PrimarySmtpAddress)"
    $targets = @()
    if ($m.ForwardingSmtpAddress) {
        $targets += [pscustomobject]@{ Source = 'ForwardingSmtpAddress'; Address = ("$($m.ForwardingSmtpAddress)" -replace '^smtp:', ''); Type = 'smtp' }
    }
    if ($m.ForwardingAddress) {
        $res = Resolve-Forward "$($m.ForwardingAddress)"
        if ($null -eq $res) {
            $targets += [pscustomobject]@{ Source = 'ForwardingAddress'; Address = "$($m.ForwardingAddress)"; Type = 'unresolved' }
        } else {
            $targets += [pscustomobject]@{ Source = 'ForwardingAddress'; Address = $res.Address; Type = $res.Type }
        }
    }
    $keep = [bool]$m.DeliverToMailboxAndForward
    foreach ($t in $targets) {
        $verified = ($t.Type -ne 'unresolved')
        $external = (Test-External $t.Address) -or ($t.Type -match 'MailContact|MailUser') -or (-not $verified)
        if ($external) {
            Add-Finding 'GROUPS-004' 'minor' "Mailbox forwards to external address: $box" `
                ("{0}={1} ({2}); DeliverToMailboxAndForward={3}" -f $t.Source, $t.Address, $t.Type, $keep) `
                "Third-party mail forwarded out of the tenant leaves with the original From and your IP: SPF fails and DKIM survives only if nothing modified the body. At p=reject on the sender side the outside receiver drops it. Confirm the forward is intended, and keep disclaimers off this path" $verified $box
        } else {
            Add-Finding 'GROUPS-005' 'info' "Mailbox forwards internally: $box" `
                ("{0}={1} ({2}); DeliverToMailboxAndForward={3}" -f $t.Source, $t.Address, $t.Type, $keep) `
                "Internal forward, no alignment impact; listed so the forwarding inventory is complete" $verified $box
        }
        $fwdRows += [pscustomobject][ordered]@{
            Mailbox = $box; Source = $t.Source; Target = $t.Address; TargetType = $t.Type; External = $external
            DeliverToMailboxAndForward = $keep; RuleName = ''; RuleEnabled = $null
        }
    }
}
$extFwd = @($fwdRows | Where-Object { $_.External })
Write-Note ("  {0} mailboxes forward, {1} to external targets" -f $fwdBoxes.Count, $extFwd.Count)
foreach ($f in @($extFwd | Select-Object -First $Top)) {
    Write-Note ("    {0}  ->  {1}  [{2}]" -f $f.Mailbox, $f.Target, $f.Source) Red
}
if ($extFwd.Count -gt $Top) { Write-Note ("    ... {0} more, use -Json or -ExportPath for the full list" -f ($extFwd.Count - $Top)) }

# --- inbox rules (opt-in, per mailbox) ---------------------------------------------
$inboxScanned = 0
$inboxErrors = 0
$inboxInternal = 0
$inboxExternal = 0
if ($IncludeInboxRules) {
    Write-Note "`n=== Inbox rules that forward or redirect (one call per mailbox) ===" Yellow
    $boxes = Invoke-Section 'Mailbox list for inbox rules' { Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -ErrorAction Stop }
    $i = 0
    foreach ($m in $boxes) {
        $i++
        $box = "$($m.PrimarySmtpAddress)"
        if (-not $Json) {
            Write-Progress -Activity 'Inbox rules' -Status $box -PercentComplete ([int](100 * $i / [math]::Max(1, $boxes.Count)))
        }
        try { $rules = @(Get-InboxRule -Mailbox $box -ErrorAction Stop) } catch { $inboxErrors++; continue }
        $inboxScanned++
        foreach ($ir in $rules) {
            $targets = @(@($ir.ForwardTo) + @($ir.ForwardAsAttachmentTo) + @($ir.RedirectTo) | Where-Object { $_ })
            foreach ($t in $targets) {
                # entries render as "Display Name [SMTP:user@domain]"; keep the address
                $addr = "$t"
                if ($addr -match 'SMTP:([^\]\s>]+)') { $addr = $Matches[1] }
                $external = Test-External $addr
                if ($external) {
                    $inboxExternal++
                    $sev = 'minor'
                    if (-not $ir.Enabled) { $sev = 'info' }
                    Add-Finding 'GROUPS-006' $sev "Inbox rule forwards to external address: $box" `
                        ("rule='{0}'; enabled={1}; target={2}" -f $ir.Name, [bool]$ir.Enabled, $addr) `
                        "User-created forwards carry the same alignment break as mailbox forwarding and are the classic post-compromise exfil path. Confirm with the owner; the outbound spam policy AutoForwardingMode is the tenant-wide switch" $true $box
                } else {
                    $inboxInternal++
                }
                $fwdRows += [pscustomobject][ordered]@{
                    Mailbox = $box; Source = 'InboxRule'; Target = $addr; TargetType = 'inbox-rule'; External = $external
                    DeliverToMailboxAndForward = $null; RuleName = "$($ir.Name)"; RuleEnabled = [bool]$ir.Enabled
                }
            }
        }
    }
    if (-not $Json) { Write-Progress -Activity 'Inbox rules' -Completed }
    Write-Note ("  {0} mailboxes scanned ({1} failed), {2} external rule forwards, {3} internal" -f $inboxScanned, $inboxErrors, $inboxExternal, $inboxInternal)
} else {
    Write-Note "`n=== Inbox rules skipped (add -IncludeInboxRules; one call per mailbox) ===" Yellow
}

# --- remote domains and the auto-forward switch --------------------------------------
Write-Note "`n=== Automatic forwarding controls ===" Yellow
$remote = Invoke-Section 'RemoteDomain' { Get-RemoteDomain -ErrorAction Stop }
$remoteRows = @()
foreach ($rd in $remote) {
    $af = [bool]$rd.AutoForwardEnabled
    $dn = "$($rd.DomainName)"
    $rn = "$($rd.Name)"
    if ($af) {
        $sev = 'info'
        if ($dn -eq '*') { $sev = 'minor' }
        Add-Finding 'GROUPS-007' $sev ("Remote domain allows automatic forwarding: {0} ({1})" -f $rn, $dn) `
            ("AutoForwardEnabled=True; DomainName={0}" -f $dn) `
            "The Default (*) remote domain applies to every external domain. The outbound spam policy AutoForwardingMode is the controlling switch since 2020; keep both consistent with the forwarding inventory above" $true $rn
        Write-Note ("  remote domain {0} ({1}): AutoForwardEnabled=True" -f $rn, $dn) Red
    }
    $remoteRows += [pscustomobject][ordered]@{ Name = $rn; DomainName = $dn; AutoForwardEnabled = $af }
}
$osp = Invoke-Section 'HostedOutboundSpamFilterPolicy' { Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop }
foreach ($p in $osp) {
    $mode = "$($p.AutoForwardingMode)"
    $pn = "$($p.Name)"
    if ($mode -eq 'On') {
        Add-Finding 'GROUPS-008' 'minor' "Outbound spam policy permits automatic external forwarding: $pn" ("AutoForwardingMode={0}" -f $mode) `
            "Every inbox rule and mailbox forward above can reach outside. Set AutoForwardingMode to Off unless a listed forward is a business requirement, then scope it with a separate policy" $true $pn
        Write-Note ("  outbound spam policy {0}: AutoForwardingMode=On" -f $pn) Red
    } elseif ($mode -eq 'Automatic') {
        Add-Finding 'GROUPS-008' 'info' "Outbound spam policy relies on the Microsoft default for forwarding: $pn" ("AutoForwardingMode={0}" -f $mode) `
            "Automatic currently means Off; set it to Off explicitly so the setting does not depend on a default you do not control" $true $pn
        Write-Note ("  outbound spam policy {0}: AutoForwardingMode=Automatic" -f $pn)
    } else {
        Write-Note ("  outbound spam policy {0}: AutoForwardingMode={1}" -f $pn, $mode)
    }
}

# --- roll-up ----------------------------------------------------------------------
$rank = @{ info = 0; minor = 1; major = 2; blocking = 3 }
$worst = $null
foreach ($f in $out) {
    if ($null -eq $worst -or $rank[$f.severity] -gt $rank[$worst]) { $worst = $f.severity }
}
$actionable = @($out | Where-Object { $_.severity -eq 'major' -or $_.severity -eq 'blocking' }).Count
$code = 0
if ($actionable -gt 0) { $code = 1 }

Write-Note "`n=== Findings ===" Yellow
foreach ($f in @($out | Select-Object -First $Top)) {
    $tag = ''
    if (-not $f.verified) { $tag = ' (not verified)' }
    $color = ''
    if ($f.severity -eq 'major' -or $f.severity -eq 'blocking') { $color = 'Red' }
    Write-Note ("  [{0}] {1} {2}{3}" -f $f.severity, $f.id, $f.title, $tag) $color
}
if ($out.Count -gt $Top) { Write-Note ("  ... {0} more, use -Json or -ExportPath for the full list" -f ($out.Count - $Top)) }
Write-Note ("`n{0} findings, {1} major or blocking; {2} sections not checked" -f $out.Count, $actionable, $skipped.Count)

$counts = [ordered]@{
    distribution_groups = $dgs.Count; dynamic_groups = $ddgs.Count; unified_groups = $ugs.Count
    open_groups = @($groupRows | Where-Object { -not $_.RequireSenderAuthentication }).Count
    groups_with_external_members = @($groupRows | Where-Object { $_.ExternalMembers -gt 0 }).Count
    membership_unverified = @($groupRows | Where-Object { $_.MemberCheck -ne 'ok' }).Count
    mailbox_forwards = $fwdBoxes.Count
    mailbox_forwards_external = @($fwdRows | Where-Object { $_.Source -ne 'InboxRule' -and $_.External }).Count
    inbox_rules_checked = [bool]$IncludeInboxRules
    inbox_rule_mailboxes_scanned = $inboxScanned; inbox_rule_mailboxes_failed = $inboxErrors
    inbox_rule_forwards_external = $inboxExternal; inbox_rule_forwards_internal = $inboxInternal
    remote_domains_autoforward = @($remoteRows | Where-Object { $_.AutoForwardEnabled }).Count
}

if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath | Out-Null }
    $groupRows | Export-Csv (Join-Path $ExportPath "group_audit.csv") -NoTypeInformation -Encoding UTF8
    $fwdRows | Export-Csv (Join-Path $ExportPath "forwarding_audit.csv") -NoTypeInformation -Encoding UTF8
    $out | Export-Csv (Join-Path $ExportPath "group_findings.csv") -NoTypeInformation -Encoding UTF8
    Write-Note "`nCSV written to $ExportPath" Green
}

if ($Json) {
    $doc = [ordered]@{
        tool = 'audit_groups'
        options = [ordered]@{ top = $Top; include_inbox_rules = [bool]$IncludeInboxRules; skip_members = [bool]$SkipMembers }
        counts = $counts
        groups = @($groupRows)
        forwards = @($fwdRows)
        remote_domains = @($remoteRows)
        findings = @($out)
        skipped = @($skipped)
        summary = [ordered]@{ findings = $out.Count; actionable = $actionable; worst = $worst
                              skipped = $skipped.Count; exit_code = $code }
        exit_code = $code
    }
    ConvertTo-Json -InputObject $doc -Depth 6
} else {
    Write-Note "`nRemember: a group or forward re-sends someone else's mail from your IPs. At p=reject the outside receiver, not you, decides what happens to that copy." Cyan
}
exit $code
