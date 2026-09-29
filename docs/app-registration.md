# App registration setup (the data plane)

The way this toolkit is meant to run: a read-only Entra ID App Registration
lets the scripts read your tenant's domain list, run hunting queries, and
(optionally) read the mailbox that receives your aggregate DMARC reports.
Everything downstream - the audit, the report, the rollout plan, and any AI
agent you later point at the outputs - works from what those scripts pull.
No user token in a script, no portal copy-paste, and nothing in the chain
that can write to your tenant. No AI is involved in any of this.

## Create the registration (about ten minutes, one Global Admin click)

1. Entra admin center > App registrations > **New registration**. Name it
   something honest like `dmarc-audit-toolkit-readonly`. Single tenant. No
   redirect URI - this is app-only, nothing signs in interactively.
2. **API permissions** > Add a permission > Microsoft Graph >
   **Application permissions**. Add the rows below. Remove the default
   delegated `User.Read` while you are there.

| Permission | Needed for | Required? |
|---|---|---|
| `ThreatHunting.Read.All` | the hunting queries (30 days of mail-flow data) | yes |
| `Domain.Read.All` | reading the tenant's own domain list, so `audit.py` with no arguments audits everything you own | recommended; without it, name the domains on the command line |
| `Mail.Read` | reading the aggregate report mailbox for the outside view | only if you set `RUA_MAILBOX`; must be scoped, see below |

3. **Grant admin consent** for the tenant. Until an admin consents, the
   token is issued with no roles and every call returns 401 or 403.
4. **Certificates & secrets** > New client secret. Set the shortest expiry
   your rotation habits can live with. For anything long-lived, prefer a
   certificate over a secret.
5. Record the values into your local `.env` (gitignored, never committed):

```
AZURE_TENANT_ID=<Directory (tenant) ID>
AZURE_CLIENT_ID=<Application (client) ID>
AZURE_CLIENT_SECRET=<the secret value, shown once at creation>
RUA_MAILBOX=<the mailbox on your rua= line, or leave empty>
```

## Scope Mail.Read to one mailbox (only if you use RUA_MAILBOX)

`Mail.Read` as an application permission is tenant-wide: the app could read
every mailbox. An Exchange Online Application Access Policy restricts it to
the report mailbox and nothing else. Run once, as an Exchange admin:

```powershell
New-ApplicationAccessPolicy -AppId <client id> -PolicyScopeGroupId reports@example.com -AccessRight RestrictAccess -Description "DMARC toolkit - aggregate report mailbox only"
Test-ApplicationAccessPolicy -Identity someone.else@example.com -AppId <client id>   # expect Denied
```

Point it at the mailbox that receives **aggregate** (`rua`) reports, never
the forensic (`ruf`) one: forensic reports carry message samples and headers
the toolkit does not need. Microsoft is moving this control to RBAC for
Applications; if your tenant has that, scope the app the same way there.

## Prove it works

```
python src/verify_setup.py
python src/verify_setup.py --expect-denied someone.else@example.com
```

Every check prints PASS, WARN, FAIL or INFO with the exact fix: credentials
present, token obtained, roles present and roles in **excess** (write-capable
ones called out), the consent grant behind each role with the date it was
granted, the domain list, a hunting query, the report mailbox, and (with
`--expect-denied`) that another mailbox is refused, which proves the access
policy is in effect. A summary line at the end counts passed, warnings and
failed; the exit code is 1 when anything failed. Nothing is printed that you
could not paste into a ticket: no token, no secret.

## Why least privilege, and what to do with an existing registration

The three permissions above can read mail-flow telemetry, a domain list, and
one mailbox. They cannot read other mail, change a transport rule, or touch
DNS. That is the entire point: the blast radius of a leaked secret is
"someone can read our authentication telemetry," not "someone can
reconfigure mail flow." It matches ground rule 1 in `AGENTS.md`: everything
here is read-only.

If you are reusing a registration that already exists, run
`verify_setup.py` first. It lists every role beyond the three, and flags any
that can write (`ReadWrite`, `Manage`, `Send`, and the like). Remove those.
`Directory.Read.All` works in place of `Domain.Read.All` but is far broader;
swap it.

## Optional: unattended PowerShell audits

`audit_rules.ps1`, `audit_bypasses.ps1` and `audit_groups.ps1` read Exchange
settings that have no Graph API. They run fine interactively after
`Connect-ExchangeOnline`. To run them from a schedule with no human signed
in, add the Office 365 Exchange Online application permission
`Exchange.ManageAsApp`, assign the app's service principal a **view-only**
Exchange role (View-Only Organization Management, or Global Reader), and use
a certificate credential - app-only Exchange PowerShell does not accept
secrets. The role assignment, not the permission name, is what decides
whether the app can change anything; keep it view-only. Skip this entirely
on the Python path.

To make and upload the credential, pick your platform:

**Windows** (PowerShell, built in - private key stays in the cert store):

```powershell
$c = New-SelfSignedCertificate -Subject "CN=DMARC-Audit-ReadOnly" `
    -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable
Export-Certificate -Cert $c -FilePath .\dmarc-audit-readonly.cer
```

**macOS / Linux** (OpenSSL, built in on both - two files come out):

```bash
# private key + public cert, no passphrase so scripts can run unattended
openssl req -x509 -newkey rsa:2048 -keyout dmarc-audit.key \
    -out dmarc-audit-readonly.cer -days 365 -nodes -subj "/CN=DMARC-Audit-ReadOnly"
chmod 600 dmarc-audit.key
# bundle both into the .pfx the scripts read on this platform
openssl pkcs12 -export -out dmarc-audit-readonly.pfx \
    -inkey dmarc-audit.key -in dmarc-audit-readonly.cer -passout pass:
```

Upload `dmarc-audit-readonly.cer` (same file on every platform) under
**Certificates & secrets**; the `.key` / `.pfx` never leaves your machine.
Then in `.env`:

```
# Windows:
EXO_CERT_THUMBPRINT=<the cert's thumbprint>
EXO_ORGANIZATION=<yourtenant>.onmicrosoft.com

# macOS / Linux:
EXO_CERT_FILE=dmarc-audit-readonly.pfx
EXO_ORGANIZATION=<yourtenant>.onmicrosoft.com
```

`EXO_APP_ID` is optional and defaults to `AZURE_CLIENT_ID`; `EXO_CERT_PASSWORD`
is only needed if you put a passphrase on the PFX. A Windows thumbprint is
shown by `Get-ChildItem Cert:\CurrentUser\My`; on OpenSSL it is
`openssl x509 -in dmarc-audit-readonly.cer -noout -fingerprint -sha1`.

With those set, the three scripts connect app-only on their own (via
`src/ToolkitExo.ps1`) and only offer interactive sign-in when app-only is not
configured.
Close-out when the project wraps: delete the certificate from the
registration and remove the role assignment.

## Run

```
python src/audit.py                                   # domains read from the tenant
python src/audit.py example.com,other.example         # named domains, merged with the tenant's
python src/run_hunting.py queries/sender_census.kql --out census.csv
python src/run_hunting.py queries/genuine_failures.kql --timespan P7D --out failures.csv
```

`run_hunting.py` exchanges the credentials for a token, POSTs the KQL to the
Microsoft Graph `security/runHuntingQuery` endpoint, and writes the result
as CSV. Edit the domain placeholder at the top of each query file first; the
script warns if you forget. Advanced hunting looks back at most 30 days,
and the API enforces execution-time, result-size, and rate caps - narrow the
time window or the projection if a query gets truncated or throttled.

The pipeline worth knowing: `queries/raw_maillog.kql` projects exactly the
columns `src/dedupe.py` expects, so

```
python src/run_hunting.py queries/raw_maillog.kql --out maillog.csv
python src/dedupe.py maillog.csv --auth-column DMARC
```

takes you from tenant data to a deduplicated failure count with no portal
export and no column flags, and `audit.py --maillog maillog.csv` folds the
same file into the full report. One API call returns at most 100,000 rows.
`collect.py` notices when a domain lands on that cap and splits the window
into smaller slices on its own; when you run `run_hunting.py` by hand, narrow
the window (or split by subdomain) and run it twice.

## Validation

Prove the plumbing before trusting any number from it: run
`sender_census.kql` and check the busiest two or three senders against the
same query pasted into the Defender portal. Same rows, same counts, then
the API path is good.

## Where the AI agent fits

Nowhere in the steps above. Once the reports exist, and only if
`AI_ANALYSIS_ENABLED=true` is set in `.env`, an agent that reads `AGENTS.md`
can pick up `report.json` and work from it, or pull fresh data itself by
running the same scripts: the script reads the credentials, and the secret
never appears in the conversation. The agent analyzes; the registration
reads; nothing writes. Rotation, consent, and the secret's lifetime stay a
human job.
