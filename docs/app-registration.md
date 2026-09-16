# App registration setup (the intended data plane)

The way this toolkit is meant to run: a read-only Entra ID App Registration
pulls hunting-query results by API, and everything downstream - dedupe,
census, an AI agent doing analysis - works from that output. No user token
in a script, no portal copy-paste, and nothing in the chain that can write
to your tenant.

## Create the registration (about five minutes)

1. Entra admin center > App registrations > **New registration**. Name it
   something honest like `dmarc-audit-toolkit-readonly`. Single tenant. No
   redirect URI - this is app-only, nothing signs in interactively.
2. **API permissions** > Add a permission > Microsoft Graph >
   **Application permissions** > `ThreatHunting.Read.All`. Remove the
   default delegated `User.Read` while you are there.
3. **Grant admin consent** for the tenant. Until an admin consents, every
   call returns 401 or 403.
4. **Certificates & secrets** > New client secret. Set the shortest expiry
   your rotation habits can live with. For anything long-lived, prefer a
   certificate over a secret.
5. Record three values into your local `.env` (gitignored, never committed):

```
AZURE_TENANT_ID=<Directory (tenant) ID>
AZURE_CLIENT_ID=<Application (client) ID>
AZURE_CLIENT_SECRET=<the secret value, shown once at creation>
```

## Why this permission and nothing else

`ThreatHunting.Read.All` runs advanced hunting queries and can do nothing
else - it cannot read mailboxes, change transport rules, or touch DNS. That
is the entire point: the blast radius of a leaked secret is "someone can
read our mail-flow telemetry," not "someone can reconfigure mail flow."
It matches ground rule 1 in `AGENTS.md`: everything here is read-only.

## Run a query

```
python src/run_hunting.py queries/sender_census.kql --out census.csv
python src/run_hunting.py queries/genuine_failures.kql --timespan P7D --out failures.csv
```

The script exchanges the credentials for a token, POSTs the KQL to the
Microsoft Graph `security/runHuntingQuery` endpoint, and writes the result
as CSV. Edit `example.com` in the query files to your domain first; the
script warns if you forget. Advanced hunting looks back at most 30 days,
and the API enforces execution-time, result-size, and rate caps - narrow
the time window or the projection if a query gets truncated or throttled.

## Validation

Prove the plumbing before trusting any number from it: run
`sender_census.kql` and check the busiest two or three senders against the
same query pasted into the Defender portal. Same rows, same counts, then
the API path is good.

## Where the AI agent fits

Give your agent the repo and the `.env` file on disk and it can pull fresh
data itself: it runs `src/run_hunting.py`, the script reads the
credentials, and the secret never appears in the conversation. The agent
analyzes; the registration reads; nothing writes. Rotation, consent, and
the secret's lifetime stay a human job.
