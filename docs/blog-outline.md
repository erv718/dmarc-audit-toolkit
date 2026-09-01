# Blog post outline: what a real DMARC rollout actually looks like

Working title options:
- *Your DMARC failure count is wrong*
- *Six months to p=reject: what the guides leave out*
- *The vendor said they can't do DKIM. We passed anyway.*

## The frame

Every DMARC guide is the same: publish `p=none`, read the reports, ratchet to
`reject`. None of them prepare you for the part that actually takes six months -
finding out who sends mail as you, getting other companies to change their
configuration, and telling the difference between a broken sender and a
measurement artifact.

## 1. You cannot fix what you cannot name

Reporting tools name a *service*, not a system in your company. "SendGrid is
failing" is not actionable when SendGrid is a platform used by three different
vendors, none of whom you have a ticket with.

**Technique - fingerprint the account, not the platform.** VERP bounce
addresses (`bounces+<account-id>-...@sendgrid.net`), base64-encoded account IDs
in `Received` headers, click-tracking hostnames, and custom reverse DNS all
identify *which customer* of a platform is sending. One vendor turned out to
own two accounts on the same platform, one authenticated and one not - which
explained why the fix "already applied" had not worked.

## 2. Your failure count is wrong

The single most useful lesson. One logical email produces several log rows:
relay hops, forwarding legs, multi-recipient fan-out. The original leg passes;
the relayed leg fails because the relaying host is not in the sender's SPF and
the message was altered.

Count rows and a healthy sender looks broken. **Group by Message-ID and treat a
message as failing only when no copy passed.**

Story beat: a "critical outage" - dozens of quarantined internal messages - that
turned out to be echoes. Every recipient had the mail, delivered seconds
earlier on the first leg. This mistake was made twice, by someone who knew
better, because the dashboard number is so persuasive.

## 3. Blocked and failed are different questions

Mail can be quarantined by a transport rule while DMARC passes, or fail DMARC
and be delivered by an allow rule. Internal overrides make a domain look
healthy that external receivers are already junking.

Story beat: months of reports that everyone assumed were arriving had been
quarantined for a quarter. The vendor's "unauthorized" change to their From
address had not broken delivery - it had *restored* it.

## 4. The SPF lookup limit is a countdown nobody is watching

Ten DNS lookups, hard limit, PERMERROR past it - for the entire domain.
Ours was at nine. One more vendor would have broken authentication everywhere.

Takeaway for the org: new senders authenticate with DKIM, not another include.

## 5. When a vendor says they cannot do DKIM

Shared IP pools genuinely cannot offer per-customer DKIM signing. That is not
an excuse, it is architecture.

DMARC needs **one** aligned method, not both. Point the bounce address at a
subdomain you control, publish the vendor's SPF there, and SPF alignment
carries the message. One setting, no DKIM required.

Story beat: went from 0% to 99.7% passing with a single field change on a
mailing list - after a week of arguing about DKIM.

## 6. The thing enforcement is actually for

What was left failing at the end was not vendors. It was 505 employee names
being spoofed in a week with invoice, wire and voicemail lures, and a
persistent BEC campaign against an executive assistant that rotated domains
every few days.

DMARC does not stop lookalike domains or display-name impersonation - pair it
with impersonation protection and out-of-band verification for payment changes.
But it does close the door on someone simply sending as your CEO.

## 7. What I would do differently

- Dedupe from day one; build it into the first query, not after two wrong calls
- Inventory subdomains at the start - they inherit `sp=` and attackers find them
- Audit allow rules before enforcing, not after
- Ask every vendor for the *account identifier*, not just "are you set up"
- Write the removal criteria into every exception you create

## Toolkit

Link to the repo. Scripts, queries, and the methodology - all read-only.
