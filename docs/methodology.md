# Methodology

The order these questions get asked in matters more than the tools.

## 1. Turn on reporting before changing anything

Publish a DMARC record at `p=none` with a `rua` address. That is monitoring
only: it changes nothing about delivery and starts receivers reporting what
they see. Without it you are guessing.

Do this for every domain you own, including ones you believe send no mail.
Dormant domains are attractive precisely because nobody watches them.

## 2. Build the sender inventory

Reports name a *service*, not a system inside your company. "SendGrid is
failing" is not actionable when three different vendors use SendGrid and you
have a ticket with none of them.

Fingerprint the account rather than the platform:

- **VERP bounce addresses** often embed an account ID: `bounces+<id>-...@platform.example`
- **Received headers** sometimes carry a base64-encoded account identifier
- **Click-tracking hostnames** are per-account
- **Custom reverse DNS** on the sending IP identifies the customer

One vendor may hold several accounts on the same platform, with only some
authenticated. That is invisible until you fingerprint.

## 3. Deduplicate before you believe any number

Group by Message-ID. A message is a genuine failure only when **no copy of it
passed**. See `src/dedupe.py`.

Skipping this step produces false emergencies. It is the single most common
reason people conclude enforcement broke something when it did not.

## 4. Separate delivery from authentication

Two independent questions:

- Did DMARC pass or fail?
- Was the message delivered, quarantined, or rejected, and by what?

Local allow rules can deliver mail that failed authentication, which makes a
domain look healthy internally while external receivers junk it. Filtering
rules can quarantine mail that authenticated fine. Always check both.

## 5. Audit your allow rules before enforcing

Inventory every rule that bypasses filtering. For each one ask whether it is
conditional on authentication passing.

A rule that fires only on `dmarc=pass` is safe: it skips spam scoring for known
senders and cannot rescue a forgery. A rule with no authentication condition
bypasses everything, and rules keyed on forgeable inputs such as a string in a
`Received` header can be triggered by anyone who knows the string.

Every exception should carry a written removal criterion. Otherwise exception
lists grow forever and nobody remembers why any entry exists.

## 6. Check the SPF lookup budget

Run `src/spf_lookups.py`. If you are at nine of ten, the next vendor breaks
authentication for the entire domain.

The practical policy that follows: new senders authenticate with DKIM, not
another SPF include.

## 7. Ratchet slowly, with a gate at each step

`p=none` to `p=quarantine` at a low percentage, then increase, then `p=reject`.

The percentage controls sampling, so it only ever affects mail that already
fails. Raising it cannot break a passing sender. What each step buys you is
time for aggregate reports, which lag 24 to 48 hours, to surface senders your
own logs cannot see because they deliver to external recipients.

Gate each step on one question: **is any legitimate sender in the failing
bucket?** If the answer is only spoofing, advance.

## 8. Enable DKIM before reject, always

SPF breaks when mail is forwarded. DKIM survives it. A domain authenticating on
SPF alone is fine at quarantine, where a forwarded message lands in junk and can
be retrieved, and fragile at reject, where it bounces.

Check DKIM is genuinely signing by reading the headers of a real message. A
control panel showing "enabled" only means the configuration exists.

## 9. When a vendor says they cannot do DKIM

Shared IP pools often genuinely cannot offer per-customer signing. That is
architecture, not obstruction.

DMARC requires **one** aligned method, not both. Point the vendor's bounce
address at a subdomain you control, publish their SPF there, and SPF alignment
carries the message. One configuration field, no DKIM required.

Caveat: SPF-only alignment does not survive forwarding, so revisit it before
moving that domain to reject.

## 10. Know what DMARC does not solve

At full enforcement, what remains failing is usually not vendors. It is
attackers spoofing your domain, which is exactly what enforcement stops.

But DMARC does nothing about lookalike domains or display-name impersonation.
An attacker who registers a similar domain and puts your executive's name in
the From header passes their own authentication perfectly. Pair enforcement
with impersonation protection and out-of-band verification for payment changes.
