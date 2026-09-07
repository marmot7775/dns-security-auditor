# Redesign requirements addendum: homepage positioning and first-run state

Status: requirements, not a work order against the current page. These five
items are constraints on the incoming front end design, held the same way the
CSS accessibility work was held, so the new design absorbs them instead of the
old page accumulating patches.

Scope: copy and layout only. No audit logic changes. One item (the sample
audit) also needs DNS records published at Cloudflare.

Every quoted "current" string below was read from `static/index.html` at
commit 7383150 and confirmed against the served page.

## Context

The homepage describes what the tool is and not why it differs from a DNS
lookup tool. The differentiator is on the About page, which opens with "Most
DNS tools show you what records you have. They leave you to figure out whether
those records are correct", and it never reaches the top of the homepage.

Below the input card, a first time visitor sees nothing at all until an audit
runs. See item 3 for the corrected reading of that state.

## 1. Headline and subhead

Current:

    DNS & Email Security Audit

    Analysis of your email authentication and DNS security configuration.
    Includes RFC 9989 readiness, DNSSEC validation, and more.

Replace with:

    Most DNS tools show you your records.
    This one tells you what is wrong with them.

    Standards based analysis of your domain's DNS and email security, with
    the reasoning and the exact fix for every finding. Covers SPF, DKIM,
    DMARC, DNSSEC, MTA-STS, TLS-RPT, BIMI, DANE, CAA and more.

Constraints:

- Voice. The About page is first person and signed. Do not introduce a
  corporate "we" anywhere on the homepage. Use the site name or no subject.
- The current subtitle carries the only homepage link to
  `/articles/dmarcbis`, on the words "RFC 9989 readiness". The replacement
  subhead drops it. That link has to land somewhere else on the homepage or
  the article loses its only internal entry point from the front page.
- Naming SPF, DKIM, DMARC, DNSSEC, MTA-STS, TLS-RPT, BIMI, DANE and CAA in
  the subhead is accurate: all nine are checked today.

SEO tradeoff to accept knowingly. The current `h1` carries the primary
keyword phrase. The replacement `h1` does not. `<title>`, the meta
description and the JSON-LD `WebApplication.description` all still carry it,
and the new subhead contains "DNS and email security", so the page is not
keyword-bare. This is a deliberate trade of head-term match for a
differentiated first line. It is worth recording that it was a choice.

## 2. Sample audit

Add below the input:

    Not sure what to enter? See a sample audit.

Requirements:

- The target is a domain under our control with a deliberately imperfect
  published configuration, so the sample always demonstrates findings, RFC
  citations and copy paste fixes rather than a wall of green.
- Do not use google.com, microsoft.com or example.com. Large providers return
  clean results and prove nothing about what this tool does.
- The sample must produce at minimum: an SPF finding, a DMARC finding at
  p=none, and one transport or DNSSEC finding.
- The link runs the ordinary audit path. No fixture, no special case, no
  cached golden result. If the published records drift, the sample drifts
  with them and stays honest.
- Build the link and the flow. Keep the target in one place so it can be
  changed without touching markup.

### Recommended target: sample.dns-audit.com

Rationale: the visible label says "sample audit", so `sample.` matches the
copy exactly. It sits under a domain already controlled at Cloudflare, so
publishing records needs no new registration.

### Why the DNSSEC route is not available

dns-audit.com is DNSSEC signed. A DS record is published at the parent
(keytag 2371, algorithm 13) and the zone serves a KSK and a ZSK. Validation
succeeds for the zone and therefore for any name in it, so a subdomain cannot
be made to fail DNSSEC without unsigning the whole zone. The third finding
has to come from transport.

### Records to publish

| Name | Type | Value | Finding it produces |
| --- | --- | --- | --- |
| `sample.dns-audit.com` | TXT | `v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:sendgrid.net include:_spf.salesforce.com include:servers.mcsv.net ~all` | Exceeds the 10 lookup limit, which is a permerror, plus a soft `~all` where `-all` belongs |
| `_dmarc.sample.dns-audit.com` | TXT | `v=DMARC1; p=none; pct=100; rua=mailto:dmarc@sample.dns-audit.com` | Policy at p=none, and `pct=` which RFC 9989 removes |
| `sample.dns-audit.com` | MX | `10 dnsaudit-com0i.mail.protection.outlook.com` | Mail is accepted somewhere, so absent MTA-STS and absent TLS-RPT both become real findings rather than not applicable |

Notes on that MX. It is the org domain's existing Microsoft 365 host.
Pointing the sample subdomain at it adds no new mail surface: Microsoft
rejects recipients for a domain that is not provisioned in the tenant. It
also makes the sample exercise vendor detection and the provider
intelligence section, so the sample shows more of the tool, not less.

With those three records the sample produces, at minimum: an SPF permerror,
an SPF softfail finding, a DMARC p=none finding, an RFC 9989 tag finding, a
missing MTA-STS finding, a missing TLS-RPT finding, a missing DKIM selector
result, no BIMI and no DANE. That is a full page of real output.

### Risk that needs an explicit decision

dns-audit.com publishes `v=DMARC1; p=reject` with no `sp=` tag, so today
every subdomain inherits reject. Publishing `p=none` at
`_dmarc.sample.dns-audit.com` overrides that for exactly that one name.
Combined with an SPF record that permerrors and no DKIM, mail claiming to be
from `anything@sample.dns-audit.com` would not be rejected on DMARC grounds.

The blast radius is one obviously-demo subdomain with no mail, no users and
no reputation. The org domain and every other subdomain keep p=reject. The
alternative is a separate throwaway domain, which isolates the risk fully at
the cost of a registration and a sample URL that no longer reads as ours.

Recommendation: accept the subdomain. Record the decision here so it is not
rediscovered later as a misconfiguration.

## 3. Pre-run empty state

### Correction to the stated premise

The addendum as drafted said a first time visitor lands on a results
dashboard showing four zero counters and five empty section headings. That
is not what renders. `static/style.css:791` sets `.results-section { display:
none; }`, and the only rules that override it are the print stylesheet and
`static/app.js:520`, which runs after an audit completes. Verified against
the served stylesheet, not just the working tree.

What is actually true:

- The skeleton is present in the initial HTML and hidden by CSS. Anything
  that reads the markup without the stylesheet, such as reader mode, a text
  browser or a text extractor, does see the zero counters and the empty
  headings. That is a smaller version of the same problem and is worth
  fixing, but it is not what a browser shows.
- What a browser shows below the input card before a run is nothing. Dead
  space, and no statement anywhere on the page of what the tool checks.

So the requirement stands and the rationale changes. This is not removing a
broken-looking skeleton. It is filling an empty region with orientation, and
holding the line that the skeleton must not start rendering pre-run as the
redesign moves markup around.

### Requirement

Before an audit runs, none of the results scaffolding may be visible, and
preferably none of it should be in the initial markup at all. The full list,
which is longer than the five headings originally named:

| Element | What it shows pre-run |
| --- | --- |
| `#domain-banner` | Empty domain name, empty timestamp, PDF / Export / Share buttons |
| `#executive-summary-slot` | Empty |
| `#summary-grid` | Passing 0, Warnings 0, Issues 0, Not checked 0 |
| `#resilience-section` | "Authentication Resilience" |
| `#priority-section` | "Key Findings" |
| `#anomalies-section` | "What's Unusual" |
| `.results-toolbar` | "Findings", Copy All Records, Expand All |
| `#vendors-section` | "Email Services (detected from DNS records)" |
| `#provider-intelligence-section` | "Your Email Platform" |

In its place, one empty state:

    Your results will appear here.
    Enter a domain above to check its DNS and email security configuration.

Followed by a plain list of what gets checked. No emoji and no checkmark
glyphs. Plain text list or the site's existing list style.

## 4. DKIM selector label

Change the disclosure control (`#selector-toggle`) from:

    Test a specific DKIM selector

to:

    Advanced: test a specific DKIM selector

The field currently reads as though it may be required. It is not. Selector
auto-discovery runs on every audit.

## 5. Inline plain language definitions in results

Attach a one line definition to each finding, shown only for record types
present in that domain's audit. This is not a homepage glossary and must not
appear before a run.

    SPF
    Lists the servers allowed to send mail using your domain.

    DKIM
    Adds a signature receivers can check to confirm a message really came
    from your domain and was not altered along the way.

    DMARC
    Tells receiving servers what to do with mail that fails those checks,
    and sends you reports on who is sending as your domain. At p=none it
    reports only. Enforcement is what stops impersonation.

    DNSSEC
    Lets resolvers verify that DNS answers for your domain are genuine and
    were not forged in transit.

Accuracy constraints, these matter more than brevity:

- Do not say SPF controls which servers can send email. It authorizes, and
  it authenticates the envelope sender, not the visible From address.
- Do not say DMARC protects a domain from impersonation without naming
  enforcement. Most domains with DMARC sit at p=none.

Clarification on "present". Present means the check ran and produced a
finding, not that the record exists. A domain with no DMARC record still gets
a DMARC card, and that reader needs the definition more than anyone. Gate the
definition on the card being rendered, not on record presence.

Coverage gap to resolve. Four protocols have copy. The complete scope renders
cards for thirteen checks. Either the remaining cards get definitions written
to the same accuracy bar, or the four are visibly a different kind of thing
from the rest. Four explained and nine not, with no signal why, reads as
unfinished. This needs a decision before the definitions ship.

## Do not change

The trust line below the input stays exactly as it is:

    No account. No cookies. Open source. What gets logged

The "What gets logged" link is the honest and verifiable element. Do not
replace it with a no tracking claim.

The footer tagline stays as it is. Its current exact wording is "Free,
open-source DNS & email security auditing", with a line break before the
ampersand.

## Out of scope

Contrast and hierarchy are already covered by the held accessibility
constraints, WCAG AA 4.5:1 on body text and 44px touch targets. Nothing new
here.

## Open decisions

1. Sample audit target. Recommended above as sample.dns-audit.com, with the
   p=none spoofing tradeoff named. Needs Neil's yes before records go in.
2. Where the RFC 9989 article link lives once the subhead drops it.
3. Whether definitions cover four protocols or all thirteen.
