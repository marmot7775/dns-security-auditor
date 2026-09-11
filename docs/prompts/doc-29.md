# Doc 29: homepage wording, layout, and type

Scope: static/index.html and the CSS that styles the audit card. No new features. Everything here is copy, order, or spacing. Line numbers are from main at d7a50b4; re-locate by content if they have moved.

Fonts stay as they are. DM Sans for text and JetBrains Mono for records are self-hosted, subsetted, and swap cleanly. Do not add a typeface or a Google Fonts link (the CSP would block it anyway). The type changes below are size and measure only.

## 1. Headline and subtitle

index.html:139 to 140.

Current:

    <h1 class="audit-title">DNS &amp; Email Security Audit</h1>
    <p class="audit-subtitle">Most DNS tools show you your records. This one tells you what is wrong with them. Includes <a href="/articles/dmarcbis" class="audit-subtitle-link">RFC 9989 readiness</a>, DNSSEC validation, and more.</p>

Replace with:

    <h1 class="audit-title">Find what is wrong with your domain's email and DNS</h1>
    <p class="audit-subtitle">Most DNS tools show you your records. This one tells you what is wrong with them, cites the RFC section it checked against, and gives you the corrected record to paste. Includes <a href="/articles/dmarcbis" class="audit-subtitle-link">RFC 9989 readiness</a> and DNSSEC chain validation.</p>

The headline now says what happens when you press the button instead of naming the category. The subtitle gains the two things the page never states anywhere: findings cite the RFC section, and fixes are pasteable records. "And more" is gone; it promised nothing.

Keep the page <title> and og:title as they are. The h1 is for the reader, the title tag is for search.

## 2. Input above the scope selector

index.html:141 to 192. The card currently runs: headline, subtitle, six scope buttons, scope description, then the domain input. On a 390px phone the six buttons fill the card from the subtitle to the fold and the input is the last thing a visitor reaches. The page has one job, and its input is the last element in the card.

Move the `<form id="audit-form">` block (currently 174 to 192) to sit directly after the subtitle, before `<div class="scope-selector">`. The scope selector, its buttons, and `#scope-desc` follow the form. Nothing in app.js depends on document order here: it reaches these elements by id (`scope-desc`, `audit-form`, `domain-input`, `selector-toggle`) and toggles `.compact` on the section, so verify with a real audit in Playwright at 390px and 1280px that the compact state, the recent-audits list, and the scope description still render in the right place.

Adjust spacing so the input row has the same margin above it that the scope selector had, and the scope selector has `margin-top: var(--space-lg)`.

## 3. Placeholder truncates on phones

index.html:180: `placeholder="Enter a domain or subdomain"`. At 390px the input shows "Enter a domain or s" beside the Run Audit button. Verified by screenshot.

Replace with `placeholder="example.com"`. The aria-label already says "Domain or subdomain to audit", so nothing is lost for screen readers.

## 4. Privacy line: keep the sentence, drop the link

index.html:194: `<p class="audit-privacy-note">No account. No cookies. Open source. <a href="/privacy">What gets logged</a>.</p>`

Replace with: `<p class="audit-privacy-note">No account. No cookies. Open source.</p>`

The privacy page stays where it is and stays linked in the footer on every page. The trust line under the button stays; the link out of the card goes.

## 5. Scope tooltips name half their checks

Three tooltips describe fewer checks than the scope runs. SCOPE_CHECKS in audit_engine.py:291 is the source of truth, and app.js copies the title attribute into the visible `#scope-desc` line, so this is on-page text, not hover text.

index.html:156, transport. Current: `title="Mail in transit: MTA-STS, TLS-RPT and MX transport security."` Scope is mx, mta_sts, tls_rpt, dane. Replace with: `title="Mail in transit: MTA-STS, TLS-RPT, DANE, and MX."`

index.html:160, dns_infra. Current: `title="The DNS itself: DNSSEC, CAA and nameservers."` Scope is dnssec, caa, dane, nameservers, ct. Replace with: `title="The DNS itself: DNSSEC, CAA, DANE, nameservers, and Certificate Transparency."`

index.html:164, security_scan. Current: `title="Quick posture check: DMARC, SPF, DKIM and DNSSEC."` Scope is dmarc, spf, dkim, dnssec, dane, ct, caa, mta_sts. Replace with: `title="Quick posture check: DMARC, SPF, DKIM, DNSSEC, DANE, CAA, MTA-STS, and Certificate Transparency."`

Add a test that, for every scope button in index.html, each check named in SCOPE_CHECKS appears in that button's title, so the two cannot drift again.

## 6. Structured data and meta descriptions disagree with each other and with the tool

index.html:7, 14, and 18 (meta description, og:description, twitter:description): "Checks DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA." No DANE.

index.html:31 (JSON-LD WebApplication description): "checking DMARC, SPF, DKIM, MTA-STS, DNSSEC, DANE, CAA, BIMI, and TLS-RPT." No MX.

index.html:51 (FAQ answer to "What does this DNS security audit check?"): "It checks 9 email and DNS security protocols". The tool runs 12 checks.

index.html:100 (DefinedTerm for DMARC): "defined in RFC 7489." RFC 9989 obsoletes it, and the FAQ at line 59 on the same page says so.

Use one string for 7, 14, 18, and 31: `DNS and email security audit. Twelve checks covering DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, DANE, nameservers, and Certificate Transparency, with findings and copy-paste fixes.`

Line 51: `It runs 12 checks: DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, DANE, nameservers, and Certificate Transparency. Each one reports pass, warning, or fail with the specific finding and a copy-paste fix where one applies.`

Line 100: `Domain-based Message Authentication, Reporting, and Conformance. A DNS-based email authentication policy protocol defined in RFC 9989, which obsoletes RFC 7489.`

## 7. Two headings called Findings

index.html:266 `Key Findings` (the prioritized subset) and index.html:280 `Findings` (every check card). A reader cannot tell whether the second repeats the first.

Change line 280 to `<h2 class="results-label">All Checks</h2>`. Check app.js and the PDF for any string that refers to this section by name and keep them consistent.

## 8. Type: headline size and reading measure

style.css:538, `.audit-title` is 1.87rem at every width above the phone breakpoints. The card is 830px wide on desktop, and 30px is small for the only headline on the page. At `min-width: 768px` set `.audit-title` to 2.25rem. Leave the phone sizes at 3397, 4209, and 4332 alone; the new headline is longer and already wraps to three lines at 390px.

style.css:547, `.audit-subtitle`, and the `.scope-desc` rule: on desktop these run the full 830px card width, about 100 characters per line. Add `max-width: 64ch` to both. Left aligned, no centering.

## 9. The DKIM selector toggle looks like a caption

style.css:633, `.selector-toggle` is muted text with no underline and no affordance, and it sits under the input where a caption would. Give it the link color (`var(--primary-light)` in dark, the light-theme equivalent in the two light-mode blocks) and `text-decoration: underline; text-underline-offset: 3px`. Keep the 44px mobile hit area at 9150.

## Verification

Screenshots at 390px and 1280px, both themes, before and after: the input must be visible without scrolling at 390px on the new layout. Run a real audit in Playwright and confirm the compact header state, the scope description, and the recent-audits list all still work with the form above the selector. Run the axe sweep on the homepage; nothing in this doc should change a contrast ratio, but the selector toggle color is new, so check it.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since style.css changes.
Restart the service after deploy and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-29.md in the same commit.

## Done when

The headline says what the tool does, the input is the first control in the card, every scope description names every check in its scope, the four metadata strings agree with each other and with SCOPE_CHECKS, and the page at 390px shows the input without scrolling.
