# Doc 30: README, SECURITY.md, and stale references on the site

Copy only. No behavior changes. Everything here is a statement that is wrong, out of date, or contradicts another page. Line numbers are from main at 24411d1; re-locate by content if they have moved.

## 1. README describes a check that no longer exists

README.md:46 is a Blocklist row: "Domain reputation check against Spamhaus DBL". README.md:113 lists Blocklist in the Email Security scope and README.md:117 in the Security Scan scope. audit_engine.py has no blocklist code, and live_check.py's own docstring explains why it was removed. A reader who runs the tool, sees no Blocklist card, and concludes the tool is broken is the cost.

Fix: delete the row at 46. Change the heading at README.md:40 from "Infrastructure and Reputation" to "Infrastructure and Certificates". Line 113 becomes `| Email Security | DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI |`. Line 117 becomes `| Security Scan | DMARC, SPF, DKIM, DNSSEC, DANE, CT, CAA, MTA-STS |`. Both then match SCOPE_CHECKS at audit_engine.py:291.

live_check.py:39 still carries "Blocklist" in CARD_ORDER. Remove it.

## 2. README counts

README.md:13 "## 13 Security Checks", README.md:112 "All 13 checks", README.md:134 "across all 13 checks". The engine runs 12: DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, DANE, nameservers, Certificate Transparency. Change all three to 12.

README.md:19 and README.md:130 say "21 checks" for dangerous combination detection. _detect_dangerous_combinations in result_transformer.py emits 20: eight critical, eight advisory, four info. Change both to 20. The "3 severity levels" half of the claim is correct.

Add a test that counts the check registry the engine actually runs and asserts the README's headline number matches, so the count cannot drift again.

## 3. README says there is no database

README.md:144: "Stateless single-page application with a FastAPI backend. No database, no user accounts, no tracking."

dns_snapshots.py opens a SQLite file, store_audit_snapshots writes to it on every audit, and the privacy page at static/privacy.html:93 discloses it: "The server keeps a small database of DNS records it has looked up." The README denying what the privacy page discloses is the worst version of this error to have.

Replace with: "Single-page application with a FastAPI backend. No user accounts and no tracking. The only stored state is a SQLite table of DNS records seen during past audits, used for change detection and pruned after 90 days."

## 4. README cites an obsoleted RFC for DNSSEC algorithms

README.md:36: "algorithm analysis per RFC 8624". RFC 9904 (December 2025) obsoletes RFC 8624 and moves the algorithm requirements to the IANA DNSSEC algorithm registries. The recommendation levels did not change, so the code is right; the citation is stale on a site whose pitch is knowing which RFC is current.

Replace "algorithm analysis per RFC 8624" with "algorithm analysis against the IANA DNSSEC algorithm registries, which RFC 9904 made the canonical source in place of RFC 8624".

## 5. README gets the np tag wrong

README.md:84: "RFC 9989 also introduces the `np` tag to set separate policies for non-existent subdomains, closing a gap that allowed attackers to spoof fabricated subdomains like `ceo.example.com`."

Two errors. There was no gap: under RFC 7489 a fabricated subdomain has no record of its own, so the receiver applies the Organizational Domain's sp, or p when sp is absent. RFC 9989 section 4.7 states the same inheritance when np is absent. And np was not introduced by RFC 9989; Appendix C lists it as imported from RFC 9091. What np buys you is a stricter policy for non-existent subdomains than for real ones, which matters when sp has to stay at none while a real subdomain is still being aligned.

Replace with: "RFC 9989 also brings in the `np` tag from RFC 9091, which sets a policy for non-existent subdomains separately from real ones. Under RFC 7489 a fabricated subdomain like `ceo.example.com` already inherited `sp`, or `p` when `sp` was absent, so the two moved together. With `np` you can hold `sp=none` while a real subdomain is still being aligned and reject fabricated ones at the same time."

## 6. README says selectors are private

README.md:62: "Domains where selectors could not be detected are not marked down for it, since selectors are private and cannot be verified from outside."

A published DKIM key is public DNS, and verifying one from outside is exactly what the tool does when handed a selector. What cannot be done is enumerate them, which the italic note on the same line already says correctly.

Replace the clause with: "since DNS gives no way to list the names under `_domainkey` and an undetected selector is not evidence of a missing one."

## 7. Publication date given as 19 May 2026 in three places

README.md:86, static/about.html:71, and static/index.html:59 all say the DMARC RFCs were published 19 May 2026. The RFC Editor metadata for RFC 9989, 9990, and 9991 gives "May 2026" with no day. The IETF Datatracker records the publication event at 2026-05-20 05:25 UTC, which reads as 19 May in Pacific time, which is probably where the date came from.

Change all three to "May 2026". Everything else in those sentences checks out: Standards Track, all three obsolete 7489, 9989 also obsoletes 9091, 9991 updates 6591.

## 8. About page check list is incomplete

static/about.html:71 ends: "SPF, DKIM, DNSSEC, MTA-STS, TLS-RPT, DANE, CAA, BIMI, and nameserver configuration are all covered." With DMARC named earlier in the paragraph that is ten of twelve. MX and Certificate Transparency are missing, and MX appears nowhere on the page.

Replace with: "SPF, DKIM, MX, DNSSEC, MTA-STS, TLS-RPT, DANE, CAA, BIMI, Certificate Transparency, and nameserver configuration are all covered."

The rest of the About page is a separate doc. Change only this sentence and the date in item 7.

## 9. README feature cell is unreadable

README.md:19 is a 62-word table cell listing eight features, and it duplicates the RFC 9989 Checker section at README.md:123 which says the same eight things at length.

Replace the cell with: "Validation against RFC 9989 and against RFC 7489, side by side, with a per-tag decoder, dangerous-combination detection, and the DNS Tree Walk of [RFC 9989 Section 4.10](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10) for hierarchical policy discovery. Full detail under RFC 9989 Checker below."

## 10. SECURITY.md

SECURITY.md:7: "**Email:** nta345@icloud.com". Every other surface uses neil@dns-audit.com. Change it.

SECURITY.md:39: "Please do not publicly disclose vulnerabilities until a fix has been released. We are committed to addressing security issues promptly and will credit reporters in the fix commit unless they prefer anonymity." A one-person project written in the first person everywhere else. "We are committed to addressing security issues promptly" promises nothing beyond the response timeline already stated above it.

Replace with: "Please hold off on public disclosure until a fix is released. I credit reporters in the fix commit unless they would rather stay anonymous."

## 11. Privacy page understates what recentAudits holds

static/privacy.html:86: "the last few domains you audited in this browser". _recordRecentAudit in static/app.js stores `{domain, timestamp}` and caps the list at 10. The timestamp is not mentioned. On a page whose argument is "here is everything, and here is the file where you can check it", an unlisted stored field is the one error that costs the page its credibility.

Replace with: "the last ten domains you audited in this browser, each with the time you audited it, offered back to you as shortcuts under the search box."

Per CLAUDE.md, update the Last updated date on privacy.html in the same commit.

## 12. 404 page

static/404.html:43: "Return home to the main page, or run an audit on your domain from the homepage." Both links point to /. Replace with: `<p>The homepage is the whole tool. <a href="/">Run an audit on your domain</a>.</p>`

static/404.html:53 has a raw `&` in the footer where every other page uses `&amp;`. Match the others.

## Tests

The count test in item 2. Also a test that no static page or README mentions "Blocklist" outside live_check.py's docstring, so the removed check cannot reappear in copy.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Commit to a branch, push, merge to main, then deploy per CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-30.md in the same commit.

## Done when

The README describes the twelve checks the engine runs and nothing it does not, every RFC it cites is current, the database claim matches the privacy page, SECURITY.md uses the project address and the first person, and the three publication dates agree with the RFC Editor.
