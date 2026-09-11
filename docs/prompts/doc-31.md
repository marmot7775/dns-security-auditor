# Doc 31: factual errors in the three articles

Copy only. Every item below is a statement that is wrong against the RFC, the vendor's own documentation, or the cited source. Voice and structure items are held for a later doc; do not restyle anything here. Line numbers are from main at 24411d1; re-locate by content if they have moved. Update the visible Updated date and the JSON-LD dateModified on each article you touch.

## dmarcbis.html

### 1. The tree walk diagram teaches the wrong rule

Lines 224 to 239, the After column. Step 3 says "Query DNS one label up, _dmarc.example.co.uk, record found" and step 4 says "Use this record, Organizational domain = example.co.uk". That says the walk stops at the first record found and that record governs.

RFC 9989 section 4.10 says otherwise. Steps 5 to 7 repeat "until the process stops or there are no more labels remaining". The only early stop is a record carrying psd=n or psd=y. Otherwise the walk runs to the top and section 4.10.2 selects the Organizational Domain by rule: a psd=n record wins; else a psd=y record means the domain one label below it; else "the DMARC Policy Record found at the name with the fewest number of labels". Fewest labels, not first found. The repo's own dmarc_tree_walk.py implements this correctly.

Fix: make the After column five steps. Step 3: "Query DNS one label up: _dmarc.example.co.uk, record found". Step 4: "Keep walking: _dmarc.co.uk, _dmarc.uk, no record". Step 5: "Pick the record with the fewest labels: Organizational domain = example.co.uk". Add one sentence under the figure: "The walk does not stop at the first record. It stops early only if a record carries psd=y or psd=n. Otherwise it runs to the top and the record with the fewest labels wins."

### 2. The walk does not start one label up, and does not always go one label at a time

Line 154: "It starts at the full domain in the message and walks upward one label at a time, checking for a DMARC record at each step". And the diagram's step 2 labels the query at _dmarc.mail.example.co.uk "Query DNS one label up" when that is the From domain itself.

RFC 9989 section 4.10.1: policy discovery starts with one query at the Author Domain, and if a record is there, that is the policy and no walk happens. The walk starts at the immediate parent. Section 4.10 step 4: "If x >= 8, remove the left-most (highest-numbered) labels from the subject domain until 7 labels remain", so a long domain jumps most of the way up in one move, capped at eight queries.

Fix, line 154: "Instead of referencing a list, the receiver queries DNS directly. It asks for a record at the From domain first. If there is one, that is the policy, and no walk happens. If there is not, it starts at the parent and works upward, checking for a DMARC record at each step, capped at eight queries so nobody can grind a receiver down with a hundred-label domain:". Diagram step 2 action: "Query DNS at the From domain".

### 3. The reporting URI advice names a change that did not happen

Line 262: "Fix reporting URIs. Make sure they begin with mailto:. The new parser is stricter."

RFC 7489 section 6.3 and RFC 9989 section 4.7 use identical language for rua and ruf: any valid URI, mailto MUST be supported. Nothing got stricter about the scheme. The real change is RFC 9989 Appendix C.4: "the ability to specify a maximum report size in the DMARC URI has been removed." audit_engine.py already flags this ("rua/ruf size modifier (!N) is obsolete in RFC 9989"), so the article is telling readers to check the wrong thing.

Fix: "Drop the report size suffix. If your rua= or ruf= address carries a size limit like mailto:dmarc@example.com!10m, remove the !10m. RFC 9989 Appendix C.4 removed that syntax, and receivers implementing the new spec will ignore it. The address itself is unchanged."

### 4. The np=reject advice is backwards

Line 264: "Consider np=reject. If you are already at p=reject, this closes the non-existent subdomain spoofing gap."

RFC 9989 section 4.7, np tag: "If the np tag is absent, the policy specified by the sp tag (if the sp tag is present) or the policy specified by the p tag (if the sp tag is not present) MUST be applied for non-existent subdomains." A domain at p=reject with no sp already rejects mail from non-existent subdomains. Adding np=reject changes nothing there. np matters in the opposite case: when p or sp is weaker than reject.

Fix: "Consider np=reject. This matters most if you are not yet at full enforcement. Under RFC 9989, non-existent subdomains inherit sp= if you have it, otherwise p=. So p=reject with no sp already covers them. But if you are sitting at p=none or p=quarantine while you work through your senders, np=reject lets you shut down spoofing of subdomains that do not exist, at no risk to real mail, because there is no real mail from a subdomain that is not in DNS."

### 5. Public Suffix List size

Line 177: "External text file, ~14,000 entries". The current list from publicsuffix.org has 10,325 rules (6,950 ICANN, 3,375 private), checked Sept 9, 2026. Change to "External text file, about 10,000 rules".

### 6. The article's publication date predates the RFC

Line 33: `"datePublished": "2026-04-26"`. The article is titled "DMARCbis is now RFC 9989" and RFC 9989 was published in May 2026. The index card at static/articles/index.html:93 carries the same April date. Set both to 2026-05-20.

### 7. RFC 9091 is obsoleted too

Line 250: "Together they obsolete RFC 7489 and put DMARC on the Standards Track for the first time." RFC 9989's header reads "Obsoletes: 7489, 9091". Since the article devotes a step to psd=, the reader should know where the tag came from.

Fix: append "RFC 9989 also retires RFC 9091, the experimental PSD DMARC spec, and folds public suffix policy discovery into the tree walk. The psd= tag is what survived of it."

## dane.html

### 8. Microsoft 365 does not have inbound DANE by default

Line 95: "If your inbound mail lands at Microsoft or a European provider, you have DANE on the wire."

Per learn.microsoft.com, "How SMTP DNS-based Authentication of Named Entities (DANE) works": outbound SMTP DANE validation is on by default for Exchange Online, but inbound is opt-in per accepted domain. The admin runs Enable-DnssecForVerifiedDomain, publishes a new MX record pointing at the returned *.mx.microsoft host at priority 20, then runs Enable-SmtpDaneInbound. A tenant that has done none of that publishes no TLSA records.

Fix: "If your inbound mail lands at a European provider that publishes TLSA records, you have DANE on the wire. Microsoft 365 can do it, but not on its own: outbound DANE validation is on by default, while inbound is opt-in per domain. An admin has to enable DNSSEC for the domain, swap the MX record for the one Exchange Online hands back, and turn on inbound DANE. Until someone does that, a Microsoft 365 tenant publishes no TLSA records."

### 9. The Google outbound DANE claim has no source

Line 94: "Google does outbound DANE validation" links to a captaindns.com blog whose only support is one uncited FAQ line. Google's own MTA-STS documentation does not mention DANE or TLSA. The rest of the sentence, that Google publishes no TLSA records and prefers MTA-STS, is correct.

Fix: "Google publishes no TLSA records for Google Workspace domains and points senders at MTA-STS instead. MTA-STS fetches a transport policy over HTTPS and validates the receiver's certificate through the web PKI, with CT logs as the auditable backstop. Google's position is that the web PKI is more accountable than the DNS hierarchy for transport keys." Drop the outbound validation claim and the captaindns link.

### 10. The Dutch figure needs its sample stated

Line 73: "about a quarter of inbound email by volume to Dutch mailboxes, with a much smaller share by domain count". The cited Zivver page (September 2025) covers the 10,000 domains most emailed by Zivver customers and says it is not a random sample. It reports 25.0% of traffic and 12.56% of domains. So the by-domain share is half, not "much smaller", and the population is one vendor's corpus.

Fix: "now reaches a serious share of Dutch mail. In a September 2025 sample of the 10,000 domains most often emailed by Zivver's Dutch customers, 12.6% of domains published TLSA records, but those domains took 25% of the mail by volume. Big receivers are doing it; small ones are not." Keep the Zivver link on the sample description.

## dnssec.html

### 11. Verisign's industry brief does not track DNSSEC, and the APNIC figure is stale

Line 136: "Verisign's quarterly Domain Name Industry Brief tracks DNSSEC signing rates for .com and .net" and "APNIC Labs measures resolver-side validation closer to a third of queries globally".

The DNIB covers registration counts and growth, not DNSSEC. The Verisign product that does is the DNSSEC Scoreboard (verisign.com/resources/dnssec-tools/dnssec-scoreboard/), which reports .com and .net domains with DS records. APNIC measures the share of users behind a validating resolver, not queries, and its world row as of September 2026 reads 38.35% validating and 46.86% including partial. "Closer to a third" was true around 2022.

Fix: "Verisign's DNSSEC Scoreboard tracks how many .com and .net domains carry a DS record; the share has been creeping up and remains low. APNIC Labs measures the other end, the share of users behind a validating resolver, and as of September 2026 it reports 38% validating worldwide, or 47% counting partial validation. Both numbers are moving up. Signing is the slower one." Link the Scoreboard URL above in place of the DNIB link.

### 12. CDS scanning is a ccTLD practice, not a .com one

Line 114: "Most major TLD registries now run CDS scanners that pick those signals up automatically." Line 143: "If your TLD is .com, .net, .org, .io, .dev, .app, or any major ccTLD, the registry side is fine. CDS scanning works. The bottleneck is your registrar." Line 141: "assuming the registrar supports CDS scanning. Most major ones now do."

For .com, .net, .org, .dev, and .app the DS record reaches the registry through the registrar over EPP; the registry does not scan the child zone. The registries that do run CDS scanners are ccTLDs, .ch, .cz, .li, .se, and .nl among them. Line 141 and line 143 also contradict each other: most registrars support it, and the registrar is the bottleneck.

Fix, line 114: "A growing set of registries, mostly ccTLDs such as .ch, .cz, .li, .se, and .nl, now run CDS scanners that pick those signals up automatically. In the big gTLDs the same job falls to your registrar."

Fix, line 141: "The provider handles signing and key rollover. Getting the DS record to the registry is the handoff that still varies: some registrars pick up CDS records automatically, many still want you to paste the DS into a web form."

Fix, line 143: "If your TLD is .com, .net, .org, .io, .dev, or .app, the registry takes your DS record from your registrar and nowhere else, so your registrar is the bottleneck. Some ccTLD registries, .ch, .cz, .li, .se, and .nl among them, scan your zone for CDS records directly and skip the registrar entirely. Check which model your TLD uses before you assume automation exists."

### 13. The IANA TLD report does not exist

Line 144: "The IANA TLD report is the canonical reference." No such document, and no link. IANA's Root Zone Database (iana.org/domains/root/db) shows DS records per TLD and is the nearest real thing.

Fix: "IANA's Root Zone Database (link https://www.iana.org/domains/root/db) shows which TLDs are signed. It will not tell you whether the registry automates DS updates, so ask the registry or your registrar for that."

### 14. RSA-SHA256 is not in the same bucket as RSA-SHA1

Line 150: "Algorithm 13, ECDSA P-256. Not RSA-SHA256. Not RSA-SHA1." The IANA DNSSEC algorithm registry, which RFC 9904 made canonical when it obsoleted RFC 8624, lists RSASHA256 (8) as RECOMMENDED for signing, the same rating as ECDSAP256SHA256 (13) and ED25519 (15). RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7) are MUST NOT for signing. The line flattens three positions into one, omits Ed25519, and sits awkwardly against line 116 which says "RSA-SHA256 still works".

Fix: "Algorithm 13, ECDSA P-256, or algorithm 15, Ed25519. RSA-SHA256 is still a fine algorithm and the IANA registry still recommends it, but its signatures are large enough to push responses toward TCP fallback, which is where a good share of the old DNSSEC-broke-my-domain stories came from. RSA-SHA1, algorithms 5 and 7, is a different matter: the registry marks it MUST NOT for signing. If you are signing fresh in 2026 and your provider still defaults to RSA, ask them why."

### 15. The six-year claim does not fit the RFCs it follows

Line 119: "Most of this happened in the last six years." The section just walked through RFC 6605 (2012), RFC 7344 (2014), RFC 7477 (2015), RFC 8078 (2017), and RFC 9615 (2024). Only the last one is inside six years. What happened recently is the provider rollout.

Fix: "The standards took twelve years. The provider rollout that made them matter mostly happened in the last six."

### 16. Three references with no link, one attributing a position to a named person

Line 104: "I read Against DNSSEC when it came out. I cited it. The IANIX outage list was earned. Paul Vixie publicly soured on the adoption trajectory and the criticism stuck." Every other reference in the article is linked. The Vixie sentence attributes a position to a living person with no source.

Fix: link "Against DNSSEC" to https://sockpuppet.org/blog/2015/01/15/against-dnssec/ and the IANIX list to https://ianix.com/pub/dnssec-outages.html. Replace the Vixie clause with "None of that was wrong at the time."

## Tests

A test that every href in static/articles/*.html to rfc-editor.org or datatracker.ietf.org names an RFC number that appears in the article text, and that no article links to captaindns.com. Cheap, and it catches the next unsourced vendor blog.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md only if style.css or a JS file changes; article HTML alone does not need it.
Commit to a branch, push, merge to main, then deploy per CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-31.md in the same commit.

## Done when

The tree walk diagram matches RFC 9989 section 4.10, no article tells a reader to do something the RFC does not ask for, every provider claim matches that provider's own documentation, every statistic names its source and sample, and every cited RFC number is current.
