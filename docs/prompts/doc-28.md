# Doc 28: false or unsupported statements in app output

Context: a cold copy review of everything the app tells a user (cards, warnings, executive summary, roadmap, generated records, PDF) found statements that are wrong against the RFC, unsupported by any source, or that contradict another sentence on the same screen. This doc fixes the ones that put a false statement in front of a user. Pluralization, tone, and README items are separate docs.

Doc 27 is merged and live and already covers the Protocol Coverage count; do not touch that here.

Line numbers are from main at 24411d1. Re-locate by content if they have moved.

## 1. Generated DMARC records carry an inert fo=1

result_transformer.py:3665 builds the recommended record for a domain with no DMARC as `v=DMARC1; p=none; fo=1; rua=mailto:dmarc@{domain}`. The migration target at 3629 is `v=DMARC1; p=reject; sp=reject; np=reject; fo=1; rua=...`. The wizard step at 3592 to 3598 says "Set fo=1 for full failure visibility" with the reason "fo=1 captures all failures." The change list just below 3665 gives the same reason.

RFC 9989 section 4.7, fo tag: "This tag's content MUST be ignored if a ruf tag is not also specified." None of these records include ruf, so fo=1 does nothing and the stated reason is false. The same file already knows this: the fo warning near 3154 is gated on ruf being present, and the note near 2735 tells the reader that most large receivers no longer send failure reports at all. The record builder then adds the tag anyway.

Fix: remove fo=1 from every generated record and target string that does not also include ruf. Remove the fo migration step and the fo change-list entry unless the current record has ruf. Where a fo step survives because ruf is present, the why text reads: "fo=0 reports only when every mechanism fails. fo=1 reports when either SPF or DKIM fails. The tag has no effect unless ruf= is also set."

Search the file for every other place that emits fo=1 into a record string, including result_transformer.py:2743 and 3160, and apply the same rule.

## 2. Wrong RFC section on the malformed-DMARC issue

audit_engine.py:1042: "RFC 9989 section 5.4 defines the version tag value as case sensitive". Section 5.4 is Policy Enforcement Considerations. The rule is in section 4.7: "The tag value is case sensitive, and the only possible value is DMARC1."

Fix: change 5.4 to 4.7. The parallel MTA-STS and TLS-RPT strings in checks_extra.py cite their sections correctly; check nothing else in that block cites 5.4.

## 3. PermError described wrong, and hedged on one surface

result_transformer.py:3997: "Receiving servers treat an SPF PermError as if no SPF record exists, which damages sender reputation."

RFC 7208 section 2.6.7 defines permerror as records that could not be interpreted; "none" (2.6.1) is a different result. Receivers do not map one onto the other, and "damages sender reputation" has no source anywhere in the codebase.

remediation_planner.py:203 for the same finding: "Receivers may treat this as a PermError and reject or skip SPF evaluation entirely." RFC 7208 section 4.6.4 is a MUST: "If this limit is exceeded, the implementation MUST return permerror." No may.

Fix, result_transformer.py:3997: "Receivers must return PermError once the limit is exceeded (RFC 7208 section 4.6.4). A PermError is not a pass, so SPF cannot satisfy DMARC alignment for any message from this domain. Audit your includes and remove services you no longer use."

Fix, remediation_planner.py:203: "Your SPF record requires {spf_lookups} DNS lookups, past the limit of 10 in RFC 7208 section 4.6.4. Receivers must return PermError, so SPF cannot pass for any message and cannot satisfy DMARC alignment."

## 4. Executive summary: overreaching verdict and a dead branch

result_transformer.py:266 to 267: when DMARC is missing and `spf_status == "fail"`, the verdict is "Your domain has no email authentication. Anyone on the internet can send email pretending to be you."

SPF status fail also fires for +all, for two published records, and for a syntax error, all of which mean SPF exists. DKIM is not consulted. The same file gets the gate right elsewhere with `pill_label == "Missing"`. The second sentence is a prediction the audit has no evidence for.

Fix: gate on `spf_check.get("pill_label") == "Missing"` and reword: "Your domain publishes neither an SPF record nor a DMARC record. Receivers have no way to tell your mail from mail that only claims to be yours, and no policy to apply when it fails." Keep the existing else branch for the SPF-present case.

result_transformer.py:272: `elif protected_count == 4:`. The vectors list built just above it excludes Reporting Intelligence, so it holds at most three entries and this branch can never be true. A fully protected domain falls through to the next branch, "most attack vectors covered", while the Spoofing Protection metric beside it says "Every spoofing vector protected."

Fix: `elif _vector_total and protected_count == _vector_total:`.

## 5. Gmail and Yahoo claim is wrong for most of the audience

result_transformer.py:467: "Without DMARC, your business emails may be landing in spam. Gmail and Yahoo now require DMARC for reliable delivery."

Google's sender guidelines (https://support.google.com/a/answer/81126) require SPF or DKIM of all senders. DMARC is required only of senders at 5,000 or more messages a day, and there "your DMARC enforcement policy can be set to none." Yahoo's requirement is likewise scoped to bulk senders. The sentence as written is false for every sender below that threshold, which is most people who run this tool.

Fix: "Without DMARC, receivers have no instruction for mail that fails authentication, and you get no reports about who is sending as you. Google and Yahoo require DMARC of bulk senders (Google's threshold is 5,000 messages a day to Gmail); below that it is optional but still the only way to see what is being sent in your name."

## 6. Tree walk panels badge an obsolete RFC

static/app.js:2866 badges the DMARC Evaluation panel `rfc7489`, linking to RFC 7489. static/app.js:2915 badges the Report Delivery Chain `rfc7489 §7.1`. The same file calls RFC 7489 obsolete at 1514 and 1534, and the evaluation panel's own note at 2882 talks about RFC 9989 behavior.

Fix: evaluation panel badge `rfc9989` linking to https://datatracker.ietf.org/doc/html/rfc9989. Report chain badge `rfc9990 §4` linking to https://datatracker.ietf.org/doc/html/rfc9990#section-4 (Verifying External Destinations, which is where that rule now lives).

## 7. SPF lookup list drops ptr and mislabels redirect

static/app.js:2994: "RFC 7208 limits SPF to 10 DNS-querying mechanisms (include, a, mx, redirect, exists)."

RFC 7208 section 4.6.4: "The following terms cause DNS queries: the include, a, mx, ptr, and exists mechanisms, and the redirect modifier." A reader counting their own record against the on-screen list comes up short.

Fix: "RFC 7208 caps SPF at 10 terms that cause a DNS query: the include, a, mx, ptr, and exists mechanisms, and the redirect modifier. Past the cap, receivers return PermError."

## 8. MTA-STS extension tags flagged as invalid

checks_extra.py:309 to 317: any TXT tag other than v and id gets a warning "Valid MTA-STS TXT tags are: v, id" and a fix "Remove '{key}' from the record."

RFC 8461 section 3.1 ABNF: `sts-field = sts-id / sts-extension`. Extension fields are legal and senders ignore unknown ones. The fix tells the operator to delete something the spec permits.

Fix: severity info. Text: "'{key}' is not a tag defined in RFC 8461 section 3.1. The record format allows extension fields, so senders ignore it rather than reject the record. Remove it only if it was a typo for v or id."

## 9. DKIM fix names a key size the finding may not have

remediation_planner.py:283 to 288: "One or more of your DKIM selectors use 1024-bit RSA keys". `has_weak_dkim` comes from dkim_formatter.py, which flags any key under 2048 bits, so this fires on 512, 768, and 1536 too and then tells the reader they have 1024. audit_engine.py:265 words the same finding without inventing a size.

Fix: "One or more of your DKIM selectors publish an RSA key shorter than 2048 bits, below what RFC 8301 recommends. Rotate those selectors to a 2048-bit RSA key or an Ed25519 key."

## 10. TLS-RPT issue names the wrong actor

checks_extra.py:757: "so receivers discard this record." TLS-RPT records are read by the sending MTA, which is the party that generates the report. The parallel MTA-STS string at checks_extra.py:530 says "senders discard this record", correctly.

Fix: "so sending mail servers discard this record and never generate a report."

## 11. PDF prints an all-clear under a summary that says otherwise

pdf_report.py:650: when the roadmap is empty, the PDF prints "No action items. Your email security meets all current best practices." The code just above it has already printed `roadmap["summary"]`, which result_transformer.py writes specifically for this case: on a scoped run it names the checks that were not run, and after a failed lookup it says "This is not an all-clear." The hardcoded line then contradicts it on the same page, and on a real all-clear it says the same thing twice.

Fix: delete the else branch. The summary already covers every empty-roadmap case.

## Tests

For item 1, a test that no record string emitted by the builder or wizard contains `fo=` unless it also contains `ruf=`.

For item 4, a test that a domain with DMARC missing and SPF present-but-failing (+all) does not get the "no email authentication" verdict, and a test that a domain with every vector protected gets the "all attack vectors" verdict, not "most".

For item 8, a test that an MTA-STS TXT record with an extension tag produces no warning-severity issue.

For item 11, render a PDF from a scoped result with an empty roadmap and assert the text "meets all current best practices" does not appear.

Assert on rendered text, not on dicts, wherever the surface is the PDF or app.js.

## Repo rules

No em dashes and no double hyphens in any user-facing string.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Commit to a branch, push, merge to main, then deploy per CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-28.md in the same commit.

## Done when

No generated record carries a tag the RFC says will be ignored, every RFC section cited in these strings is the section that contains the rule, the Gmail claim matches Google's published guidelines, and the PDF no longer prints an all-clear under a summary that says it is not one.
