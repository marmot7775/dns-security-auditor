# Doc 27: PDF report says things the audit did not find

Four defects where the PDF (and in two cases the web summary) states something the data does not support. Each was reproduced against the transformer or the rendered PDF. Line numbers are from main at d25d110; re-locate by content if they have moved. Do not redo Doc 29; it is merged and live.

## 1. Protocol Coverage counts unpublished protocols as configured

result_transformer.py:352:

    elif st in ("warn", "fail") and pill not in ("Missing", "Not configured", ""):
        configured += 1

The count decides "configured" by testing the display label against a two-entry allowlist. The transformer emits at least five other labels that mean nothing is published: "Not found" (DKIM, 4496), "Not enabled" (DNSSEC), "No mail" (SPF, 3867), "None" (5143), and "N/A" (4462, 5334, 5515, 5632). A pass-status card can also carry "Not configured" or "N/A" (BIMI, DANE) and the pass branch counts it without looking at the pill at all.

Reproduced on a zone that publishes no records: the PDF cover and the web executive summary both report Protocol Coverage 4/8. Half the stack shown as configured on a domain with nothing in DNS.

Fix: stop testing pill_label against a hardcoded allowlist. That approach fails silently every time anyone adds a pill, which is how it got here. Decide configured from the check result itself, not from the display label. Add an explicit boolean the transform layer sets per card (for example `configured: True` when the check found a record), so a new pill cannot change the count by accident, and so the cover (pdf_report.py:353) and the body are reading the same fact.

## 2. The DMARC Deep Dive drops the finding and the remediation

pdf_report.py:661, _dmarc_deep_dive. It reads status, verdict, record, tag_breakdown, strict_validation, and record_builder. It never reads details, explanation, or fix. DMARC is also excluded from _protocol_details at pdf_report.py:1072, which has no DMARC branch, so there is no second rendering. Every other check gets all three through _protocol_card at 1145.

Reproduced on a domain with SPF and MX and no _dmarc record, the most common failing case this tool reports. Section 3 of the PDF is, in full: the DMARC FAIL line, "No DMARC policy published", and the Record Builder with a recommended record. Dropped: the error detail naming the absent record, the explanation, and the fix. The fix survives only as an unlabelled numbered line in Priority Fixes.

Second reproduction, a domain whose rua points at a third-party domain that has not published the authorization record. The card carries 12 details, two at severity error, including "Aggregate reporting (rua): 2 destinations, 1 unauthorized (reports silently dropped)" and the explanation. Neither string appears anywhere in the rendered PDF. Meanwhile the Deep Dive prints the opposite as fact: "Aggregate reports are sent to reports@thirdparty..." So a broken reporting setup is presented in the PDF as a working one.

Fix: render details, explanation, and fix in the DMARC section the way _protocol_card does for every other check. Keep everything the section renders today; this is an addition, not a replacement. Error-severity details in particular must not be droppable.

## 3. A scoped PDF asserts findings from checks it never ran

result_transformer.py:253, build_executive_summary. The unavailable guard at 179 to 193 catches status == "unavailable". A check that was out of scope is absent from check_map entirely, so it never reaches that guard and falls through to the else at 253:

    verdict = "Your domain has email authentication configured."

scope=dns_infra is a live UI button on the homepage, and the PDF button forwards the scope, so /api/audit/{domain}/pdf?scope=dns_infra is a real path a user can reach. That scope runs DNSSEC, CAA, DANE, CT, and nameservers only.

Reproduced: cover page 1 and Executive Summary page 2 both read "Your domain has email authentication configured", and the cover reads "Action Needed" under RFC 9989 Readiness. No DMARC, SPF, or DKIM query was made. Same for scope=transport.

One branch away, the code already does this right: when a check is unavailable it says "Not assessed" (268, 316) precisely to avoid advice drawn from a record never read. Out of scope needs the same treatment.

Fix: treat absent-from-check_map the same as unavailable in build_executive_summary. A check that did not run cannot support a verdict about it. Also name the scope on the PDF cover (the result dict carries `scope`, audit_engine.py:5564) so the reader knows the document covers five checks rather than twelve. A scoped report that does not say it is scoped is the underlying problem.

## 4. A failed nameserver lookup is rendered as a missing-NS finding

audit_engine.py:3546 to 3555, _raw_check_nameservers. The generic dns.exception.DNSException handler sets status "error" and returns with no lookup_failed flag, so a SERVFAIL, NoNameservers, or timeout is indistinguishable from a real answer. result_transformer.py:6540 to 6552 then emits status fail, pill Missing, verdict "No nameservers found", and the explanation "Without them, nothing works: no website, no email, no DNS resolution", with the fix "Configure NS records with your domain registrar."

Reproduced with every query raising NoNameservers. It also becomes the cover's only issue and Priority Fix number 1.

This is exactly what 28c644c fixed for DNSSEC and CAA (see lookup_failed at 3006, 3021, 3376). Nameservers was not included. A DNSSEC-bogus zone SERVFAILs at the validating resolver this tool uses, so a real zone reaches this path and is told to go add NS records at its registrar.

The neighbours are fine: MTA-STS, TLS-RPT, and DANE carry lookup_failed and come out unavailable. Nameservers is the outlier.

Fix: set lookup_failed on every exception path in _raw_check_nameservers where the answer came from an exception rather than a real negative answer, and route a lookup_failed result to the unavailable status the other checks already use. NXDOMAIN is a genuine answer and stays a finding.

## Tests

tests/test_unavailable_checks_never_pass.py and tests/test_summary_hears_unavailable.py have no nameserver case and no scoped-audit case, which is why items 3 and 4 survived. Add both.

For item 1, add a test that the cover count equals the number of checks the body renders as configured, driven from a real transformer result rather than a hand-built dict, so a new pill cannot desync them again.

For item 2, assert that every error-severity detail on the DMARC card appears in the rendered PDF text. Extract with pdfplumber or pypdf text extraction; that is the assertion that would have caught it.

Assert on rendered PDF text, not on the result dict. Every one of these four was correct in the data and wrong in the document.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Commit to a branch, push, merge to main, then deploy per CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-27.md in the same commit.

## Done when

The cover count matches what the body says, the DMARC section carries its own finding and fix, a scoped PDF says what it covered and claims nothing about what it did not check, and a failed NS lookup is not a finding.
