# Doc 34: PDF fixes, then the palette

Two parts, done in order as two separate PRs. Part A first: branch, PR, CI, merge, deploy, health SHA. Only then Part B, the same way. Do not combine them in one PR.

# Part A: PDF rendering defects and one false sentence on scoped reports

Reproduced today by rendering two PDFs from main at 17964ba against a fixture zone (SPF, one DKIM selector, DMARC p=none with pct and ri, two MX, no DNSSEC, no MTA-STS), one complete and one scope=dns_infra, then rasterizing with pdftoppm and reading the pages. Line numbers are from 17964ba; re-locate by content if they have moved.

Item 1 is a false statement and goes first. The rest are layout.

## 1. A scoped PDF says DNS did not answer when the checks were never run

Doc 27 item 3 made build_executive_summary treat a scoped-out check as unassessed, which fixed the false "email authentication configured" verdict. But it reused the lookup-failure wording. On scope=dns_infra the cover and the Executive Summary now read: "Parts of this domain's DNS did not answer, so its email authentication was not assessed. The DMARC, SPF and DKIM lookups did not complete, and this report cannot say whether those records exist." DNS answered fine. The checks were not in scope. The Spoofing Protection metric detail says "DMARC lookup did not complete" for the same reason.

result_transformer.py:260 to 265 (verdict) and 342 (metric detail). The code already distinguishes the two cases: `_unavailable(name)` versus `_scoped_out(name)`.

Fix: when the unassessed checks are scoped out rather than unavailable, the verdict reads: "This run did not check email authentication. DMARC, SPF, and DKIM were outside its scope, so this report makes no claim about them. Run the Complete Audit or Email Security scope for that." Metric detail: "Not in this run's scope." When some are unavailable and some scoped out, say both, naming which is which. Keep the existing lookup-failure wording for the unavailable case.

Add a test that a scope=dns_infra result's verdict does not contain "did not answer" or "did not complete".

## 2. Migration path puts a calendar on DMARC monitoring

result_transformer.py:3559: "Review aggregate reports for 2-4 weeks". Also pdf_report.py:1820 in the sample data. This is step 1 of the migration wizard on the web and in the PDF.

How long p=none monitoring runs depends on the sender inventory settling, not on a date. Two to four weeks is wrong for any domain with more than a few sending services and reads as reckless to anyone who has run a real rollout.

Fix: "Review aggregate reports until the sender inventory is stable". Why text: "Identify every legitimate sender and fix their SPF or DKIM alignment before enforcing. Move on when a full reporting cycle shows no new legitimate sources, not on a date." Apply to both files.

Add a test that no migration step, roadmap item, or fix string contains "weeks" or "days" as a duration for monitoring.

## 3. Roadmap is not ordered by priority

result_transformer.py:566, build_security_roadmap, appends items in check order and never sorts. On the fixture, the roadmap table reads HIGH (DMARC) at #1 and CRITICAL (DKIM) at #2. The tier counts above the table are right; the rows below them are not.

Fix: stable sort `items` by priority rank (critical, high, medium, low) before returning, so the web roadmap and the PDF both get the order. Test with a result that has a critical item after a high one.

## 4. Roadmap table columns too narrow

pdf_report.py, the roadmap table around 583 onward. Priority and Protocol columns wrap mid-word: "CRITICA L", "MTA-ST S", "TLS-RP T". Widen those two columns (Priority needs room for CRITICAL in bold caps, Protocol for TLS-RPT and MTA-STS) and take the width from the Business Impact column, which has the most slack.

## 5. Cover count overprints its label

pdf_report.py:189 to 191, _findings_summary. The 22pt total is placed in a Paragraph with leading 16, so the digits descend into the "checks total" line under it. On the rendered cover the "12" sits on top of "checks total". Give that first Paragraph a leading of at least 26, or put the number and label in one Paragraph with a line break.

## 6. Metric label and detail run together

pdf_report.py:353: `_metric_cell(f"Spoofing Protection\n{sp_detail}", ...)`. ReportLab Paragraph ignores the newline, so the cover reads "Spoofing Protection Every spoofing vector exposed" as one run-on line. Use `<br/>` in the label markup, or render the detail as a second Paragraph in the cell with the smaller style.

## 7. Warning glyph renders as a black box

pdf_report.py:88 DETAIL_ICON uses U+26A0 for warnings; 479, 482, 806, and 839 use it too. Helvetica has no glyph for it, so every warning line in the DMARC deep dive, the strict-validation list, and the biggest-risk box prints a filled square. The check and cross glyphs render.

Fix: either register a TrueType font that has the glyph (DejaVuSans is on the droplet at /usr/share/fonts/truetype/dejavu/ and on most Debian systems; check with fc-list before relying on it, and fall back if absent) and use it for icon spans only, or replace the warning glyph with a bold "!" in the warning color. The second is simpler and has no font dependency. Whichever is chosen, add a test that rasterizes one page containing a warning line and asserts no .notdef box: the cheap version is to extract text with pypdf and assert the glyph used is present in the font, or assert the icon character is in a fixed allowlist of characters known to render in the registered fonts.

## 8. TOC on a scoped PDF lists sections that do not exist

pdf_report.py:373 to 385 builds a fixed seven-item table of contents. On scope=dns_infra the PDF contains sections 1, 2, 5, and 7, but the TOC lists 3 (DMARC Deep Dive), 4 (Attack Surface Analysis), and 6 (Migration Path), and the numbering leaves gaps. The scope line Doc 27 added is correct; the TOC above it contradicts it.

Fix: build the TOC from the sections actually emitted, and number them consecutively. The section header numbers at 449, 583, 690, 939, 1135, 1488, and 1565 are hardcoded strings; derive them from a counter so a scoped PDF reads 1, 2, 3, 4 rather than 1, 2, 5, 7.

## Part A verification

Render the two fixtures again (complete and scope=dns_infra), rasterize every page with pdftoppm, and look at them. Assert on rendered text for items 1, 2, 3, and 8. Items 4 through 7 are visual; confirm by eye and keep the PNGs out of the commit. Save this part as docs/prompts/doc-34.md in its commit.

# Part B: palette and type, Phases 1 and 2 only

Go on the Phase 1 and Phase 2 work you proposed (type scale consolidation, one brand accent, calmer status colours, deeper dark ground, warmer light ground, PDF colours mirrored). Conditions:

Every text and status colour passes 4.5:1 in both themes, and the existing contrast and axe tests stay green.

The fail red change updates the CLAUDE.md rule in the same commit, with the new hex values and the reason.

Before and after screenshots of the homepage, a results page, and one article, in both themes, go in the PR description.

Nothing from Phase 3: no layout changes, no logo swap, nothing added under the input, no changes to results page structure. Tokens, sizes, weights, and colours only.

Cache-bust per CLAUDE.md. Save the Phase 1 and 2 proposal text you wrote as docs/prompts/doc-35.md in that commit.

# Repo rules, both parts

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Each part: commit to its own branch, push, PR, wait for CI, merge to main, deploy per CLAUDE.md, confirm /api/health reports the new SHA. Report both SHAs.

# Done when

Part A: a scoped PDF says its checks were out of scope rather than that DNS failed, the migration path names a condition rather than a number of weeks, the roadmap lists critical items first, and every page of both fixtures renders cleanly with a table of contents that matches the sections present.

Part B: the site renders in both themes with the new tokens, every contrast check passes, and the PR carries the before and after screenshots.
