# Doc 33: use the audited domain in examples, and delete merged branches

Line numbers are from main at 82ad343; re-locate by content if they have moved.

## 1. Placeholder domain in text about a real domain

The audited domain is in scope at every one of these sites (the enclosing function already takes `domain` or reads `raw["domain"]`), so the placeholder reads as a mistake to the person whose domain it is.

result_transformer.py:2672 "secure-login.yourdomain.com and spoof mail from them."
result_transformer.py:2698 "secure-login.yourdomain.com. Without np=, the policy for these is"
result_transformer.py:3081 "secure-login.yourdomain.com have no enforcement while your root domain rejects."
checks_extra.py:440 "Add mx lines, e.g., 'mx: mail.yourdomain.com'."
checks_extra.py:689 "Add rua=mailto:tls-reports@yourdomain.com"
checks_extra.py:945 "l=https://yourdomain.com/logo.svg;"

Fix: use `{domain}` (or the `_dom` fallback variable that Doc 32 introduced in the two DMARC helpers) in each. For checks_extra.py:440, if the MX check's hosts are available in scope, use the real primary MX host; otherwise `mail.{domain}`. Leave result_transformer.py:2296, 2598, 3010, 3541, 3700, and 3864 alone; those are the fallbacks for when no domain was passed, which is correct.

Extend the Doc 32 test that pins the subdomain warnings to the audited domain so it also asserts that no card, warning, or fix string contains "yourdomain.com" when a domain was supplied.

## 2. Delete merged remote branches

All four are fully merged into main (verified with git merge-base). Delete them on origin:

claude/review-dns-audit-w8UyI
cut-top1000
fix-audit-defects
log-schema

Do not delete anything else. If a branch turns out not to be an ancestor of main, stop and say so instead of deleting it.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Commit to a branch, push, merge to main, then deploy per CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-33.md in the same commit.

## Done when

No generated string shows yourdomain.com to a user who supplied a domain, and origin has only main.
