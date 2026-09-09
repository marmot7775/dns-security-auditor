# Prompt 26: say who built this and how to reach him

Repo: dns-security-auditor. HEAD 8d27692, 765 tests pass. Keep them
passing.

The site is a lead generator that currently has no path to a lead. The
entire hire route is one sentence at static/about.html:79 plus a 14px
LinkedIn icon in the footer attribution. The results page, where a visitor
has just been shown a list of problems with their own domain, says nothing
about who built the tool or how to reach him.

Three changes. Copy is given verbatim below; use it as written.

## 1. A contact line under the results, shown only when findings exist

Render it after the last result card, before the footer. Show it only when
the audit produced at least one fail or warn. A clean domain gets nothing,
because there is nothing to hand off and a pitch on a clean report reads
as a pitch.

Exact copy:

  Some of these are a five minute DNS change. Some are not. If you want a
  second opinion on which is which, this is what I do for a living.
  neil@dns-audit.com

Style it as quiet text, not a call to action box. No button, no border, no
accent colour, no exclamation. It should read like a note at the bottom of
a report rather than an advertisement. Match the muted body text already
used for secondary copy on the page, and give it the same max width as the
result cards so it lines up with them.

The email is a plain mailto link. Do not obfuscate it with JavaScript. The
address will get scraped and Neil can filter mail, which is the thing he
does professionally; friction on the only contact path costs more than the
spam does.

## 2. Replace the hero subtitle

static/index.html:140 currently reads:

  Analysis of your email authentication and DNS security configuration.
  Includes RFC 9989 readiness, DNSSEC validation, and more.

That describes the tool. Replace the first sentence with the one that
argues for it, keeping the existing RFC 9989 link exactly as it is:

  Most DNS tools show you your records. This one tells you what is wrong
  with them. Includes RFC 9989 readiness, DNSSEC validation, and more.

Keep the <a> around "RFC 9989 readiness" pointing at /articles/dmarcbis
with the same class. Only the leading sentence changes.

## 3. Put the email in the footer

The footer attribution on all eight pages currently says "Built by Neil
Anuskiewicz" followed by the LinkedIn icon. Add the address after the name
so every page has a contact path, not just the results:

  Built by Neil Anuskiewicz  neil@dns-audit.com  [LinkedIn icon]

Same mailto treatment, same muted footer link styling as the existing
footer links. Keep the LinkedIn icon and its 44px mobile target exactly as
it is now, including the fix that stopped it stealing taps from neighbours.
Verify with document.elementFromPoint at 375px that adding the address does
not reintroduce an overlap.

## What not to do

No modal, no popup, no sticky bar, no "get a free consultation", no form.
No email capture of any kind. No language that promises an outcome. The
credibility of this tool is that it is free, honest and unwalled, and that
credibility is the thing generating the lead in the first place.

Do not add the contact line to the PDF. That is a separate decision.

## Repo rules

No em dashes and no double hyphens in any user-facing string.
Run the cache-bust step from CLAUDE.md as the final commit step, since this
touches static files including static/articles/*.html.
Run python3 -m pytest tests/ -q. All 765 must pass.
Restart the service after deploy, per CLAUDE.md line 91.
Save this doc as docs/prompts/doc-26.md in the same commit.

## Done when

A visitor whose audit found problems can reach Neil without leaving the
results page, every page footer carries an address, and the homepage makes
a claim instead of a description.
