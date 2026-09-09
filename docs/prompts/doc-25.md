# Prompt 25: a record that fails the version gate is reported as no record

Repo: dns-security-auditor. HEAD 2c967a3, 750 tests pass. Keep them passing.

One fix. It predates prompt 24 rather than being caused by it; fixing the
version gate is what made this the next thing standing between a broken
record and an honest answer about it.

## A TXT record at _dmarc that fails the version gate vanishes entirely

Reproduce with a domain publishing a record that is real but not valid:

  _dmarc.example.com TXT:  v=dmarc1; p=reject; rua=mailto:d@example.com

  raw result from _raw_check_dmarc:
    record               None
    has_record           None
    non_dmarc_txt_count  None
    status               error
    syntax_errors        [{severity: error,
                           issue: "Lowercase v=dmarc1 detected",
                           plain_english: "Lowercase v=dmarc1 detected.
                             RFC 7489 requires uppercase. This record is
                             invalid and will not be honored.",
                           fix: "Change to v=DMARC1 (uppercase)."}]

  card the user sees:
    status:  fail
    verdict: No DMARC policy published
    detail:  [error] No DMARC record exists at '_dmarc.example.com'.
             Since February 2024, Google and Yahoo require at least...
    fix:     Publish a DMARC TXT record at _dmarc.example.com with p=none...

The engine got it right. audit_engine.py:939-947 detects the case
deviation and records exactly the sentence the user needs. The transform
layer throws it away and tells them to publish a record they already
published.

Why it is thrown away: result_transformer.py reads syntax_errors only from
inside branches that assume a record exists. Line 1686 sits inside the
record branch, and line 1962 is an elif reached after those branches. When
raw["record"] is None the code takes the no-record path at line 1585 and
never looks at syntax_errors at all.

This is not only about lowercase. Any TXT record at _dmarc that fails the
version gate lands in the same hole, and it also failed to register as
non-DMARC TXT: non_dmarc_txt_count is None here, so the existing
"non-DMARC TXT records present" path does not catch it either. The record
falls between two checks and disappears.

Fix, in two parts.

Engine: when a TXT record at the DMARC name fails the version gate, keep
the record text and the reason on the result rather than discarding both.
Add a field saying a record was present and rejected, and why, using the
deviations dns_tools.version_tag_deviations already computes.
is_dmarc_version_tag currently throws that output away.

Transformer: add a branch for a record that is present and rejected,
ordered before the no-record branch at 1585. It must not say the domain
publishes nothing. Say a record is present at that name, that it is not a
valid DMARC record, quote it, give the specific reason from the engine,
and make the fix the correction rather than "publish a DMARC record."

The correct card for the reproduction above reads roughly: a TXT record is
published at _dmarc.example.com but its version tag is lowercase, and RFC
9989 section 5.4 defines the value as %s"DMARC1", which is case sensitive,
so receivers ignore the record and the domain is unprotected. Fix: change
v=dmarc1 to v=DMARC1.

Grade it fail, not unavailable. The lookup succeeded, the answer is known,
and the answer is that the domain has no working DMARC. Unavailable is for
questions the tool could not answer, and this one it answered.

Check whether BIMI, TLS-RPT and MTA-STS have the same hole now that they
reject wrong-case records. Prompt 24 gave TLS-RPT and MTA-STS a malformed
card, so they may already be correct, but a rejected BIMI record may be
reporting as no record. Reproduce each rather than reading.

## Tests

Add a case per record type covering a present-but-rejected record,
asserting the user-visible verdict does not claim the record is absent and
that the fix names the correction rather than telling the user to publish.

Assert on the card text, not the raw dict. The raw result was already
correct here and the card is where it went wrong.

## Repo rules

No em dashes and no double hyphens in any user-facing string.
Run python3 -m pytest tests/ -q. All 750 plus your new ones must pass.
Restart the service after deploy, per CLAUDE.md line 91.

## Done when

A domain publishing v=dmarc1 is told its record has a lowercase version tag
and how to fix it, and no card claims a record is absent when a record is
present and rejected.
