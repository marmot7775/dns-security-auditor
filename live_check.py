#!/usr/bin/env python3
"""Run a fixed set of domains through the live API and print card statuses.

Every review before this one ran against a resolver on the development
machine, not the droplet's. That is why the Blocklist check went years
without anyone noticing it never returned a result: locally it answered,
and in production Spamhaus refuses queries from the droplet's cloud range.
A check that behaves differently in the two places is invisible to a test
suite and to a local audit, and only a run against the deployed site finds
it.

Output is deterministic: fixed domain order, fixed card order, one line per
card. Two runs diff cleanly, so a deploy that was supposed to change three
verdicts can be shown to have changed exactly those three.

    python3 live_check.py                    # against production
    python3 live_check.py --base http://127.0.0.1:8000
    python3 live_check.py > docs/live-baseline.txt

Exit status is 1 if any domain could not be audited at all, so this is
usable as a smoke test after a deploy.
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

# Chosen to cover the branches that differ: Google-hosted with retired DKIM
# selectors, Microsoft-hosted (our own), self-hosted with real DANE, and a
# provider whose selectors sit behind a CNAME.
DOMAINS = ["google.com", "dns-audit.com", "ietf.org", "proton.me"]

# Fixed render order. A card absent from a run prints as "-", so a check
# being removed or failing to appear is visible rather than silently missing.
CARD_ORDER = [
    "DMARC", "SPF", "DKIM", "MX Records", "MTA-STS", "TLS-RPT",
    "DANE", "DNSSEC", "CAA", "BIMI", "Nameservers",
    "Certificate Transparency", "Blocklist",
]

DEFAULT_BASE = "https://dns-audit.com"


def audit(base, domain, scope, timeout):
    url = f"{base}/api/audit?" + urllib.parse.urlencode(
        {"domain": domain, "scope": scope}
    )
    req = urllib.request.Request(url, headers={"User-Agent": "live-check/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--scope", default="complete")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--domains", nargs="*", default=DOMAINS)
    args = ap.parse_args()

    print(f"# live check  base={args.base}  scope={args.scope}")
    failed = False

    for domain in args.domains:
        print(f"\n{domain}")
        try:
            result = audit(args.base, domain, args.scope, args.timeout)
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
            print(f"  !! audit failed: {type(e).__name__}: {str(e)[:80]}")
            failed = True
            continue

        cards = {c.get("name"): c for c in result.get("checks", [])}
        for name in CARD_ORDER:
            card = cards.get(name)
            if card is None:
                print(f"  {name:26s} -")
                continue
            pill = card.get("pill_label") or ""
            print(f"  {name:26s} {card.get('status', '?'):12s} {pill}")

        # Any card the fixed order does not know about, so a new check shows up
        # here instead of going unreported.
        for name in sorted(set(cards) - set(CARD_ORDER)):
            print(f"  {name:26s} {cards[name].get('status', '?'):12s} "
                  f"{cards[name].get('pill_label') or ''}  (unlisted)")

        summary = result.get("executive_summary") or {}
        coverage = summary.get("protocol_coverage") or {}
        print(f"  {'· coverage':26s} "
              f"{coverage.get('configured', '?')}/{coverage.get('total', '?')}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
