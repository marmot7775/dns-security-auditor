"""
Doc 29, item 5: the visible scope description under the scope buttons is
copied straight from each button's title attribute (see app.js), so a
title that names fewer checks than the scope actually runs is on-page
misinformation, not just a stale tooltip.

This test locks each scope button's title to the check set audit_engine
actually runs for that scope (SCOPE_CHECKS), so the two cannot drift apart
again without a failing test pointing at the fix.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import SCOPE_CHECKS

INDEX_HTML = os.path.join(os.path.dirname(__file__), "..", "static", "index.html")

# Every check key audit_engine knows about, i.e. what SCOPE_CHECKS["complete"]
# (None = run all) expands to. Kept as a literal list, not derived from the
# union of the other scopes, so a scope that stops covering some check does
# not silently shrink what "complete" is checked against.
ALL_CHECK_KEYS = {
    "dmarc", "spf", "dkim", "mx", "mta_sts", "tls_rpt", "bimi",
    "dnssec", "caa", "dane", "nameservers", "ct",
}

CHECK_DISPLAY_NAMES = {
    "dmarc": "DMARC",
    "spf": "SPF",
    "dkim": "DKIM",
    "mx": "MX",
    "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT",
    "bimi": "BIMI",
    "dnssec": "DNSSEC",
    "caa": "CAA",
    "dane": "DANE",
    "nameservers": "nameservers",
    "ct": "Certificate Transparency",
}


class TestScopeButtonTitlesMatchScopeChecks(unittest.TestCase):
    def setUp(self):
        with open(INDEX_HTML, encoding="utf-8") as f:
            self.html = f.read()
        self.assertEqual(
            set(CHECK_DISPLAY_NAMES), ALL_CHECK_KEYS,
            "CHECK_DISPLAY_NAMES in this test is missing a check key; add its display name.",
        )

    def _button_titles(self):
        pattern = re.compile(
            r'<button[^>]*\bdata-scope="(?P<scope>[a-z_]+)"[^>]*\btitle="(?P<title>[^"]*)"'
        )
        matches = pattern.findall(self.html)
        self.assertTrue(matches, "No scope buttons with a title attribute were found in index.html")
        return dict(matches)

    def test_every_scope_button_names_every_check_it_runs(self):
        titles = self._button_titles()
        self.assertEqual(set(titles), set(SCOPE_CHECKS), "Scope buttons in index.html do not match SCOPE_CHECKS keys")

        for scope, check_set in SCOPE_CHECKS.items():
            expected_checks = ALL_CHECK_KEYS if check_set is None else check_set
            title = titles[scope]
            for check_key in expected_checks:
                display_name = CHECK_DISPLAY_NAMES[check_key]
                self.assertIn(
                    display_name.lower(), title.lower(),
                    f'Scope "{scope}" runs "{check_key}" but its title does not mention '
                    f'"{display_name}": {title!r}',
                )



class TestHomepageMetadataMatchesScopeChecks(unittest.TestCase):
    """Doc 29, item 6, and its "done when" clause.

    The meta description, og:description, twitter:description and the
    JSON-LD WebApplication description are four copies of one sentence, and
    they had drifted: three said nine checks with no DANE, the fourth had no
    MX, and the FAQ on the same page said "9 protocols" for a tool that runs
    twelve. Hold all of them to each other and to the check list.
    """

    def setUp(self):
        with open(INDEX_HTML, encoding="utf-8") as f:
            self.html = f.read()

    def _metadata_strings(self):
        html = self.html
        return {
            "meta description": re.search(
                r'<meta name="description" content="([^"]+)"', html).group(1),
            "og:description": re.search(
                r'<meta property="og:description" content="([^"]+)"', html).group(1),
            "twitter:description": re.search(
                r'<meta name="twitter:description" content="([^"]+)"', html).group(1),
            "JSON-LD WebApplication description": re.search(
                r'"@type": "WebApplication".*?"description": "([^"]+)"', html, re.S).group(1),
        }

    def _missing(self, text):
        return sorted(
            CHECK_DISPLAY_NAMES[k] for k in ALL_CHECK_KEYS
            if CHECK_DISPLAY_NAMES[k].lower() not in text.lower()
        )

    def test_there_are_twelve_checks(self):
        """The FAQ and the description both say twelve. Hold them to it."""
        self.assertEqual(len(ALL_CHECK_KEYS), 12)

    def test_the_four_description_strings_are_identical(self):
        strings = self._metadata_strings()
        self.assertEqual(len(set(strings.values())), 1, strings)

    def test_every_description_names_every_check(self):
        for where, text in self._metadata_strings().items():
            self.assertEqual(
                self._missing(text), [],
                f"{where} never mentions those checks: {text!r}",
            )

    def test_faq_answer_names_every_check_and_the_right_count(self):
        answer = re.search(
            r'"name": "What does this DNS security audit check\?".*?"text": "([^"]+)"',
            self.html, re.S,
        ).group(1)
        self.assertIn(f"{len(ALL_CHECK_KEYS)} checks", answer)
        self.assertEqual(self._missing(answer), [], f"FAQ answer: {answer!r}")
if __name__ == "__main__":
    unittest.main()
