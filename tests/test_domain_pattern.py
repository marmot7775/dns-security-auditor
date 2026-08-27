import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import DOMAIN_PATTERN
from dns_tools import normalize_domain


def test_pattern_accepts_punycode_tld():
    # .рф -> xn--p1ai
    assert DOMAIN_PATTERN.match("xn--d1abbgf6aiiy.xn--p1ai")
    # .テスト -> xn--zckzah
    assert DOMAIN_PATTERN.match("xn--r8jz45g.xn--zckzah")


def test_pattern_accepts_normalized_idn_inputs():
    assert DOMAIN_PATTERN.match(normalize_domain("президент.рф"))
    assert DOMAIN_PATTERN.match(normalize_domain("例え.テスト"))


def test_pattern_accepts_ascii():
    assert DOMAIN_PATTERN.match("example.com")
    assert DOMAIN_PATTERN.match("EXAMPLE.COM")
    assert DOMAIN_PATTERN.match("sub.example.co.uk")


def test_pattern_rejects_all_digit_tld():
    # TLDs starting with a digit are rejected by the tighter pattern
    assert not DOMAIN_PATTERN.match("example.123")


def test_pattern_rejects_short_or_empty_tld():
    assert not DOMAIN_PATTERN.match("example.c")
    assert not DOMAIN_PATTERN.match("example.")
    assert not DOMAIN_PATTERN.match("example")


def test_pattern_rejects_trailing_hyphen_tld():
    # The TLD label lacked the (?<!-) guard the other labels have.
    assert not DOMAIN_PATTERN.match("example.co-")
    assert not DOMAIN_PATTERN.match("foo.bar-")
    # Leading-hyphen rejection (already worked) must still hold.
    assert not DOMAIN_PATTERN.match("-example.com")
