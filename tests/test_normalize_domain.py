import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dns_tools import normalize_domain


def test_normalize_domain_basic():
    assert normalize_domain("EXAMPLE.com") == "example.com"
    assert normalize_domain("https://www.example.com/path") == "www.example.com"
    assert normalize_domain("example.com.") == "example.com"


def test_normalize_domain_idn_multilabel():
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"
    assert normalize_domain("BÜCHER.de") == "xn--bcher-kva.de"


def test_normalize_domain_ascii_passthrough():
    assert normalize_domain("example.com") == "example.com"


def test_normalize_domain_empty():
    assert normalize_domain("") == ""


def test_normalize_domain_invalid_no_exception():
    # Best-effort: invalid IDN passes through (lowercased) for downstream validation.
    assert normalize_domain("not a domain") == "not a domain"
