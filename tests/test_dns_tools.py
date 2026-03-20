import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dns_tools import normalize_domain


def test_normalize_domain_basic():
    assert normalize_domain("EXAMPLE.com") == "example.com"
    assert normalize_domain("https://www.example.com/path") == "example.com"
    assert normalize_domain("user@example.com") == "example.com"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("") == ""


def test_normalize_domain_protocols():
    assert normalize_domain("http://example.com") == "example.com"
    assert normalize_domain("https://example.com") == "example.com"


def test_normalize_domain_with_query():
    assert normalize_domain("example.com/page?q=1") == "example.com"
