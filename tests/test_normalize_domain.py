import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dns_tools import normalize_domain


def test_normalize_domain_basic():
    assert normalize_domain("EXAMPLE.com") == "example.com"
    assert normalize_domain("https://www.example.com/path") == "example.com"
    assert normalize_domain("example.com.") == "example.com"
