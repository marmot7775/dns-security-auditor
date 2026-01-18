from dns_security_auditor.dns_tools import normalize_domain

def test_normalize_domain_basic():
    assert normalize_domain("EXAMPLE.com") == "example.com"
    assert normalize_domain("https://www.example.com/path") == "example.com"
    assert normalize_domain("http://example.com:8080") == "example.com"
    assert normalize_domain("example.com.") == "example.com"
