"""Shared fake-DNS harness for end-to-end audit tests.

Most of this suite tests the code the bugs were in rather than the output
users see: a test builds its own raw dict and hands it to one transformer,
so it cannot catch a producer/consumer key mismatch. The test author writes
the key the transformer expects, and the mismatch with the real producer
goes unnoticed. That is the seam the ledger's bugs lived in.

tests/test_dmarc_report_auth_ordering.py argued the case for one bug and
built the fix: patch dns.resolver.Resolver.resolve and the module-level
dns.resolver.resolve, which between them cover every lookup every module
makes, then drive a real run_full_audit and assert on the transformed card.
This module generalizes that so any test can declare a zone and get a real
audit out of it.

Everything is offline by design. `no_network` is applied to every test in
this directory automatically and fails loudly on a real socket, so a check
that quietly reaches the internet shows up as a test error rather than as a
slow run and a flaky result.
"""
import ipaddress
import os
import socket
import sys
from contextlib import contextmanager
from unittest.mock import patch

import dns.flags
import dns.rdatatype
import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ------------------------------------------------------------------
# Fake rdata, one shape per record type
# ------------------------------------------------------------------

class _Name(str):
    """A dnspython-ish name: str(name) keeps the trailing dot."""

    def __new__(cls, text):
        return super().__new__(cls, text.rstrip(".") + ".")

    @property
    def target(self):
        return self


class _TxtRdata:
    def __init__(self, text):
        # Real TXT rdata is a list of <=255-byte strings. Records longer than
        # that arrive split, and code that joins them wrongly is a bug worth
        # catching, so the split is reproduced here rather than smoothed over.
        self.strings = [
            text[i:i + 255].encode("utf-8") for i in range(0, len(text), 255)
        ] or [b""]

    def __str__(self):
        return " ".join('"%s"' % s.decode("utf-8") for s in self.strings)


class _MxRdata:
    def __init__(self, value):
        preference, exchange = value
        self.preference = int(preference)
        self.exchange = _Name(exchange)

    def __str__(self):
        return f"{self.preference} {self.exchange}"


class _AddressRdata:
    def __init__(self, value):
        self.address = value

    def __str__(self):
        return self.address


class _TargetRdata:
    def __init__(self, value):
        self.target = _Name(value)

    def __str__(self):
        return str(self.target)


class _CaaRdata:
    def __init__(self, value):
        flags, tag, val = value
        self.flags = int(flags)
        self.tag = tag.encode("utf-8") if isinstance(tag, str) else tag
        self.value = val.encode("utf-8") if isinstance(val, str) else val

    def __str__(self):
        return '%d %s "%s"' % (
            self.flags, self.tag.decode("utf-8"), self.value.decode("utf-8")
        )


_RDATA_BY_TYPE = {
    "TXT": _TxtRdata,
    "SPF": _TxtRdata,
    "MX": _MxRdata,
    "A": _AddressRdata,
    "AAAA": _AddressRdata,
    "NS": _TargetRdata,
    "CNAME": _TargetRdata,
    "PTR": _TargetRdata,
    "CAA": _CaaRdata,
}


class _FakeRRset(list):
    def __init__(self, rdatas, ttl):
        super().__init__(rdatas)
        self.ttl = ttl


class _FakeResponse:
    def __init__(self, ad_flag):
        self.flags = dns.flags.AD if ad_flag else 0
        self.answer = []


class FakeAnswer(list):
    """Mimics dnspython's Answer: iterable of rdata, plus rrset and response."""

    def __init__(self, rdatas, ttl=300, ad_flag=False):
        super().__init__(rdatas)
        self.rrset = _FakeRRset(rdatas, ttl)
        self.response = _FakeResponse(ad_flag)
        self.ttl = ttl


# ------------------------------------------------------------------
# Zone
# ------------------------------------------------------------------

class FakeZone:
    """A DNS zone declared as {qname: {rtype: [values]}}.

    Names are matched case-insensitively with the trailing dot stripped, the
    way a resolver would. Anything not declared is NXDOMAIN, which is what
    makes a fixture readable: only what the zone actually publishes appears.
    """

    def __init__(self, records=None, ad_flag=False, ttl=300):
        self.ad_flag = ad_flag
        self.ttl = ttl
        self.queries = []
        self._records = {}
        for name, by_type in (records or {}).items():
            for rtype, values in by_type.items():
                self.add(name, rtype, values)

    @staticmethod
    def _key(name, rtype):
        return str(name).rstrip(".").lower(), str(rtype).upper()

    def add(self, name, rtype, values):
        if not isinstance(values, (list, tuple)) or (
            rtype.upper() in ("MX", "CAA") and values and not isinstance(values[0], (list, tuple))
        ):
            values = [values]
        self._records[self._key(name, rtype)] = list(values)
        return self

    def resolve(self, name, rdtype="A", *args, **kwargs):
        key = self._key(name, rdtype)
        self.queries.append(key)
        values = self._records.get(key)
        if values is None:
            raise dns.resolver.NXDOMAIN()
        factory = _RDATA_BY_TYPE.get(key[1])
        if factory is None:
            # A type this harness does not model. NXDOMAIN keeps the check on
            # its "not configured" path instead of raising an AttributeError
            # deep inside a transformer.
            raise dns.resolver.NXDOMAIN()
        return FakeAnswer(
            [factory(v) for v in values], ttl=self.ttl, ad_flag=self.ad_flag
        )


# ------------------------------------------------------------------
# Patching
# ------------------------------------------------------------------

class FakeHttpResponse:
    """Enough of a requests.Response for the two checks that fetch over HTTP."""

    def __init__(self, body="", status_code=200, content_type="text/plain", json_data=None):
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}
        self.text = body
        self.content = body.encode("utf-8")
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _blocked_http(*args, **kwargs):
    # requests.RequestException, not OSError. The checks catch the former and
    # degrade to their "could not reach the service" path, which is what
    # production sees when crt.sh is down. Raising a bare OSError escapes
    # that handling and lands in run_full_audit's generic error path instead,
    # so the test would exercise a state production never reaches.
    import requests
    raise requests.exceptions.ConnectionError("network disabled in tests")


@contextmanager
def fake_dns(zone, mta_sts_policy=None, ct_certs=None, bimi_logo=None):
    """Patch every DNS and HTTP entry point the audit reaches.

    Both resolver entry points are patched because the modules use both:
    dns.resolver.resolve at module level and Resolver().resolve on an
    instance. Patching one and not the other leaves half the lookups live.

    Two checks also speak HTTP. MTA-STS fetches its policy file and CT
    queries crt.sh, so a fixture that wants either to succeed passes the body
    in. Left unset they raise, which is what those checks see when the remote
    side is unreachable, and is the honest default for an offline suite.

    MTA-STS is stubbed at checks_extra._safe_fetch rather than at the socket:
    the SSRF pinning below that seam has its own tests, and reproducing it
    here would test the harness instead of the policy parser.
    """
    def _method(self, name, rdtype="A", *args, **kwargs):
        return zone.resolve(name, rdtype, *args, **kwargs)

    def _fetch(url, *args, **kwargs):
        # Both MTA-STS and BIMI fetch through _safe_fetch, so this has to
        # dispatch on the URL. Serving one to the other is silent: the BIMI
        # logo validator just reports that the SVG will not parse.
        target = str(url)
        if "mta-sts" in target or target.endswith("mta-sts.txt"):
            if mta_sts_policy is None:
                _blocked_http()
            return FakeHttpResponse(mta_sts_policy)
        if bimi_logo is not None:
            return FakeHttpResponse(bimi_logo, content_type="image/svg+xml")
        return _blocked_http()

    def _requests_get(url, *args, **kwargs):
        target = str(url)
        if "crt.sh" in target:
            if ct_certs is None:
                _blocked_http()
            import json as _json
            return FakeHttpResponse(
                _json.dumps(ct_certs), content_type="application/json",
                json_data=ct_certs,
            )
        if bimi_logo is not None:
            return FakeHttpResponse(bimi_logo, content_type="image/svg+xml")
        return _blocked_http()

    with patch("dns.resolver.Resolver.resolve", _method), \
         patch("dns.resolver.resolve", zone.resolve), \
         patch("checks_extra._safe_fetch", _fetch), \
         patch("requests.get", _requests_get), \
         patch("requests.post", _blocked_http), \
         patch("requests.Session.request", _blocked_http), \
         patch("socket.getaddrinfo", _blocked_http):
        yield zone


@pytest.fixture
def audit():
    """Run a real run_full_audit against a declared zone.

    Returns the full result dict, so assertions land on result["checks"],
    the cards the frontend and the PDF actually render.
    """
    import audit_engine

    def _run(zone, domain, scope="complete", mta_sts_policy=None, ct_certs=None,
             bimi_logo=None,
             **kwargs):
        if isinstance(zone, dict):
            zone = FakeZone(zone)
        with fake_dns(zone, mta_sts_policy=mta_sts_policy, ct_certs=ct_certs,
                      bimi_logo=bimi_logo):
            return audit_engine.run_full_audit(domain, scope=scope, **kwargs)

    return _run


def _is_loopback(address):
    try:
        host = address[0] if isinstance(address, (tuple, list)) else address
        return ipaddress.ip_address(str(host)).is_loopback
    except (ValueError, IndexError, TypeError):
        return False


@pytest.fixture(autouse=True)
def no_network(request):
    """Fail any test in this directory that reaches off this machine.

    Loopback stays open: several tests stand up a local STARTTLS or HTTP
    server on 127.0.0.1 on purpose, and that is not the hazard. Egress is.
    A check that quietly queries a real resolver or crt.sh should surface as
    a test error, not as a slow run and a result that changes with the
    weather. Opt out entirely with @pytest.mark.allow_network.
    """
    if request.node.get_closest_marker("allow_network"):
        yield
        return

    real_socket = socket.socket

    class _GuardedSocket(real_socket):
        def connect(self, address):
            if not _is_loopback(address):
                raise AssertionError(
                    f"test opened a network connection to {address!r}; "
                    f"declare it in the zone or mark the test allow_network"
                )
            return super().connect(address)

        def connect_ex(self, address):
            if not _is_loopback(address):
                raise AssertionError(
                    f"test opened a network connection to {address!r}; "
                    f"declare it in the zone or mark the test allow_network"
                )
            return super().connect_ex(address)

    with patch.object(socket, "socket", _GuardedSocket):
        yield


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "allow_network: test binds or connects a real socket on purpose"
    )
