"""A "there is no such record" answer must not outlive the result cache.

Prompt 04 added a shared DNS cache and it was the right call. What it missed
is that dnspython caches negative answers too, and nothing bounded them.

dnspython caches NODATA under (qname, rdtype, rdclass) and NXDOMAIN under
(qname, ANY, rdclass). Answer.expiration is time.time() plus
chaining_result.minimum_ttl, which for a negative answer comes from the SOA
minimum in the authority section. Measured on dnspython 2.8.0:

    NXDOMAIN with SOA (minimum 86400)   900 s
    NODATA with SOA                     900 s
    NXDOMAIN with no SOA                4,294,967,295 s (136 years)

The result cache in server.py is 5 minutes, and it is 5 minutes on purpose:
a re-audit is supposed to show a change. A 15 minute negative entry sitting
underneath it breaks the workflow the tool exists for. An operator audits,
is told "No DMARC policy published", publishes the record, waits out the
result cache, re-runs, and is told the same thing again. The no-SOA case
pins the entry for the life of the process, bounded only by LRU eviction,
and it is reachable through any stub forwarder that drops the authority
section.

The suite patches dns.resolver.Resolver.resolve, so _PLAIN_CACHE is never
exercised by the audit tests at all. These go at the cache directly.
"""
import os
import sys
import time

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns_tools

QNAME = "_dmarc.example.com."
SOA = "example.com. 900 IN SOA ns.example.com. h.example.com. 1 7200 3600 1209600 86400"


def _answer(body, rdtype=dns.rdatatype.TXT, qname=QNAME):
    """Build a real dns.resolver.Answer from a wire-format message."""
    question = dns.message.make_query(qname, rdtype)
    response = dns.message.from_text(body)
    response.question = question.question
    response.id = question.id
    return dns.resolver.Answer(
        dns.name.from_text(qname), rdtype, dns.rdataclass.IN, response
    )


def nxdomain_with_soa():
    return _answer(
        f"id 0\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA\n;AUTHORITY\n{SOA}\n",
        rdtype=dns.rdatatype.ANY,
    )


def nodata_with_soa():
    return _answer(f"id 0\nopcode QUERY\nrcode NOERROR\nflags QR AA\n;AUTHORITY\n{SOA}\n")


def nxdomain_without_soa():
    """What a stub forwarder that strips the authority section produces."""
    return _answer("id 0\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA\n",
                   rdtype=dns.rdatatype.ANY)


def positive():
    return _answer(
        'id 0\nopcode QUERY\nrcode NOERROR\nflags QR AA\n;ANSWER\n'
        '_dmarc.example.com. 3600 IN TXT "v=DMARC1; p=reject"\n'
    )


NEGATIVES = {
    "NXDOMAIN with SOA": nxdomain_with_soa,
    "NODATA with SOA": nodata_with_soa,
    "NXDOMAIN with no SOA": nxdomain_without_soa,
}


@pytest.mark.parametrize("label", sorted(NEGATIVES))
def test_negative_answers_are_capped(label):
    answer = NEGATIVES[label]()
    uncapped = answer.expiration - time.time()

    cache = dns_tools.BoundedNegativeCache(max_size=10)
    cache.put((dns.name.from_text(QNAME), answer.rdtype, dns.rdataclass.IN), answer)

    held = answer.expiration - time.time()
    assert held <= dns_tools.NEGATIVE_TTL_CAP + 1, (
        f"{label}: cached for {held:,.0f} s, cap is "
        f"{dns_tools.NEGATIVE_TTL_CAP:,.0f} s (uncached value was {uncapped:,.0f} s)"
    )


def test_the_cap_is_shorter_than_the_result_cache():
    """The point of the cap. A 5 minute result cache with a longer negative
    entry underneath it means a re-audit cannot show a record that was just
    published, which is the one thing a re-audit is for."""
    assert dns_tools.NEGATIVE_TTL_CAP < 300, (
        f"negative entries live {dns_tools.NEGATIVE_TTL_CAP} s, at or beyond the "
        "5 minute result cache in server.py"
    )


def test_a_negative_answer_expires_out_of_the_cache():
    """Capping expiration is only useful if get() honors it."""
    answer = nxdomain_without_soa()
    cache = dns_tools.BoundedNegativeCache(max_size=10)
    key = (dns.name.from_text(QNAME), answer.rdtype, dns.rdataclass.IN)
    cache.put(key, answer)

    assert cache.get(key) is not None, "a fresh negative answer should be readable"
    answer.expiration = time.time() - 1
    assert cache.get(key) is None, (
        "an expired negative answer was still served from the cache"
    )


def test_positive_answers_keep_their_own_ttl():
    """The negatives carry the staleness risk. The positives are where the
    saving of about 35 duplicate queries per audit came from, and clamping
    them would give that back."""
    answer = positive()
    ttl = answer.expiration - time.time()
    assert ttl > dns_tools.NEGATIVE_TTL_CAP, "fixture is not exercising the cap"

    cache = dns_tools.BoundedNegativeCache(max_size=10)
    cache.put((dns.name.from_text(QNAME), answer.rdtype, dns.rdataclass.IN), answer)

    assert answer.expiration - time.time() == pytest.approx(ttl, abs=1), (
        "a positive answer had its TTL shortened by the negative cap"
    )


def test_the_shared_caches_are_the_bounded_kind():
    """The subclass only helps if the resolvers actually use it."""
    assert isinstance(dns_tools._PLAIN_CACHE, dns_tools.BoundedNegativeCache)
    assert isinstance(dns_tools._DNSSEC_CACHE, dns_tools.BoundedNegativeCache)
    assert dns_tools.get_resolver().cache is dns_tools._PLAIN_CACHE
    assert dns_tools.get_dnssec_resolver().cache is dns_tools._DNSSEC_CACHE


def test_selector_probes_do_not_touch_the_shared_cache():
    """~193 unique NXDOMAIN probes per audit against a 2000 entry cache
    evicted the repeated lookups the cache exists for."""
    assert dns_tools.get_uncached_resolver().cache is None
