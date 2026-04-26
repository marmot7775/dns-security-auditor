"""Tests for SSRF protection in checks_extra._resolve_and_validate."""

from unittest.mock import patch

import pytest
import socket

from checks_extra import _resolve_and_validate


def _fake_getaddrinfo(ip_str):
    family = socket.AF_INET6 if ":" in ip_str else socket.AF_INET
    return lambda *args, **kwargs: [(family, socket.SOCK_STREAM, 0, "", (ip_str, 443))]


BLOCKED_IPS = [
    "10.0.0.1",          # RFC 1918 private
    "127.0.0.1",         # loopback
    "169.254.1.1",       # link-local
    "224.0.0.1",         # multicast
    "240.0.0.1",         # reserved/future
    "100.64.0.1",        # CGNAT (RFC 6598)
    "0.0.0.1",           # "this network"
    "198.18.0.1",        # benchmark testing
    "255.255.255.255",   # limited broadcast
    "192.0.0.1",         # IETF protocol assignments
    "::1",               # IPv6 loopback
    "fe80::1",           # IPv6 link-local
    "fc00::1",           # IPv6 unique local
    "2001:db8::1",       # IPv6 documentation
    "2002::1",           # 6to4
    "::ffff:192.168.1.1",  # IPv4-mapped IPv6 (private)
]

PUBLIC_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "2606:4700:4700::1111",  # Cloudflare DNS v6
]


@pytest.mark.parametrize("ip_str", BLOCKED_IPS)
def test_blocked_ips_are_rejected(ip_str):
    with patch("checks_extra.socket.getaddrinfo", side_effect=_fake_getaddrinfo(ip_str)):
        with pytest.raises(ValueError, match="not a public address"):
            _resolve_and_validate("example.test")


@pytest.mark.parametrize("ip_str", PUBLIC_IPS)
def test_public_ips_are_allowed(ip_str):
    with patch("checks_extra.socket.getaddrinfo", side_effect=_fake_getaddrinfo(ip_str)):
        assert _resolve_and_validate("example.test") == ip_str


def test_dns_failure_raises_value_error():
    with patch("checks_extra.socket.getaddrinfo", side_effect=socket.gaierror("nope")):
        with pytest.raises(ValueError, match="DNS resolution failed"):
            _resolve_and_validate("nonexistent.test")
