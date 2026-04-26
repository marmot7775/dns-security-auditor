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


def _multi_getaddrinfo(*ip_strs):
    def _fake(*args, **kwargs):
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                (ip, 443),
            )
            for ip in ip_strs
        ]
    return _fake


def test_public_then_private_is_rejected():
    """Multi-record DNS where the first IP is public but a later one is
    private must be rejected: _safe_fetch only pins one address, but a
    contract violation here is one refactor away from real SSRF."""
    fake = _multi_getaddrinfo("8.8.8.8", "10.0.0.1")
    with patch("checks_extra.socket.getaddrinfo", side_effect=fake):
        with pytest.raises(ValueError, match="not a public address"):
            _resolve_and_validate("example.test")


def test_private_then_public_is_rejected():
    fake = _multi_getaddrinfo("10.0.0.1", "8.8.8.8")
    with patch("checks_extra.socket.getaddrinfo", side_effect=fake):
        with pytest.raises(ValueError, match="not a public address"):
            _resolve_and_validate("example.test")


def test_all_public_ips_returns_first():
    fake = _multi_getaddrinfo("8.8.8.8", "1.1.1.1")
    with patch("checks_extra.socket.getaddrinfo", side_effect=fake):
        assert _resolve_and_validate("example.test") == "8.8.8.8"
