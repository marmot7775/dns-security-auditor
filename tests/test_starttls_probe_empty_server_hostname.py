"""Regression test for the STARTTLS probe raising on every healthy server.

Bug: mx_check._check_starttls built its SMTP client with
smtplib.SMTP(timeout=timeout) and then called server.connect(hostname,
port) separately. smtplib.SMTP.__init__ only sets self._host from its
own `host` constructor argument, which was empty here; the later
.connect() call never updates it. server.starttls() passes
server_hostname=self._host to ssl.SSLContext.wrap_socket, so every
STARTTLS attempt raised "server_hostname cannot be an empty string or
start with a leading dot" -- even against a server that completes
STARTTLS correctly.

This is only observable against a server that actually completes
STARTTLS, so this test stands up a real local STARTTLS SMTP server
with a self-signed cert rather than mocking smtplib.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _starttls_test_server import LocalStarttlsServer, generate_self_signed_cert

import mx_check


def test_starttls_succeeds_against_a_real_server():
    key_pem, cert_pem = generate_self_signed_cert()
    with LocalStarttlsServer(cert_pem, key_pem) as srv:
        result = mx_check._check_starttls("127.0.0.1", port=srv.port, timeout=5)

    assert result["error"] is None, (
        f"STARTTLS against a server that completes the handshake must not "
        f"error; got: {result['error']!r}"
    )
    assert result["supports_starttls"] is True
    assert result["tls_version"] is not None and result["tls_version"].startswith("TLSv1")
