"""Local STARTTLS SMTP server for exercising mx_check._check_starttls
against a real TLS handshake instead of a real MX host.

Not a test module itself (no test_ prefix) -- imported by the STARTTLS
and cert-parsing regression tests.
"""
import datetime
import os
import socket
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(common_name="127.0.0.1", not_before=None, not_after=None):
    """Return (key_pem, cert_pem) bytes for a self-signed leaf cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    if not_before is None:
        not_before = now - datetime.timedelta(days=1)
    if not_after is None:
        not_after = now + datetime.timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _read_line(sock):
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data


class LocalStarttlsServer:
    """A single-connection SMTP server that completes a real STARTTLS
    handshake using a caller-supplied self-signed certificate."""

    def __init__(self, cert_pem, key_pem, host="127.0.0.1"):
        self._cert_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        self._cert_file.write(cert_pem)
        self._cert_file.close()
        self._key_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        self._key_file.write(key_pem)
        self._key_file.close()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(1)
        self.host = host
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve_one, daemon=True)
        self._thread.start()

    def _serve_one(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            conn.sendall(b"220 test.local ESMTP\r\n")
            _read_line(conn)  # EHLO
            conn.sendall(b"250-test.local\r\n250 STARTTLS\r\n")
            _read_line(conn)  # STARTTLS
            conn.sendall(b"220 Ready to start TLS\r\n")

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self._cert_file.name, self._key_file.name)
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            try:
                _read_line(tls_conn)  # EHLO (post-TLS)
                tls_conn.sendall(b"250 test.local\r\n")
                _read_line(tls_conn)  # QUIT
                tls_conn.sendall(b"221 Bye\r\n")
            finally:
                tls_conn.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

    def join(self, timeout=5):
        self._thread.join(timeout)

    def cleanup(self):
        try:
            self._sock.close()
        except Exception:
            pass
        os.unlink(self._cert_file.name)
        os.unlink(self._key_file.name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.join()
        self.cleanup()
