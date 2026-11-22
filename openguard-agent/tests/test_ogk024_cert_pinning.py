import ipaddress
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent.core import cert_pinning


def _write_self_signed_cert(cert_path: Path, key_path: Path, cn: str) -> None:
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):  # noqa: A002
        pass


def _start_tls_server(cert_path: Path, key_path: Path):
    httpd = HTTPServer(("127.0.0.1", 0), _HealthHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


def test_create_pinned_ssl_context_enforces_tls_1_2():
    ctx = cert_pinning.create_pinned_ssl_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_pinned_https_adapter_accepts_valid_and_rejects_mitm_cert(tmp_path):
    cert_a = tmp_path / "server_a.crt"
    key_a = tmp_path / "server_a.key"
    cert_b = tmp_path / "server_b.crt"
    key_b = tmp_path / "server_b.key"
    _write_self_signed_cert(cert_a, key_a, "server-a")
    _write_self_signed_cert(cert_b, key_b, "server-b-mitm")

    fp_a = cert_pinning.load_expected_fingerprint(str(cert_a))

    # 1) Legitimate server with cert_a -> pinned session succeeds
    httpd_a, _ = _start_tls_server(cert_a, key_a)
    try:
        port_a = httpd_a.server_address[1]
        assert cert_pinning.verify_server_certificate("127.0.0.1", port_a, fp_a, str(cert_a))
        session = cert_pinning.build_pinned_session(
            pinned_cert_path=str(cert_a),
            ca_cert_path=str(cert_a),
        )
        res = session.get(f"https://127.0.0.1:{port_a}/health", timeout=5)
        assert res.status_code == 200
        assert res.json() == {"status": "ok"}
    finally:
        httpd_a.shutdown()
        httpd_a.server_close()

    # 2) Rogue MITM server presenting cert_b -> rejected even if CA trusts cert_b
    httpd_b, _ = _start_tls_server(cert_b, key_b)
    try:
        port_b = httpd_b.server_address[1]
        assert not cert_pinning.verify_server_certificate("127.0.0.1", port_b, fp_a, str(cert_b))

        mitm_session = cert_pinning.build_pinned_session(
            pinned_cert_path=str(cert_a),
            ca_cert_path=str(cert_b),
        )
        with pytest.raises(requests.exceptions.SSLError):
            mitm_session.get(f"https://127.0.0.1:{port_b}/health", timeout=5)
    finally:
        httpd_b.shutdown()
        httpd_b.server_close()
