import ipaddress
from pathlib import Path

from cryptography import x509

from scripts.generate_lab_certs import generate_lab_certs


def test_generate_lab_certs_creates_valid_ca_and_server_san(tmp_path):
    out_dir = tmp_path / "certs"
    result = generate_lab_certs(
        out_dir,
        extra_ips=["192.168.1.10"],
        extra_dns=["ogk.local"],
    )

    for key in ("ca_key", "ca_cert", "server_key", "server_cert"):
        assert Path(result[key]).exists()
    assert len(result["server_sha256"]) == 64

    server_cert = x509.load_pem_x509_certificate(Path(result["server_cert"]).read_bytes())
    ca_cert = x509.load_pem_x509_certificate(Path(result["ca_cert"]).read_bytes())

    assert server_cert.issuer == ca_cert.subject
    san = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = set(san.get_values_for_type(x509.DNSName))
    ips = set(san.get_values_for_type(x509.IPAddress))
    assert {"localhost", "ogk.local"}.issubset(dns_names)
    assert {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("192.168.1.10")}.issubset(ips)
