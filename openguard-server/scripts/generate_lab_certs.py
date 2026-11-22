"""Sinh Root CA và Server Certificate TLS 1.2+ cho môi trường Lab (OGK-024)."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def generate_lab_certs(
    out_dir: Path,
    extra_ips: list[str] | None = None,
    extra_dns: list[str] | None = None,
    validity_days: int = 365,
) -> dict[str, str]:
    """Sinh ca.key/ca.crt và server.key/server.crt có SAN localhost + 127.0.0.1."""
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenGuard Kids Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "OpenGuard Kids Lab Root CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days * 3))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenGuard Kids Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "openguard-server.local"),
        ]
    )

    san_entries: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.DNSName("openguard-server.local"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    for dns_name in extra_dns or []:
        san_entries.append(x509.DNSName(dns_name))
    for ip_str in extra_ips or []:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path = out_dir / "ca.key"
    ca_cert_path = out_dir / "ca.crt"
    server_key_path = out_dir / "server.key"
    server_cert_path = out_dir / "server.crt"

    _write_key(ca_key_path, ca_key)
    _write_cert(ca_cert_path, ca_cert)
    _write_key(server_key_path, server_key)
    _write_cert(server_cert_path, server_cert)

    fingerprint = hashlib.sha256(server_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return {
        "ca_key": str(ca_key_path),
        "ca_cert": str(ca_cert_path),
        "server_key": str(server_key_path),
        "server_cert": str(server_cert_path),
        "server_sha256": fingerprint,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Sinh TLS certs cho môi trường Lab OpenGuard Kids")
    parser.add_argument(
        "--out-dir",
        default=str(Path(__file__).resolve().parents[1] / "certs"),
        help="Thư mục lưu ca.crt/server.crt",
    )
    parser.add_argument("--ip", action="append", default=[], help="Thêm IP SAN (vd 192.168.1.10)")
    parser.add_argument("--dns", action="append", default=[], help="Thêm DNS SAN")
    args = parser.parse_args()

    result = generate_lab_certs(Path(args.out_dir), extra_ips=args.ip, extra_dns=args.dns)
    print(f"[OGK-024] Đã sinh TLS certs tại {args.out_dir}")
    print(f"Server SHA-256 fingerprint: {result['server_sha256']}")


if __name__ == "__main__":
    main()
