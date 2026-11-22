import hashlib
import socket
import ssl

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from agent.core.logger import get_logger

logger = get_logger("cert_pinning")


def compute_cert_fingerprint(cert_der: bytes) -> str:
    """Tính SHA-256 hex fingerprint (lowercase) từ DER certificate."""
    return hashlib.sha256(cert_der).hexdigest().lower()


def load_expected_fingerprint(pem_path: str) -> str:
    """Đọc PEM certificate và trích xuất SHA-256 fingerprint."""
    with open(pem_path, "r", encoding="utf-8") as f:
        pem_text = f.read()
    cert_der = ssl.PEM_cert_to_DER_cert(pem_text)
    return compute_cert_fingerprint(cert_der)


def create_pinned_ssl_context(ca_cert_path: str | None = None) -> ssl.SSLContext:
    """Tạo SSLContext ép buộc tối thiểu TLS 1.2+ (F5)."""
    ctx = (
        ssl.create_default_context(cafile=ca_cert_path)
        if ca_cert_path
        else ssl.create_default_context()
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def verify_server_certificate(
    host: str,
    port: int,
    expected_fingerprint: str,
    ca_cert_path: str | None = None,
) -> bool:
    """Kiểm tra trực tiếp fingerprint của server cert qua socket TLS 1.2+."""
    ctx = create_pinned_ssl_context(ca_cert_path)
    with socket.create_connection((host, port), timeout=5.0) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if not cert_der:
                return False
            live_fp = compute_cert_fingerprint(cert_der)
    if live_fp != expected_fingerprint.lower():
        logger.error(
            "CẢNH BÁO MITM: Fingerprint cert server (%s) != pinned (%s)",
            live_fp,
            expected_fingerprint,
        )
        return False
    return True


class PinnedHTTPSAdapter(HTTPAdapter):
    """HTTPAdapter ép TLS 1.2+ và ghim SHA-256 fingerprint trên mỗi kết nối."""

    def __init__(self, expected_fingerprint: str, ca_cert_path: str | None = None, **kwargs):
        self.expected_fingerprint = expected_fingerprint.lower()
        self.ca_cert_path = ca_cert_path
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = create_pinned_ssl_context(self.ca_cert_path)
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx,
            assert_fingerprint=self.expected_fingerprint,
            **pool_kwargs,
        )


def build_pinned_session(
    pinned_cert_path: str | None = None,
    ca_cert_path: str | None = None,
    expected_fingerprint: str | None = None,
) -> requests.Session:
    """Tạo requests.Session có TLS 1.2+ và Certificate Pinning."""
    session = requests.Session()
    if ca_cert_path:
        session.verify = ca_cert_path
    fp = expected_fingerprint
    if not fp and pinned_cert_path:
        fp = load_expected_fingerprint(pinned_cert_path)
    if fp:
        session.mount("https://", PinnedHTTPSAdapter(fp, ca_cert_path=ca_cert_path))
    return session
