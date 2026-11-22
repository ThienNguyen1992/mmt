from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkComponent:
    name: str
    protocol: str  # "TCP" | "UDP" | "UDP/TCP"
    port: int
    osi_layer: str
    tcpip_layer: str
    note: str


HTTPS_API_PORT = 8443
DNS_PROXY_PORT = 53
IPC_PORT = 17321

COMP_HTTPS_API = NetworkComponent(
    name="Server REST API",
    protocol="TCP",
    port=HTTPS_API_PORT,
    osi_layer="Application (7) / Presentation TLS 1.2+ (6)",
    tcpip_layer="Application",
    note=(
        "FastAPI/Uvicorn over TLS 1.2+ "
        "(/auth, /enroll, /policy, /events, /reports, /audit, /requests)"
    ),
)
COMP_WEBSOCKET = NetworkComponent(
    name="WebSocket lệnh khẩn",
    protocol="TCP",
    port=HTTPS_API_PORT,
    osi_layer="Application (7), nâng cấp HTTP -> RFC 6455",
    tcpip_layer="Application",
    note="wss://.../commands/ws/{device_id}",
)
COMP_DNS_PROXY = NetworkComponent(
    name="DNS Proxy (loopback)",
    protocol="UDP/TCP",
    port=DNS_PROXY_PORT,
    osi_layer="Application (7) trên Transport UDP (tự parse RFC 1035)",
    tcpip_layer="Application",
    note="127.0.0.1:53 (và [::1]:53) — UDP mặc định, TCP fallback khi truncated",
)
COMP_IPC = NetworkComponent(
    name="IPC Tray <-> Service",
    protocol="TCP",
    port=IPC_PORT,
    osi_layer="Application (7) — HTTP loopback có X-IPC-Token",
    tcpip_layer="Application",
    note="127.0.0.1:17321 — chỉ loopback",
)

ALL_COMPONENTS = [COMP_HTTPS_API, COMP_WEBSOCKET, COMP_DNS_PROXY, COMP_IPC]
