from shared.network_constants import ALL_COMPONENTS, DNS_PROXY_PORT, HTTPS_API_PORT, IPC_PORT


def test_labs_can_read_shared_network_constants():
    ports = {c.port for c in ALL_COMPONENTS}
    assert {HTTPS_API_PORT, DNS_PROXY_PORT, IPC_PORT}.issubset(ports)
