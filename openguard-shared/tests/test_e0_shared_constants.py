from shared.network_constants import (
    ALL_COMPONENTS,
    DNS_PROXY_PORT,
    HTTPS_API_PORT,
    IPC_PORT,
)


def test_network_constants_consistent():
    assert HTTPS_API_PORT == 8443
    assert DNS_PROXY_PORT == 53
    assert IPC_PORT == 17321
    assert len(ALL_COMPONENTS) == 4
