import base64
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.core import config as agent_config
from agent.core import sync_client
from agent.core.policy_enforcer import PolicyEnforcer, canonical_json


def _make_keys() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem.decode("ascii")


def _sign(content: dict, priv: Ed25519PrivateKey) -> str:
    return base64.b64encode(priv.sign(canonical_json(content).encode("utf-8"))).decode("ascii")


def test_heartbeat_syncs_new_signed_policy_and_skips_when_up_to_date(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    priv, pub_pem = _make_keys()
    agent_config.save_config(
        {
            "device_id": "dev-030",
            "child_id": "child-030",
            "access_token": "jwt-030",
            "refresh_token": "ref-030",
            "policy_public_key_pem": pub_pem,
            "enrolled": True,
        }
    )

    enforcer = PolicyEnforcer("dev-030", public_key_pem=pub_pem)
    policy_v2 = {"quota_weekday_min": 75, "quota_weekend_min": 120}

    hb_resp_mismatch = MagicMock(status_code=200)
    hb_resp_mismatch.json.return_value = {
        "server_policy_version": 2,
        "policy_update_available": True,
        "server_utc": "2026-11-22T14:10:00+00:00",
        "pending_commands": [],
    }
    hb_resp_match = MagicMock(status_code=200)
    hb_resp_match.json.return_value = {
        "server_policy_version": 2,
        "policy_update_available": False,
        "server_utc": "2026-11-22T14:11:00+00:00",
        "pending_commands": [],
    }
    get_policy_resp = MagicMock(status_code=200)
    get_policy_resp.json.return_value = {
        "policy_id": "pol-v2",
        "device_id": "dev-030",
        "version": 2,
        "content": policy_v2,
        "signature": _sign(policy_v2, priv),
        "created_at": "2026-11-22T14:09:50+00:00",
    }

    mock_session = MagicMock()
    mock_session.post.side_effect = [hb_resp_mismatch, hb_resp_match]
    mock_session.get.return_value = get_policy_resp

    applied_callbacks = []
    worker = sync_client.HeartbeatWorker(
        "https://127.0.0.1:8443",
        state_provider=lambda: {
            "policy_version": enforcer.get_current_version(),
            "quota_used_min": 10,
            "is_locked": False,
        },
        session=mock_session,
        policy_enforcer=enforcer,
        on_policy_updated=lambda content: applied_callbacks.append(content),
    )

    # Tick 1: mismatch -> fetches GET /policy/dev-030, verifies Ed25519, applies v2
    worker.tick_once()
    assert enforcer.get_current_version() == 2
    assert enforcer.get_content()["quota_weekday_min"] == 75
    assert len(applied_callbacks) == 1
    assert mock_session.get.call_count == 1

    # Tick 2: versions match -> does not call GET /policy again
    worker.tick_once()
    assert mock_session.get.call_count == 1


def test_fetch_and_apply_rejects_tampered_server_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    priv, pub_pem = _make_keys()
    agent_config.save_config(
        {
            "device_id": "dev-030",
            "access_token": "jwt-030",
            "policy_public_key_pem": pub_pem,
            "enrolled": True,
        }
    )

    enforcer = PolicyEnforcer("dev-030", public_key_pem=pub_pem)
    valid_v1 = {"quota_weekday_min": 60}
    assert enforcer.apply_new_policy(1, valid_v1, _sign(valid_v1, priv), policy_id="pol-1")

    tampered_resp = MagicMock(status_code=200)
    tampered_resp.json.return_value = {
        "policy_id": "pol-2",
        "device_id": "dev-030",
        "version": 2,
        "content": {"quota_weekday_min": 999},
        "signature": _sign(valid_v1, priv),  # wrong signature for tampered content
    }
    mock_session = MagicMock()
    mock_session.get.return_value = tampered_resp

    applied = sync_client.fetch_and_apply_latest_policy(
        "https://127.0.0.1:8443",
        enforcer,
        session=mock_session,
    )
    assert applied is False
    assert enforcer.get_current_version() == 1
    assert enforcer.get_content()["quota_weekday_min"] == 60
