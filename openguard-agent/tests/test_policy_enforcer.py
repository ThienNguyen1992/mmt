import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.core import config as agent_config
from agent.core import local_store
from agent.core.policy_enforcer import PolicyEnforcer, canonical_json


def _generate_ed25519_pair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem.decode("ascii")


def _sign_content(content: dict, priv: Ed25519PrivateKey) -> str:
    sig = priv.sign(canonical_json(content).encode("utf-8"))
    return base64.b64encode(sig).decode("ascii")


def test_policy_enforcer_verifies_caches_and_reloads(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    priv, pub_pem = _generate_ed25519_pair()
    enforcer = PolicyEnforcer("dev-028", public_key_pem=pub_pem)
    assert enforcer.get_current_version() == 0

    content_v1 = {"quota_weekday_min": 60, "quota_weekend_min": 120}
    sig_v1 = _sign_content(content_v1, priv)

    assert enforcer.apply_new_policy(1, content_v1, sig_v1, policy_id="pol-1") is True
    assert enforcer.get_current_version() == 1
    assert enforcer.get_current_policy_id() == "pol-1"
    assert enforcer.get_content()["quota_weekday_min"] == 60

    # Reload from SQLite cache in a fresh PolicyEnforcer instance
    reloaded = PolicyEnforcer("dev-028", public_key_pem=pub_pem)
    assert reloaded.get_current_version() == 1
    assert reloaded.get_content()["quota_weekday_min"] == 60


def test_policy_enforcer_rejects_forged_update_and_tampered_sqlite_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    priv, pub_pem = _generate_ed25519_pair()
    rogue_priv, _ = _generate_ed25519_pair()
    enforcer = PolicyEnforcer("dev-028", public_key_pem=pub_pem)

    valid_content = {"quota_weekday_min": 60, "quota_weekend_min": 120}
    valid_sig = _sign_content(valid_content, priv)
    assert enforcer.apply_new_policy(1, valid_content, valid_sig, policy_id="pol-1") is True

    # 1) Forged signature from wrong key -> rejected, keeps v1
    forged_content = {"quota_weekday_min": 999, "quota_weekend_min": 999}
    rogue_sig = _sign_content(forged_content, rogue_priv)
    assert enforcer.apply_new_policy(2, forged_content, rogue_sig, policy_id="pol-2") is False
    assert enforcer.get_current_version() == 1
    assert enforcer.get_content()["quota_weekday_min"] == 60

    # 2) Valid signature paired with tampered payload -> rejected, keeps v1
    assert enforcer.apply_new_policy(2, forged_content, valid_sig, policy_id="pol-2") is False
    assert enforcer.get_current_version() == 1

    # 3) Direct manual edit of SQLite policy_cache -> rejected on reload
    with local_store.get_connection() as conn:
        conn.execute(
            "UPDATE policy_cache SET content_json=? WHERE device_id=?",
            (json.dumps(forged_content), "dev-028"),
        )
        conn.commit()

    tampered_loader = PolicyEnforcer("dev-028", public_key_pem=pub_pem)
    assert tampered_loader.get_current_version() == 0
    assert tampered_loader.get_content() is None
