import pytest

from agent.core import acl_hardening
from agent.core import config as agent_config


def _extract_aces(dacl) -> list[tuple[str, int]]:
    import win32security

    aces = []
    for idx in range(dacl.GetAceCount()):
        _ace_hdr, mask, sid = dacl.GetAce(idx)
        sid_str = win32security.ConvertSidToStringSid(sid)
        aces.append((sid_str, mask))
    return aces


def test_build_directory_dacl_separates_data_and_ipc_permissions():
    if not acl_hardening.HAS_WIN32_SECURITY:
        pytest.skip("win32security required on Windows")

    import ntsecuritycon as con

    # DATA_DIR: ONLY SYSTEM & Administrators (no Users!)
    data_dacl = acl_hardening.build_directory_dacl(allow_users_read=False)
    data_aces = _extract_aces(data_dacl)
    assert [sid for sid, _ in data_aces] == [
        acl_hardening.SID_SYSTEM,
        acl_hardening.SID_ADMINISTRATORS,
    ]
    assert all(mask == con.FILE_ALL_ACCESS for _, mask in data_aces)

    # IPC_DIR: SYSTEM & Administrators Full + Users Read-Execute only
    ipc_dacl = acl_hardening.build_directory_dacl(allow_users_read=True)
    ipc_aces = _extract_aces(ipc_dacl)
    assert [sid for sid, _ in ipc_aces] == [
        acl_hardening.SID_SYSTEM,
        acl_hardening.SID_ADMINISTRATORS,
        acl_hardening.SID_USERS,
    ]
    users_mask = ipc_aces[2][1]
    assert users_mask == (con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE)
    assert not (users_mask & con.FILE_WRITE_DATA)


def test_harden_agent_directories_applies_correct_flags_to_data_and_ipc(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(tmp_path / "ipc"))

    monkeypatch.setattr(acl_hardening, "is_running_as_admin", lambda: False)
    with pytest.raises(PermissionError):
        acl_hardening.harden_agent_directories()

    calls = []
    monkeypatch.setattr(acl_hardening, "is_running_as_admin", lambda: True)
    monkeypatch.setattr(
        acl_hardening,
        "_apply_dacl",
        lambda path, allow_users_read: calls.append((path, allow_users_read)),
    )

    acl_hardening.harden_agent_directories()
    assert calls == [
        (str(tmp_path / "data"), False),
        (str(tmp_path / "ipc"), True),
    ]
