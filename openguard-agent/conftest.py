import sys
from pathlib import Path

import pytest

AGENT_DIR = Path(__file__).resolve().parent
SHARED_DIR = AGENT_DIR.parent / "openguard-shared"

for p in (AGENT_DIR, SHARED_DIR):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))


@pytest.fixture
def isolated_agent_dirs(tmp_path, monkeypatch):
    """Cô lập DATA_DIR và IPC_DIR của Agent sang tmp_path trong test."""
    import agent.core.config as agent_config

    root = tmp_path / "OpenGuardKids"
    data_dir = root / "data"
    ipc_dir = root / "ipc"
    data_dir.mkdir(parents=True, exist_ok=True)
    ipc_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(agent_config, "APP_ROOT_DIR", str(root))
    monkeypatch.setattr(agent_config, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(agent_config, "IPC_DIR", str(ipc_dir))
    monkeypatch.setattr(agent_config, "APP_DATA_DIR", str(data_dir))
    monkeypatch.setattr(agent_config, "CONFIG_PATH", str(data_dir / "agent_config.json"))
    return {"root": root, "data_dir": data_dir, "ipc_dir": ipc_dir}
