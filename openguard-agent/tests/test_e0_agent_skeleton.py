import logging

from shared.network_constants import (
    ALL_COMPONENTS,
    DNS_PROXY_PORT,
    HTTPS_API_PORT,
    IPC_PORT,
)

from agent.core.config import load_config, save_config
from agent.core.logger import get_logger


def test_network_constants_consistent():
    assert HTTPS_API_PORT == 8443
    assert DNS_PROXY_PORT == 53
    assert IPC_PORT == 17321
    assert len(ALL_COMPONENTS) == 4


def test_agent_config_and_logger_isolated(isolated_agent_dirs):
    cfg = load_config()
    assert cfg["enrolled"] is False
    assert cfg["server_port"] == HTTPS_API_PORT
    cfg["device_id"] = "dev-test-1"
    save_config(cfg)

    reloaded = load_config()
    assert reloaded["device_id"] == "dev-test-1"

    logger_name = "test_e0_logger"
    logger = get_logger(logger_name)
    logger.info("Kiểm tra log E0")
    log_file = isolated_agent_dirs["data_dir"] / "logs" / "agent.log"
    assert log_file.exists()

    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    logging.getLogger(logger_name).handlers.clear()


def test_agent_main_skeleton_exits_on_keyboard_interrupt(isolated_agent_dirs, monkeypatch):
    import agent.main as agent_main

    def _interrupt(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(agent_main.time, "sleep", _interrupt)
    agent_main.main()
    assert (isolated_agent_dirs["data_dir"] / "agent_config.json").exists()
