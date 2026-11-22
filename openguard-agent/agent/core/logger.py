import logging
import os
from logging.handlers import RotatingFileHandler

from agent.core import config as agent_config


def get_logger(name: str = "ogk_agent") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    try:
        agent_config.ensure_app_data_dir()
        log_dir = os.path.join(agent_config.DATA_DIR, "logs")
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "agent.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError:
        pass  # trong môi trường unit test không có quyền ghi ProgramData

    return logger
