import time

from agent.core.config import load_config
from agent.core.logger import get_logger

logger = get_logger()


def main():
    cfg = load_config()
    logger.info("OGK-Agent skeleton khởi động (enrolled=%s)", cfg.get("enrolled"))
    try:
        while True:
            logger.debug("Agent heartbeat loop (skeleton)...")
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Đã dừng Agent skeleton.")


if __name__ == "__main__":
    main()
