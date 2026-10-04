import logging
import os


def setup_logger(log_file="results/netrecon.log"):
    os.makedirs(
        os.path.dirname(log_file),
        exist_ok=True
    )

    logger = logging.getLogger("netrecon")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        file_handler = logging.FileHandler(
            log_file,
            encoding="utf-8"
        )

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )

        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger