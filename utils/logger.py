# =============================================================================
# utils/logger.py — Centralized Rotating Logger
# =============================================================================
# Provides a single shared logger used by every module in the system.
# Outputs to both the console (INFO+) and a rotating log file.

import logging
import os
from logging.handlers import RotatingFileHandler

import config


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger configured with:
      - Console handler (StreamHandler)
      - Rotating file handler (logs/netmon.log)

    Usage:
        from utils.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Module started")
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if get_logger() is called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Console Handler ───────────────────────────────────────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # ── Rotating File Handler ─────────────────────────────────────────────────
    os.makedirs(config.LOG_DIR, exist_ok=True)
    log_path = os.path.join(config.LOG_DIR, config.LOG_FILENAME)
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
