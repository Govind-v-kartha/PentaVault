"""Centralized logging configuration for the scanner."""

import logging
import os
from datetime import datetime


def setup_logger(log_dir: str = "logs") -> logging.Logger:
    """Configure and return the root scanner logger.

    Logs are written to both console (INFO+) and a timestamped file (DEBUG+).
    """
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("scanner")
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # File handler — captures everything
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fh = logging.FileHandler(
        os.path.join(log_dir, f"scan_{timestamp}.log"), encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )

    # Console handler — INFO and above
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the scanner namespace."""
    return logging.getLogger(f"scanner.{name}")
