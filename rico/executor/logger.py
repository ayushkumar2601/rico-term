"""Logging utilities for RICO HTTP requests."""

import logging
from pathlib import Path
from datetime import datetime


def setup_logger(log_file: str = "rico.log") -> logging.Logger:
    """
    Set up logger for RICO requests.

    Args:
        log_file: Path to log file

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("rico")
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers
    if logger.handlers:
        return logger

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


def log_request(method: str, url: str, status_code: int, response_time: float):
    """
    Log an HTTP request.

    Args:
        method: HTTP method
        url: Request URL
        status_code: Response status code
        response_time: Response time in seconds
    """
    logger = setup_logger()
    logger.info(
        f"Request: {method} {url} | Status: {status_code} | Time: {response_time:.3f}s"
    )
