"""Logging setup with credential redaction and optional rotation."""

from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path
from typing import Optional

from .errors import redact


class RedactionFilter(logging.Filter):
    """Last line of defence: API keys/tokens never reach a log sink."""

    _url_creds = re.compile(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # defensive: never break logging
            return True
        cleaned = redact(message)
        cleaned = self._url_creds.sub(lambda m: m.group(1) + "<redacted>@", cleaned)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        return True


def configure_logging(verbose: bool = False, log_file: Optional[str] = None,
                      force: bool = False) -> logging.Logger:
    """Configure console + optional rotating file logging.

    Returns the extension logger.  `force=True` is used by the CLI; library
    callers keep whatever logging configuration the host application set.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("marsadix.web_recon")
    logger.setLevel(level)

    root = logging.getLogger()
    if root.handlers:
        # When embedded in a host app (or pytest), use the host's handlers.
        # Drop any local handlers installed by this module so they cannot
        # retain a closed capture stream.
        for handler in tuple(logger.handlers):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass
        logger.propagate = True
        return logger
    if not force and logger.handlers:
        return logger

    if force:
        # Replace our own handlers instead of stacking StreamHandlers on each
        # CLI invocation.
        for handler in tuple(logger.handlers):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    redaction = RedactionFilter()

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.addFilter(redaction)
    logger.addHandler(console)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(fmt)
        file_handler.addFilter(redaction)
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger
