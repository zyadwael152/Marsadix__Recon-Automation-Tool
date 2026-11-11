"""Logging setup. Every module does:  log = logging.getLogger(__name__)"""

from __future__ import annotations

import logging


def setup_logging(verbose: bool = False) -> None:
    # Respect handlers installed by the host application (including pytest's
    # capture handlers). ``force=True`` would remove those handlers and can
    # leave stale handlers writing to closed capture streams. basicConfig is
    # intentionally a no-op when the host already configured logging.
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
