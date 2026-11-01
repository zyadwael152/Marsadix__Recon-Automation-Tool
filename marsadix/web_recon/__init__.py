"""Marsadix Member 2 extension: web-surface reconnaissance.

This package is deliberately additive.  It imports the untouched Marsadix core
(`marsadix.db`, `marsadix.models`, `marsadix.core.scope`) and adds the missing
Member 2 capabilities around it:

* archive URL ingestion (gau, Wayback CDX, optional Common Crawl);
* katana and built-in crawling;
* JavaScript endpoint extraction;
* URL normalization, scope re-validation and status-code filtering;
* safe storage through the existing SQLite helpers/models;
* structured tool outcomes, rate limiting and logging.

Nothing in this package patches the base repository at import time.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .config import Member2Config, load_member2_config
from .pipeline import WebPipelineReport, run_web_pipeline

__all__ = [
    "Member2Config",
    "WebPipelineReport",
    "load_member2_config",
    "run_web_pipeline",
    "__version__",
]
