"""Optional `run(ctx)` adapter for a custom Marsadix pipeline.

The base pipeline's stage list is deliberately not patched by this package.
If a team decides to add the extension as a post-web stage, point the loader at
`marsadix.web_recon.stage:run`; the signature matches the base stage contract.

Returning a dict with a `skipped` key makes the base pipeline display the run
as skipped (for example, passive scans with no archive providers).
"""

from __future__ import annotations

import logging

from .config import Member2Config
from .pipeline import run_web_pipeline

logger = logging.getLogger(__name__)


def run(ctx) -> dict:
    cfg = Member2Config(
        db_path=getattr(ctx.config, "db_path", "marsadix.db"),
        output_dir=getattr(ctx.config, "output_dir", "output"),
        rate_limit=getattr(ctx.config, "rate_limit", 10),
        tool_timeout=getattr(ctx.config, "tool_timeout", 300),
    )
    # `conn` and `scan_id` avoid re-opening the DB while the pipeline holds its
    # connection.  The scan's stored scope file is reused when present.
    report = run_web_pipeline(
        conn=ctx.conn,
        scan_id=ctx.scan.id,
        scope_path=getattr(ctx.scan, "scope_file", None),
        scope_obj=getattr(ctx, "scope", None),
        config=cfg,
    )
    return {"member2": report.to_dict()}
