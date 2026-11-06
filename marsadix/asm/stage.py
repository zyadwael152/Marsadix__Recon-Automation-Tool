"""ASM stage: run active Nuclei checks against in-scope Web/asset inventory.

Web owns discovery and enrichment. ASM owns vulnerability-template execution
and persistence. This stage intentionally consumes the shared DB inventory
instead of importing or invoking the Web Recon pipeline.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import replace

from marsadix import db
from marsadix.web_recon.config import load_member2_config
from marsadix.web_recon.scope_filter import ScopeEnforcer
from marsadix.web_recon.tools import ToolResolver

from .nuclei import run_nuclei

log = logging.getLogger(__name__)


def _targets(ctx) -> list[str]:
    """Build a stable candidate list from this scan's assets and Web inventory."""
    values: list[str] = []
    for row in db.get_assets(ctx.conn, ctx.scan.id):
        if row["host"]:
            values.append(str(row["host"]))
    for row in db.get_web_items(ctx.conn, ctx.scan.id):
        if row["url"]:
            values.append(str(row["url"]))
    # Preserve order while removing exact duplicates; the Nuclei wrapper
    # further canonicalizes to one in-scope request per origin.
    return list(dict.fromkeys(values))


def run(ctx) -> dict:
    """Execute ASM Nuclei checks for standard/full scans only."""
    if not ctx.allows("standard"):
        return {"skipped": "ASM active checks require standard or full mode"}

    # Reuse Member 2's validated tool settings so existing Nuclei binary,
    # timeout, rate, tag and severity configuration remains effective.
    cfg = load_member2_config()
    cfg = replace(
        cfg,
        db_path=getattr(ctx.config, "db_path", cfg.db_path),
        output_dir=getattr(ctx.config, "output_dir", cfg.output_dir),
        rate_limit=max(1, int(getattr(ctx.config, "rate_limit", cfg.rate_limit))),
        tool_timeout=max(1, int(getattr(ctx.config, "tool_timeout", cfg.tool_timeout))),
        nuclei_enabled=True,
        write_outputs=False,
    )
    cfg.validate()

    targets = _targets(ctx)
    if not targets:
        return {"skipped": "ASM found no asset or Web URL candidates"}

    enforcer = ScopeEnforcer(
        scope=ctx.scope,
        target=ctx.target,
        allow_private=cfg.allow_private,
        dns_timeout=cfg.dns_timeout,
    )
    resolver = ToolResolver(cfg)
    batch = asyncio.run(run_nuclei(
        targets=targets,
        scan_id=ctx.scan.id,
        target=ctx.target,
        config=cfg,
        resolver=resolver,
        enforcer=enforcer,
    ))

    saved = db.save_many(ctx.conn, "findings", batch.findings) if batch.findings else 0
    outcome = batch.outcome.to_dict() if batch.outcome else None
    log.info(
        "ASM Nuclei completed for scan #%s: status=%s findings=%s saved=%s",
        ctx.scan.id,
        (batch.outcome.status if batch.outcome else "unknown"),
        len(batch.findings), saved,
    )
    return {
        "asm": {
            "engine": "nuclei",
            "status": batch.outcome.status if batch.outcome else "unknown",
            "targets_considered": len(targets),
            "findings_detected": len(batch.findings),
            "findings_saved": saved,
            "groups": dict(batch.groups),
            "outcome": outcome,
        }
    }
