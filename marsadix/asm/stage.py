"""ASM stage: run active Nuclei checks against in-scope Web/asset inventory.

Web owns discovery and enrichment. ASM owns vulnerability-template execution
and persistence. This stage intentionally consumes the shared DB inventory
instead of importing or invoking the Web Recon pipeline.
"""
from __future__ import annotations

import asyncio
import logging

from marsadix import db
from marsadix.skills import register_handler
from .config import ASMConfig
from .scope import ScopeEnforcer
from .runtime import ToolResolver

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

    # ASM owns its Nuclei configuration; shared runtime limits are inherited
    # from the main application config, never from Web Recon.
    cfg = ASMConfig.from_runtime(ctx.config)
    if not cfg.nuclei_enabled:
        return {"asm": {"engine": "nuclei", "status": "skipped",
                        "reason": "disabled by MARSADIX_ASM_NUCLEI_ENABLED"}}

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


# The registry lists a skill as "active" only when code for it exists: this stage runs the three Nuclei groups.
for _name in ("nuclei-takeover", "nuclei-exposures", "nuclei-tech-cve"):
    register_handler(_name)(run)
