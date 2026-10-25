"""
Pipeline skeleton (Core role owns this file).

A *stage* is a function  run(ctx: Context) -> None  that lives in its owner's
module. The pipeline calls the stages in order; a stage that doesn't exist yet
is skipped, so everyone can plug in without touching this file:

    recon  -> marsadix/recon/stage.py : run(ctx)     (Person 1)
    web    -> marsadix/web/stage.py   : run(ctx)     (Person 2)
    asm    -> marsadix/asm/stage.py   : run(ctx)     (Person 2)
    track  -> marsadix/core/diff.py   : run_stage(ctx)  (Person 5)
    graph  -> marsadix/core/graph.py  : run_stage(ctx)  (Person 5)

Inside a stage: use ctx.scope.is_in_scope(host) BEFORE touching any host, call
the wrappers (pure functions that return lists of models), then save with
db.save_many(ctx.conn, "assets", [...]).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from typing import Optional

from .. import db
from ..models import Scan, ScanMode, ScanStatus
from .config import SCAN_MODES, Config, ConfigError
from .loader import load_callable
from .scope import Scope, ScopeError, normalize_host

log = logging.getLogger(__name__)

STAGES = [
    ("recon", "marsadix.recon.stage:run"),
    ("web", "marsadix.web.stage:run"),
    ("ports", "marsadix.ports.stage:run"),
    ("asm", "marsadix.asm.stage:run"),
    ("track", "marsadix.core.diff:run_stage"),
    ("graph", "marsadix.core.graph:run_stage"),
]


@dataclass
class Context:
    conn: object
    scan: Scan
    scope: Scope
    config: Config

    @property
    def target(self) -> str:
        return self.scan.target

    @property
    def mode(self) -> str:
        """This run's mode: "passive" | "standard" | "full" (C15)."""
        m = self.scan.mode
        return getattr(m, "value", m)

    def allows(self, minimum: str) -> bool:
        """
        True if this run's mode is at least `minimum`. Stages that contact the
        target must gate themselves on this:

            if not ctx.allows("standard"):   # passive: no contact with the target
                return {"skipped": "..."}
        """
        return SCAN_MODES.index(self.mode) >= SCAN_MODES.index(minimum)

    def in_scope(self, host: str) -> bool:
        return self.scope.is_in_scope(host)


@dataclass
class StageResult:
    name: str
    status: str            # ok | skipped | failed
    detail: str = ""


def run_scan(target: str, config: Config, scope: Optional[Scope] = None,
             max_depth: Optional[int] = None, rate_limit: Optional[int] = None,
             mode: Optional[str] = None, allow_injection: Optional[bool] = None,
             scope_file: Optional[str] = None):
    """
    Create a scan, run every available stage, store the outcome.

    `scope` (C15): required for "standard" and "full", which send traffic to the
    target; ScopeError otherwise. Only "passive" may fall back to a scope
    derived from the target itself (target + its subdomains). `scope_file` is
    the path the scope was loaded from; it is stored on the scan record so a
    report can say which scope authorised the scan.

    `rate_limit`: max requests per second sent to the target; must be >= 1
    (httpx/katana treat 0 as "unlimited", which is never what a typo meant).

    `mode` (C15): "passive" | "standard" | "full". Defaults to config.scan_mode.
    This is stored on the Scan record (ctx.scan.mode) and on ctx.config.scan_mode
    for the duration of this run; stage authors (recon/web/asm) are expected to
    check it before doing anything more intrusive than the mode allows -- the
    pipeline itself does not know what each stage considers "active".

    `allow_injection` (A5): explicit opt-in for injection-style checks (XSS,
    SQLi, SSTI probes). None keeps config.allow_injection; True/False overrides
    it for this run only, without touching config.toml.
    """
    host = normalize_host(target)
    if not host:
        raise ScopeError(f"invalid target: {target!r}")

    resolved_mode = config.scan_mode if mode is None else mode
    if resolved_mode not in SCAN_MODES:
        raise ConfigError(f"mode must be one of {SCAN_MODES}, got {resolved_mode!r}")

    if scope is None:
        if resolved_mode != "passive":
            raise ScopeError(
                f"mode '{resolved_mode}' sends traffic to the target, so it needs an "
                f"explicit scope: pass a scope file (--scope scope.txt, see "
                f"scope.example.txt). --mode passive does not need one.")
        scope = Scope.from_target(host)
    decision = scope.check(host)
    if not decision:
        raise ScopeError(f"target '{host}' is not in scope ({decision.reason})")

    resolved_rate = config.rate_limit if rate_limit is None else rate_limit
    if resolved_rate < 1:
        raise ConfigError(f"rate limit must be at least 1 request/second, got {resolved_rate}")
    resolved_depth = config.max_depth if max_depth is None else max_depth
    if resolved_depth < 0:
        raise ConfigError(f"max depth cannot be negative, got {resolved_depth}")

    # The resolved values are put on ctx.config for this run: a stage reading
    # ctx.config.scan_mode / rate_limit used to get the config.toml value even
    # when the CLI flag said otherwise.
    overrides: dict = {"scan_mode": resolved_mode, "rate_limit": resolved_rate,
                       "max_depth": resolved_depth}
    if allow_injection is not None and allow_injection != config.allow_injection:
        overrides["allow_injection"] = allow_injection
    run_config = replace(config, **overrides)

    conn = db.connect(config.db_path)
    db.init_db(conn)

    first = conn.execute("SELECT COUNT(*) FROM scans WHERE target=?", (host,)).fetchone()[0] == 0
    scan = Scan(
        target=host,
        status=ScanStatus.RUNNING,
        is_baseline=first,
        max_depth=resolved_depth,
        rate_limit=resolved_rate,
        mode=ScanMode(resolved_mode),
        scope_file=scope_file,
    )
    db.save_scan(conn, scan)
    log.info("scan #%s started: %s (baseline=%s, mode=%s)", scan.id, host, first, resolved_mode)

    ctx = Context(conn=conn, scan=scan, scope=scope, config=run_config)
    results = []
    for name, path in STAGES:
        fn = load_callable(path)
        if fn is None:
            log.info("stage '%s' not implemented yet, skipping", name)
            results.append(StageResult(name, "skipped", f"{path} not found"))
            continue
        try:
            log.info("stage '%s' started", name)
            outcome = fn(ctx)
            # A stage that deliberately did nothing (e.g. the mode forbids it)
            # returns {"skipped": "<reason>"} so `marsadix scan` reports it as
            # skipped instead of a misleading "ok".
            if isinstance(outcome, dict) and outcome.get("skipped"):
                results.append(StageResult(name, "skipped", str(outcome["skipped"])))
            else:
                results.append(StageResult(name, "ok"))
        except Exception as e:  # one broken stage must not kill the scan
            log.exception("stage '%s' failed", name)
            results.append(StageResult(name, "failed", f"{type(e).__name__}: {e}"))

    failed = any(r.status == "failed" for r in results)
    db.finish_scan(conn, scan.id, "failed" if failed else "completed")
    scan.status = ScanStatus.FAILED if failed else ScanStatus.COMPLETED
    conn.close()
    return scan, results
