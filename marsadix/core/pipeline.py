"""
Pipeline skeleton (Core role owns this file).

Independent stages (web + ports: both only read the recon result and write their
own tables) run at the same time (C5b); everything else runs in order.

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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Optional

from .. import db
from ..models import Scan, ScanMode, ScanStatus
from . import limits, toolstatus
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


# Stages that do not depend on each other and may run side by side. They must be
# adjacent in STAGES. Each gets its own SQLite connection (WAL, see db.connect).
PARALLEL_GROUPS = [("web", "ports")]


def _plan(stages) -> list:
    """Split STAGES into steps: a list of stages that run together, or a single stage."""
    names = [n for n, _ in stages]
    plan, i = [], 0
    while i < len(stages):
        grp = next((g for g in PARALLEL_GROUPS if tuple(names[i:i + len(g)]) == g), None)
        n = len(grp) if grp else 1
        plan.append(list(stages[i:i + n]))
        i += n
    return plan


@dataclass
class Context:
    conn: object
    scan: Scan
    scope: Scope
    config: Config
    # Filled in by the pipeline while it runs, so a later stage (track/diff) can
    # tell a complete scan from a broken or partial one:
    #   stage_results  - StageResult of every stage that already finished
    #   degraded_tools - external tools/sources whose output may be INCOMPLETE
    #                    (timed out, crashed, output cut off); see core/toolstatus
    stage_results: list = field(default_factory=list)
    degraded_tools: list = field(default_factory=list)

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
    scan = None
    try:
        # "Baseline" = no scan of this target has COMPLETED yet. It used to count
        # every scan row, so one crashed or Ctrl+C'd first scan made the next one
        # (the first real one) "not a baseline".
        first = conn.execute("SELECT COUNT(*) FROM scans WHERE target=? AND status='completed'",
                             (host,)).fetchone()[0] == 0
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
        results = ctx.stage_results
        toolstatus.reset()
        limits.configure(tool_timeout=run_config.tool_timeout,
                         max_concurrency=run_config.max_concurrent_tools)
        parallel_ok = getattr(run_config, "parallel_stages", True) and run_config.db_path != ":memory:"
        for step in _plan(STAGES):
            window = len(toolstatus.runs())          # only what went wrong DURING this step is reported on it
            if len(step) > 1 and parallel_ok:
                results.extend(_run_parallel(ctx, step, run_config.db_path))
            else:
                for name, path in step:
                    results.append(_run_stage(ctx, name, path))
            # An "ok" stage can still have lost data (a tool timed out, crashed ...).
            ctx.degraded_tools = toolstatus.degraded()          # cumulative: the track stage needs all of it
            new = [r for r in toolstatus.runs()[window:] if r.status in toolstatus.INCOMPLETE]
            if new:
                for r in results[-len(step):]:
                    if r.status == "ok" and not r.detail:
                        r.detail = "incomplete: " + toolstatus.summary(new)

        if toolstatus.runs():
            import os
            from .textfile import safe_filename
            toolstatus.write_json(os.path.join(
                run_config.output_dir, f"{safe_filename(host)}_scan{scan.id}_tools.json"))
        failed = any(r.status == "failed" for r in results)
        db.finish_scan(conn, scan.id, "failed" if failed else "completed")
        scan.status = ScanStatus.FAILED if failed else ScanStatus.COMPLETED
        return scan, results
    except (KeyboardInterrupt, SystemExit):
        _close_scan(conn, scan, ScanStatus.INTERRUPTED)
        raise
    except Exception:
        _close_scan(conn, scan, ScanStatus.FAILED)
        raise
    finally:
        conn.close()


def _run_stage(ctx, name: str, path: str) -> "StageResult":
    """Run one stage. Never raises: a broken stage becomes a 'failed' result, the scan goes on."""
    try:
        fn = load_callable(path)
    except Exception as e:      # the stage's own import is broken (e.g. a mistyped module name)
        log.exception("stage '%s' could not be loaded", name)
        return StageResult(name, "failed", f"could not load {path}: {type(e).__name__}: {e}")
    if fn is None:
        log.info("stage '%s' not implemented yet, skipping", name)
        return StageResult(name, "skipped", f"{path} not found")
    try:
        log.info("stage '%s' started", name)
        outcome = fn(ctx)
        # A stage that deliberately did nothing (e.g. the mode forbids it)
        # returns {"skipped": "<reason>"} so `marsadix scan` reports it as
        # skipped instead of a misleading "ok".
        if isinstance(outcome, dict) and outcome.get("skipped"):
            return StageResult(name, "skipped", str(outcome["skipped"]))
        return StageResult(name, "ok")
    except Exception as e:  # one broken stage must not kill the scan
        log.exception("stage '%s' failed", name)
        return StageResult(name, "failed", f"{type(e).__name__}: {e}")


def _run_parallel(ctx, step, db_path: str) -> list:
    """
    Run independent stages at the same time, one thread each, each with its OWN
    database connection (a sqlite3 connection must not be shared between threads).
    Results come back in STAGES order whichever stage finishes first.
    """
    def work(name, path):
        conn = db.connect(db_path)
        try:
            return _run_stage(replace(ctx, conn=conn), name, path)
        finally:
            conn.close()

    ctx.conn.commit()                       # make everything recon wrote visible to the other connections
    with ThreadPoolExecutor(max_workers=len(step), thread_name_prefix="stage") as pool:
        futures = [pool.submit(work, n, p) for n, p in step]
        return [f.result() for f in futures]


def _close_scan(conn, scan, status: ScanStatus) -> None:
    """Never leave a scan 'running' when the process is going down: the row would stay that way forever."""
    if scan is None or scan.id is None:
        return
    try:
        db.finish_scan(conn, scan.id, status.value)
        scan.status = status
    except Exception:                                  # the DB itself may be what failed
        log.exception("could not record scan #%s as %s", scan.id, status.value)
