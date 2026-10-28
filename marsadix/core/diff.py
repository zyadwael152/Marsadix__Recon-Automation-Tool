"""
Scan-to-scan diffing  (Core role owns this file).

Two jobs, two entry points, same comparison engine underneath:

  run_stage(ctx)   - called automatically at the end of EVERY scan (the
                      "track" stage in pipeline.py). Updates tracked_assets
                      and raises Alerts for new subdomains / new ports. (C9)

  run_diff(conn, target, old_id=None, new_id=None) -> int
                      - called by `marsadix diff <target>`. Prints a
                      human-readable comparison of the last two scans
                      (or two given scan ids). (C8)

  compute_diff(conn, old_id, new_id) -> ScanDiff
                      - the reusable engine both of the above (and the
                      report builder, and the Attack Path Time Machine)
                      call. Pure: reads the DB, returns a dataclass,
                      writes nothing.

  get_target_timeline(conn, target) -> list[dict]
                      - one row per scan of a target, oldest first, with
                      basic counts. Foundation for the Attack Path Time
                      Machine (C17): walk this list and diff consecutive
                      pairs to see how the attack surface evolved.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from .. import db
from ..models import Alert, AlertChannel, AlertType, ScanDiff, default_priority

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# comparison engine (pure: no writes)
# --------------------------------------------------------------------------

def compute_diff(conn, old_id: int, new_id: int) -> ScanDiff:
    """Compare two scans of the SAME target. Caller picks which two."""
    old_assets = {r["host"] for r in db.get_assets(conn, old_id)}
    new_assets = {r["host"] for r in db.get_assets(conn, new_id)}

    old_ports = {f'{r["host"]}:{r["port"]}' for r in db.get_services(conn, old_id)}
    new_ports = {f'{r["host"]}:{r["port"]}' for r in db.get_services(conn, new_id)}

    def _versions(scan_id: int) -> dict:
        """(host, tech name) -> set of versions. A set, not one value: a host can
        run several versions of the same technology, and a plain dict kept only
        the last one saved, hiding real changes."""
        out: dict = {}
        for r in db.get_technologies(conn, scan_id):
            out.setdefault((r["host"], r["name"]), set()).add(r["version"] or "")
        return out

    def _fmt(versions: set) -> str:
        return ", ".join(sorted(v for v in versions if v)) or "?"

    old_tech, new_tech = _versions(old_id), _versions(new_id)
    changed_tech = [
        f"{host}: {name} {_fmt(old_tech[(host, name)])} -> {_fmt(vers)}"
        for (host, name), vers in new_tech.items()
        if (host, name) in old_tech and old_tech[(host, name)] != vers
    ]

    old_findings = {r["dedup_key"]: r for r in db.get_findings(conn, old_id)}
    new_findings = {r["dedup_key"]: r for r in db.get_findings(conn, new_id)}
    new_keys = set(new_findings) - set(old_findings)
    resolved_keys = set(old_findings) - set(new_findings)

    return ScanDiff(
        old_scan_id=old_id,
        new_scan_id=new_id,
        new_assets=sorted(new_assets - old_assets),
        removed_assets=sorted(old_assets - new_assets),
        new_ports=sorted(new_ports - old_ports),
        closed_ports=sorted(old_ports - new_ports),
        changed_technologies=sorted(changed_tech),
        new_findings=sorted(f'{new_findings[k]["host"]}: {new_findings[k]["title"]}' for k in new_keys),
        resolved_findings=sorted(f'{old_findings[k]["host"]}: {old_findings[k]["title"]}' for k in resolved_keys),
    )


def get_target_timeline(conn, target: str) -> list[dict]:
    """
    One entry per scan of `target`, oldest first, with basic counts.
    Used by `marsadix graph`/report "Attack Path Time Machine" view (C17):
    walk consecutive pairs through compute_diff() to see how the attack
    surface evolved scan over scan.
    """
    scans = conn.execute(
        "SELECT * FROM scans WHERE target=? ORDER BY started_at ASC, id ASC", (target,)
    ).fetchall()
    timeline = []
    for s in scans:
        n_assets = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE scan_id=?", (s["id"],)).fetchone()[0]
        n_findings = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id=?", (s["id"],)).fetchone()[0]
        timeline.append({
            "scan_id": s["id"],
            "started_at": s["started_at"],
            "status": s["status"],
            "is_baseline": bool(s["is_baseline"]),
            "asset_count": n_assets,
            "finding_count": n_findings,
        })
    return timeline


# --------------------------------------------------------------------------
# "track" pipeline stage - runs automatically at the end of every scan (C9)
# --------------------------------------------------------------------------

def _previous_scan(conn, target: str, exclude_scan_id: int) -> Optional[dict]:
    """The most recent COMPLETED scan of `target` before `exclude_scan_id`."""
    row = conn.execute(
        "SELECT * FROM scans WHERE target=? AND id<>? AND status='completed' "
        "ORDER BY started_at DESC, id DESC LIMIT 1",
        (target, exclude_scan_id)).fetchone()
    return dict(row) if row else None


def run_stage(ctx) -> None:
    """
    Pipeline stage "track". Called once, automatically, after recon/web/asm
    for every scan. Two things:
      1. update tracked_assets + alert on genuinely NEW subdomains (not on
         the very first/baseline scan of a target).
      2. diff ports against the previous completed scan + alert on newly
         opened ports.
    Alerts are deduplicated by db.save_alert_if_new (M11): re-running never
    re-sends the same alert twice.
    """
    conn = ctx.conn
    target = ctx.target
    cur_id = ctx.scan.id

    cur_hosts = [r["host"] for r in db.get_assets(conn, cur_id) if r["in_scope"]]
    new_hosts, gone_hosts, is_baseline = db.update_tracked_assets(conn, target, cur_hosts, cur_id)

    if is_baseline:
        log.info("track: baseline scan for %s (%d hosts), no new-asset alerts", target, len(cur_hosts))
    else:
        for host in new_hosts:
            alert = Alert(
                alert_type=AlertType.NEW_ASSET,
                host=host,
                title=f"New subdomain discovered: {host}",
                details=f"First seen in scan #{cur_id}",
                priority=default_priority(AlertType.NEW_ASSET),
                channel=AlertChannel.DISCORD,
            )
            if db.save_alert_if_new(conn, alert):
                log.info("track: new asset alert queued for %s", host)
        for host in gone_hosts:
            log.info("track: asset no longer seen: %s", host)
            alert = Alert(
                alert_type=AlertType.REMOVED_ASSET,
                host=host,
                title=f"Asset no longer discovered: {host}",
                details=f"Not observed in scan #{cur_id}; this may reflect a temporary discovery/source failure and should be verified.",
                priority=default_priority(AlertType.REMOVED_ASSET),
                channel=AlertChannel.DISCORD,
                dedup_key=f"removed_asset|{host}|scan:{cur_id}|discord",
            )
            if db.save_alert_if_new(conn, alert):
                log.info("track: asset disappearance alert queued for %s", host)

    prev = _previous_scan(conn, target, cur_id)
    if prev is None:
        return  # nothing to diff ports against yet

    diff = compute_diff(conn, prev["id"], cur_id)
    for entry in diff.new_ports:
        host, _, port = entry.partition(":")
        alert = Alert(
            alert_type=AlertType.NEW_PORT,
            host=host,
            title=f"New open port: {entry}",
            details=f"Not open in scan #{prev['id']}; open in scan #{cur_id}",
            priority=default_priority(AlertType.NEW_PORT),
            channel=AlertChannel.DISCORD,
        )
        if db.save_alert_if_new(conn, alert):
            log.info("track: new port alert queued for %s", entry)


# --------------------------------------------------------------------------
# `marsadix diff <target>` CLI command (C8)
# --------------------------------------------------------------------------

def _print_diff(diff: ScanDiff, target: str, old_id: int, new_id: int) -> None:
    def section(title: str, items: list[str]) -> None:
        print(f"\n{title} ({len(items)})")
        for item in items[:50]:
            print(f"  + {item}" if title.startswith(("New", "Resolved")) else f"  - {item}")
        if len(items) > 50:
            print(f"  ... and {len(items) - 50} more")

    print(f"Diff for {target}: scan #{old_id} -> scan #{new_id}")
    section("New assets", diff.new_assets)
    section("Removed assets", diff.removed_assets)
    section("New open ports", diff.new_ports)
    section("Closed ports", diff.closed_ports)
    section("Changed technologies", diff.changed_technologies)
    section("New findings", diff.new_findings)
    section("Resolved findings", diff.resolved_findings)
    if not any([diff.new_assets, diff.removed_assets, diff.new_ports, diff.closed_ports,
                diff.changed_technologies, diff.new_findings, diff.resolved_findings]):
        print("\nNo changes between these two scans.")


def run_snapshots(conn, target: str) -> int:
    """
    Entry point for `marsadix snapshots`. Every scan of `target` is already a
    snapshot (C16) -- this just lists them in order with basic counts, built
    on get_target_timeline(). The Attack Path Time Machine (C17) walks this
    same list and diffs consecutive pairs; this command is the quick,
    human-readable view of it.
    """
    timeline = get_target_timeline(conn, target)
    if not timeline:
        print(f"error: no scans found for {target!r}. Run `marsadix scan {target}` first.",
              file=sys.stderr)
        return 1

    print(f"Snapshots for {target} ({len(timeline)} scan(s)):\n")
    for t in timeline:
        flag = " (baseline)" if t["is_baseline"] else ""
        print(f"  #{t['scan_id']:<4} {t['started_at']}  [{t['status']}]{flag}  "
              f"{t['asset_count']} assets, {t['finding_count']} findings")
    print(f"\nCompare any two with:  marsadix diff {target} --old <ID> --new <ID>")
    return 0


def run_diff(conn, target: str, old_id: Optional[int] = None, new_id: Optional[int] = None) -> int:
    """Entry point for `marsadix diff`. Returns a process exit code."""
    if old_id is None and new_id is None:
        scans = db.get_latest_scans(conn, target, limit=2)
        if len(scans) < 2:
            print(f"error: need at least 2 scans of {target!r} to diff "
                  f"(found {len(scans)}). Run `marsadix scan {target}` again first.",
                  file=sys.stderr)
            return 1
        new_id, old_id = scans[0]["id"], scans[1]["id"]
    elif new_id is None:
        # `--old N` alone means "compare N with the next scan after it". The
        # old code took the newest scan, which could be older than N (a
        # reversed diff) or N itself.
        old_row = conn.execute(
            "SELECT started_at FROM scans WHERE id=? AND target=?", (old_id, target)
        ).fetchone()
        if old_row is None:
            print(f"error: scan id {old_id} not found for {target!r}", file=sys.stderr)
            return 1
        newer = conn.execute(
            "SELECT id FROM scans WHERE target=? AND "
            "(started_at > ? OR (started_at = ? AND id > ?)) "
            "ORDER BY started_at ASC, id ASC LIMIT 1",
            (target, old_row["started_at"], old_row["started_at"], old_id)).fetchone()
        if newer is None:
            print(f"error: no scan after #{old_id} for {target!r}", file=sys.stderr)
            return 1
        new_id = newer["id"]
    elif old_id is None:
        prev = _previous_scan(conn, target, new_id)
        if prev is None:
            print(f"error: no completed scan before #{new_id} for {target!r}", file=sys.stderr)
            return 1
        old_id = prev["id"]

    if old_id == new_id:
        print("error: --old and --new must be different scans", file=sys.stderr)
        return 1

    rows = {r["id"]: r["target"] for r in conn.execute(
        "SELECT id, target FROM scans WHERE id IN (?, ?)", (old_id, new_id))}
    if len(rows) != 2:
        print(f"error: scan id not found (old={old_id}, new={new_id})", file=sys.stderr)
        return 1
    if any(t != target for t in rows.values()):
        print(f"error: both scans must belong to {target!r} "
              f"(got {', '.join(sorted(set(rows.values())))})", file=sys.stderr)
        return 1

    diff = compute_diff(conn, old_id, new_id)
    _print_diff(diff, target, old_id, new_id)
    return 0
