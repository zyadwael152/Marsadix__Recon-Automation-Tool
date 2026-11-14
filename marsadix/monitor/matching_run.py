"""Monitor matching pipeline: stored technologies x stored CVEs -> findings -> alerts.

    DB technologies --adapter--> Asset ---+
                                          +--> Matcher --> MatchResult --> confidence -> priority -> risk
    DB cves --------adapter--> CVE -------+                       |
                                                                  +--> findings (deduplicated upsert)
                                                                  +--> alert policy (alerts/dedup.py) --> channels

Safety: reads only data already stored by earlier scans/syncs - it never contacts a target.

Scope of each run
-----------------
* default            : (all technologies x CVEs that changed/were synced in this run or became KEV)
                       + (technologies first seen since the last completed run x ALL CVEs)
* ``all_cves=True``  : all technologies x all stored CVEs; findings that no longer match are
                       marked ``resolved`` (only here, where coverage is complete).
* ``dry_run=True``   : the whole pipeline runs against an in-memory *copy* of the database, so the
                       real file is never written; nothing is sent.
* ``no_alerts=True`` : findings are persisted, no alert rows are written and nothing is sent.

Alert gating (before dedup): confidence >= ``min_confidence`` (default medium) and
priority level >= ``min_priority`` (default high).  Findings are always stored regardless.
``findings.scan_id`` is the latest scan that observed the technology (FKs stay valid);
``findings.monitor_run_id`` links the monitor run.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .. import p4data, remediation_db
from ..alerts.base import AlertPayload, Notifier
from ..alerts.dedup import LEVEL_RANK, process_alert
from ..alerts.dispatch import build_notifiers
from ..alerts.settings import AlertSettings
from ..attack_surface import record_score
from ..db_v4 import migrate_v3_to_v4
from ..dbutil import fetch_one, has_table, insert_row, update_row
from ..matching.adapter import build_assets, to_p4_cve
from ..matching.confidence import assess
from ..matching.matcher import Matcher
from ..matching.models import CVE, Asset, Confidence
from ..matching.priority import compute_priority
from ..risk import compute_risk

__all__ = ["MatchRunSummary", "run_matching", "extract_sync_info"]

_log = logging.getLogger("marsadix.monitor")


@dataclass
class MatchRunSummary:
    dry_run: bool = False
    run_id: Optional[int] = None
    records_synced: int = 0
    technologies_evaluated: int = 0
    cves_evaluated: int = 0
    matches: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    findings_resolved: int = 0
    alerts_sent: int = 0
    alerts_would_send: int = 0
    alerts_failed: int = 0
    alerts_deduplicated: int = 0
    alerts_below_threshold: int = 0
    channels: List[str] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)
    attack_surface: Optional[Dict[str, Any]] = None

    def lines(self) -> List[str]:
        sent = f"{self.alerts_would_send} (dry-run, nothing sent)" if self.dry_run else str(self.alerts_sent)
        out = [
            f"records synced:          {self.records_synced}",
            f"technologies evaluated:  {self.technologies_evaluated}",
            f"CVEs evaluated:          {self.cves_evaluated}",
            f"matches found:           {self.matches}",
            f"findings:                {self.findings_created} new, {self.findings_updated} updated, {self.findings_resolved} resolved",
            f"new alerts sent:         {sent}",
            f"alerts deduplicated:     {self.alerts_deduplicated}",
            f"alerts below threshold:  {self.alerts_below_threshold}",
            f"channels:                {', '.join(self.channels) or 'none'}",
            f"failures:                {len(self.failures) + self.alerts_failed}",
        ]
        if self.attack_surface:
            a = self.attack_surface
            out.append(f"attack surface score:    {a['score']:.1f}/100 ({a['trend']}"
                       + (f", {a['delta']:+.1f}" if a.get('delta') is not None else "") + ")")
        out.extend(f"  ! {f}" for f in self.failures)
        return out


def extract_sync_info(result: Any) -> Dict[str, Any]:
    """Pull ``changed_cve_ids`` / ``new_kev`` / ``synced`` out of whatever the NVD/KEV/EPSS sync returned."""
    def get(*names, default=None):
        for n in names:
            v = result.get(n) if isinstance(result, Mapping) else getattr(result, n, None)
            if v is not None:
                return v
        return default
    new_kev = [str(x).upper() for x in (get("new_kev", "new_kev_ids", default=[]) or [])]
    changed = get("changed_cve_ids", "new_cve_ids", "cve_ids", "updated_ids", "changed", default=None)
    changed = None if changed is None else [str(x).upper() for x in changed]
    synced = get("total", "records", "synced", "count", default=0)
    try:
        synced = int(synced if not isinstance(synced, (list, tuple, set)) else len(synced))
    except (TypeError, ValueError):
        synced = 0
    return {"changed_cve_ids": changed, "new_kev": new_kev, "synced": synced}


def _copy_to_memory(conn: sqlite3.Connection) -> sqlite3.Connection:
    mem = sqlite3.connect(":memory:")
    conn.backup(mem)
    return mem


def _last_max_tech_id(conn: sqlite3.Connection) -> int:
    r = fetch_one(conn, "SELECT max(max_tech_id) AS m FROM monitor_runs WHERE status='ok'")
    return int(r["m"] or 0) if r and r["m"] is not None else 0


def _level_ok(level: str, minimum: str) -> bool:
    return LEVEL_RANK.get(level, 1) >= LEVEL_RANK.get(minimum, 3)


def run_matching(conn: sqlite3.Connection, *, settings: Optional[AlertSettings] = None,
                 notifiers: Optional[Mapping[str, Notifier]] = None, changed_cve_ids: Optional[Iterable[str]] = None,
                 new_kev: Iterable[str] = (), synced: int = 0, all_cves: bool = False, dry_run: bool = False,
                 no_alerts: bool = False, channels: Optional[Iterable[str]] = None, client: Any = None,
                 smtp_factory: Any = None, resolver: Any = None, sleep: Any = None) -> MatchRunSummary:
    summary = MatchRunSummary(dry_run=dry_run, records_synced=synced)
    work = _copy_to_memory(conn) if dry_run else conn
    try:
        migrate_v3_to_v4(work)
        remediation_db.seed_defaults(work)
        settings = settings or AlertSettings.from_env()
        channel_list = [c for c in (channels or [])]
        if notifiers is None:
            kw = {"client": client, "smtp_factory": smtp_factory, "resolver": resolver}
            if sleep is not None:
                kw["sleep"] = sleep
            notifiers = {} if no_alerts else build_notifiers(settings, channel_list or None, **kw)
        notifiers = {} if no_alerts else dict(notifiers)
        for c in channel_list:
            if not no_alerts and c.lower() not in notifiers:
                summary.failures.append(f"channel '{c}' is not configured")
        summary.channels = sorted(notifiers)

        run_id: Optional[int] = None
        if not dry_run:
            run_id = insert_row(work, "monitor_runs", {"status": "running", "synced": synced,
                                                       "flags": json.dumps({"all": all_cves, "no_alerts": no_alerts, "channels": sorted(notifiers)})})
            work.commit()
        summary.run_id = run_id

        # ---- load + adapt --------------------------------------------------
        techs = p4data.load_technologies(work)
        ctx = p4data.asset_context(work)
        assets: List[Asset] = build_assets(techs, ctx)
        summary.technologies_evaluated = len(assets)
        max_tech_id = max([int(t.get("id") or 0) for t in techs] or [0])
        last_max = _last_max_tech_id(work)
        new_assets = [a for a in assets if (a.technology_id or 0) > last_max]

        kev_ids = sorted({str(i).upper() for i in new_kev})
        if all_cves:
            cve_rows = p4data.load_cves(work)
            batches = [(assets, cve_rows)]
        else:
            ids = set(kev_ids) | {str(i).upper() for i in (changed_cve_ids or [])}
            batches = [(assets, p4data.load_cves(work, ids))] if ids else []
            if new_assets:
                batches.append((new_assets, p4data.load_cves(work)))
        matcher = Matcher()
        seen: Dict[tuple, Any] = {}
        evaluated_ids = set()
        for batch_assets, rows in batches:
            cves: List[CVE] = []
            for row in rows:
                try:
                    cves.append(to_p4_cve(row))
                except Exception as exc:  # malformed stored CVE must not abort the run
                    summary.failures.append(f"cve row skipped ({type(exc).__name__})")
            evaluated_ids.update(c.id for c in cves)
            for r in matcher.match_all(batch_assets, cves):
                seen[(r.cve.id, r.asset.host, r.asset.cpe)] = r
        summary.cves_evaluated = len(evaluated_ids)
        summary.failures.extend(matcher.errors)
        matches = [seen[k] for k in sorted(seen)]
        summary.matches = len(matches)

        # ---- findings + alerts -----------------------------------------------
        min_conf = Confidence.coerce(settings.min_confidence.upper() if isinstance(settings.min_confidence, str) else settings.min_confidence)
        current_keys = set()
        for r in matches:
            a, cve = r.asset, r.cve
            conf = assess(r).level
            pr = compute_priority(cve.cvss, cve.epss, cve.kev, conf)
            risk = compute_risk(pr, internet_facing=a.internet_facing, behind_cdn=a.behind_cdn, criticality=a.criticality, kev=cve.kev)
            product = a.product or a.name
            rem = remediation_db.lookup(work, {"cve_id": cve.id, "title": f"{cve.id} {a.name}", "description": cve.description,
                                               "product": product, "cwe": cve.cwe, "owasp": "A06:2021"})
            key = f"cvefinding:{cve.id}|host:{a.host.lower()}|product:{product.lower()}"
            current_keys.add(key)
            scan_id = a.scan_id if a.scan_id is not None else p4data.scan_for_host(work, a.host)
            if scan_id is None:
                summary.failures.append(f"{cve.id} on {a.host}: no scan has observed this host, finding not stored")
                continue
            res = p4data.upsert_finding(work, key, {
                "scan_id": scan_id, "host": a.host, "title": f"{cve.id} in {a.name or product} {a.version or ''}".strip(),
                "severity": pr.level.label, "status": "open", "category": "cve", "source": "monitor", "cve_id": cve.id,
                "owasp_category": p4data.owasp_full("A06:2021"), "in_kev": int(cve.kev), "source_reference": "NVD/CISA KEV/EPSS",
                "product": product, "version": a.version, "cvss": cve.cvss, "epss": cve.epss, "kev": int(cve.kev),
                "confidence": conf.label, "priority_score": pr.score, "risk_score": risk.score,
                "description": cve.description[:2000], "remediation_key": rem.match_value, "template_id": cve.id,
                "evidence": json.dumps({"matched": list(r.matched_criteria), "notes": list(r.notes), "priority_reasons": list(pr.reasons),
                                        "risk_reasons": list(risk.reasons)}), "monitor_run_id": run_id})
            summary.findings_created += res["created"]
            summary.findings_updated += not res["created"]

            if not notifiers:
                continue
            if conf < min_conf or not _level_ok(pr.level.label, settings.min_priority):
                summary.alerts_below_threshold += 1
                continue
            payload = AlertPayload(
                cve_id=cve.id, host=a.host, product=product, technology=a.name or product, version=a.version or "",
                cvss=cve.cvss, epss=cve.epss, kev=cve.kev, confidence=conf.label, priority_level=pr.level.label,
                priority_score=pr.score, risk_score=risk.score, remediation_title=rem.title, remediation_text=rem.fix_text,
                description=cve.description, reasons=list(pr.reasons))
            for ch in sorted(notifiers):
                out = process_alert(work, payload, ch, notifiers[ch], dry_run=dry_run)
                if out is None:
                    summary.alerts_deduplicated += 1
                elif dry_run:
                    summary.alerts_would_send += 1
                elif out["result"].ok:
                    summary.alerts_sent += 1
                else:
                    summary.alerts_failed += 1
                    summary.failures.append(f"alert {cve.id} on {a.host} via {ch}: {out['result'].error}")
        work.commit()

        if all_cves:
            hosts = {a.host for a in assets}
            for f in p4data.load_findings(work, source="monitor", open_only=True):
                if f.get("dedup_key") and f["dedup_key"] not in current_keys and f.get("host") in hosts and f.get("cve_id"):  # 'category' is not a column of the real findings table
                    update_row(work, "findings", "id", f["id"], {"status": "resolved", "last_seen": p4data.now_iso()})
                    summary.findings_resolved += 1
            work.commit()

        score = record_score(work, run_type="monitor", run_ref=run_id, persist=not dry_run)
        summary.attack_surface = score.to_dict()
        if not dry_run:
            update_row(work, "monitor_runs", "id", run_id, {
                "status": "ok", "finished_at": p4data.now_iso(), "technologies": summary.technologies_evaluated,
                "cves_evaluated": summary.cves_evaluated, "matches": summary.matches, "alerts_sent": summary.alerts_sent,
                "failures": len(summary.failures) + summary.alerts_failed, "max_tech_id": max(max_tech_id, last_max)})
            work.commit()
        return summary
    except Exception:
        if not dry_run and summary.run_id:
            try:
                work.rollback()
                update_row(work, "monitor_runs", "id", summary.run_id, {"status": "error", "finished_at": p4data.now_iso()})
                work.commit()
            except sqlite3.Error:
                _log.warning("could not mark monitor run as failed")
        raise
    finally:
        if dry_run:
            work.close()
