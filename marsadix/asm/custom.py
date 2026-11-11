"""
Custom detection skills as a part of the ASM stage (A5, A8): XSS, SQL injection, SSTI, open redirect,
CRLF, Host header, JWT review and .git / .env exposure. The checks themselves live in `skills.py`; this
module chooses WHAT to test and HOW MUCH, and runs them.

Gating (the registry decides, see skills/registry.py):
  standard   the two low-traffic skills: JWT review and .git/.env exposure
  full       + the injection-style skills (XSS, SQLi, SSTI, open redirect, CRLF, Host header),
             and only with the explicit --allow-injection opt-in
  passive    nothing (the stage is skipped before this module is reached)

Targets are the live URLs / parameterised URLs the web stage stored. They are re-checked against the scope AND
the network guard here, and `http.ProbeClient` checks both again before every single request.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

from .. import db
from ..core import netguard, toolstatus
from ..models import WebItemKind
from ..skills import registry
from . import dnsclient, enum_dns, enum_web, skills as custom_skills
from .dnsclient import DnsClient
from .http import ProbeClient

# which skills run once per host (base URL), once per parameterised URL, or once per domain (DNS)
PARAM_SKILLS = custom_skills.PARAM_SKILLS
HOST_SKILLS = custom_skills.HOST_SKILLS | enum_web.WEB_SKILLS
DNS_SKILLS = enum_dns.DNS_SKILLS

log = logging.getLogger(__name__)

MAX_PARAM_URLS_PER_HOST = 15          # parameterised URLs one host may have tested
MAX_WORKERS = 8


def collect_targets(ctx) -> Tuple[List[custom_skills.Target], List[custom_skills.Target]]:
    """(parameterised URLs, one base target per host), scope- and network-checked and de-duplicated."""
    ips = {a["host"]: netguard.asset_ip(a) for a in db.get_assets(ctx.conn, ctx.scan.id)}
    params: List[custom_skills.Target] = []
    hosts: Dict[str, custom_skills.Target] = {}
    per_host: Dict[str, int] = defaultdict(int)
    shapes: Set[tuple] = set()

    for w in db.get_web_items(ctx.conn, ctx.scan.id):
        url, host = w["url"], w["host"]
        if not url or not ctx.in_scope(url):
            continue
        ip = ips.get(host)
        if ip and netguard.blocked_reason(ip, ctx.scope):
            continue                              # a name in scope that resolves to an internal address
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        base = f"{parts.scheme}://{parts.netloc}"
        if w["kind"] == WebItemKind.URL.value and not parts.query:
            hosts.setdefault(base, custom_skills.Target(ctx.scan.id, host, base + "/", base))
        if parts.query:
            names = tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True)))
            shape = (host, parts.path, names)
            if shape not in shapes and per_host[host] < MAX_PARAM_URLS_PER_HOST:
                shapes.add(shape)
                per_host[host] += 1
                params.append(custom_skills.Target(ctx.scan.id, host, url, base))
                hosts.setdefault(base, custom_skills.Target(ctx.scan.id, host, base + "/", base))
    return params, list(hosts.values())


def _run_jobs(client: ProbeClient, dns: DnsClient, jobs, workers: int):
    findings, tested = [], 0

    def work(job):
        name, target = job
        handler = custom_skills.handler_for(name)
        try:
            return handler(dns if name in DNS_SKILLS else client, target) if handler else []
        except Exception:                                    # one broken probe must not stop the others
            log.exception("skill %s failed on %s", name, target.url)
            toolstatus.record(f"skill:{name}", "failed", "exception while probing")
            return []

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="skill") as pool:
        for res in pool.map(work, jobs):
            tested += 1
            findings.extend(res)
    return findings, tested


def run(ctx, rate_limit: Optional[float] = None, timeout: float = 10) -> Optional[dict]:
    """Run the active custom skills. None when nothing applies (so callers can leave their result alone)."""
    allow = bool(getattr(ctx.config, "allow_injection", False))
    active = [s for s in registry.active_skills(ctx.mode, allow) if s.engine == "custom"]
    held_back = [s.name for s in registry.active_skills(ctx.mode, True)
                 if s.engine == "custom" and s.needs_opt_in] if not allow else []
    if held_back:
        log.info("injection-style skills not run (they need --allow-injection in full mode): %s", ", ".join(held_back))
    if not active:
        return None

    params, hosts = collect_targets(ctx)
    domain = [custom_skills.Target(ctx.scan.id, ctx.target, "", "")] if ctx.in_scope(ctx.target) else []
    jobs = []
    for s in active:
        if s.name in PARAM_SKILLS:
            jobs += [(s.name, t) for t in params]
        elif s.name in HOST_SKILLS:
            jobs += [(s.name, t) for t in hosts]
        elif s.name in DNS_SKILLS:
            jobs += [(s.name, t) for t in domain]
    if not jobs:
        return None

    rate = rate_limit or getattr(ctx.config, "rate_limit", 10) or 10
    client = ProbeClient(ctx.scope, rate_limit=rate, timeout=timeout)
    dns = DnsClient(ctx.scope, rate_limit=rate, timeout=min(timeout, 5), resolvers=dnsclient.system_resolvers())
    found, tested = _run_jobs(client, dns, jobs, workers=max(1, min(MAX_WORKERS, getattr(ctx.config, "max_concurrent_tools", MAX_WORKERS))))
    saved = db.save_many(ctx.conn, "findings", found) if found else 0
    inventory = db.save_enum_items(ctx.conn, ctx.scan.id, client.inventory + dns.inventory)
    log.info("custom skills: %d check(s), %d request(s), %d finding(s), %d inventory item(s); finding nothing is NOT proof of safety",
             tested, client.requests + dns.requests, saved, inventory)
    return {"skills": sorted({s.name for s in active}), "checks": tested, "requests": client.requests + dns.requests,
            "inventory_saved": inventory,
            "findings_detected": sum(f.status.value == "detected" for f in found),
            "findings_need_review": sum(f.status.value == "needs_review" for f in found),
            "findings_saved": saved, "held_back_needs_opt_in": held_back}
