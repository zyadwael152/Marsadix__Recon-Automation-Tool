import asyncio
import dataclasses
import logging
from .discovery import discover_subdomains
from .resolver import filter_active_subdomains
from .coverage import log_missing_asset_hunter
from .confidence import compute_source_confidence
from .cdn_asn import lookup_cdn_asn
from .portscan import run_naabu, run_nmap
from .permutation import generate_permutations
from .bruteforce import bruteforce_subdomains
from .webprobe import probe_web
from .. import db
from ..models import Asset, DiscoverySource, Service, Technology

logger = logging.getLogger(__name__)


def _extract_api_keys(ctx) -> dict:
    """
    Pull the recon API keys out of the real pipeline Context (ctx.config has
    individual fields like virustotal_api_key, not a `.keys` dict - the old
    code checked `ctx.cfg.keys`, which never matched the real Context
    (attribute is `config`, not `cfg`) and silently returned {} every time,
    which is why VirusTotal/chaos always showed "No API Key provided" even
    after adding keys to config.toml).
    """
    cfg = getattr(ctx, "config", None)
    if cfg is not None:
        return {
            "virustotal": getattr(cfg, "virustotal_api_key", "") or None,
            "chaos": getattr(cfg, "chaos_api_key", "") or None,
            "alienvault": getattr(cfg, "otx_api_key", "") or None,
            "securitytrails": getattr(cfg, "securitytrails_api_key", "") or None,
            "shodan": getattr(cfg, "shodan_api_key", "") or None,
            "censys": getattr(cfg, "censys_api_key", "") or None,
        }
    # fallback for tests/callers that pass a plain dict context
    if isinstance(ctx, dict) and "config" in ctx:
        c = ctx["config"]
        get = (lambda k: c.get(k)) if isinstance(c, dict) else (lambda k: getattr(c, k, None))
        return {
            "virustotal": get("virustotal_api_key"),
            "chaos": get("chaos_api_key"),
            "alienvault": get("otx_api_key"),
            "securitytrails": get("securitytrails_api_key"),
            "shodan": get("shodan_api_key"),
            "censys": get("censys_api_key"),
        }
    return {}


def _make(cls, **kw):
    """
    Build a model object from whichever of `kw` its fields actually have, so
    this file doesn't break if models.Technology names a field differently.
    Adjust the keys passed below to match models.py if something is dropped.
    """
    fields = None
    if dataclasses.is_dataclass(cls):
        fields = {f.name for f in dataclasses.fields(cls)}
    elif hasattr(cls, "model_fields"):          # pydantic v2
        fields = set(cls.model_fields)
    if fields is not None:
        kw = {k: v for k, v in kw.items() if k in fields}
    return cls(**kw)


async def _expand_candidates(ctx, target: str, raw_results: dict) -> dict:
    """
    R5 (permutations) + R6 (DNS bruteforce). Adds NEW candidate hosts to the
    passive results, tagged with the engine that produced them. Every
    candidate must pass ctx.in_scope before it's even resolved. Resolution and
    wildcard filtering happen afterwards in filter_active_subdomains (R7).
    """
    cfg = getattr(ctx, "config", None)
    max_perm = getattr(cfg, "max_permutations", None) or 20000
    wordlist = getattr(cfg, "bruteforce_wordlist", None) or None
    resolvers = getattr(cfg, "resolvers_file", None) or None
    dns_rate = getattr(cfg, "dns_rate_limit", None) or None
    in_scope = getattr(ctx, "in_scope", None)

    expanded = {host: list(sources) for host, sources in raw_results.items()}

    def add(hosts, source):
        for host in hosts:
            if callable(in_scope) and not in_scope(host):
                continue
            sources = expanded.setdefault(host, [])
            if source not in sources:
                sources.append(source)

    before = len(expanded)
    perms, engine = await generate_permutations(list(raw_results), target, max_perm)
    add(perms, engine)

    found, engine = await bruteforce_subdomains(target, wordlist, resolvers, dns_rate)
    add(found, engine)

    logger.info(f"[+] R5/R6 added {len(expanded) - before} new candidate host(s) to resolve.")
    return expanded


def run(ctx, *args, **kwargs) -> dict:
    if hasattr(ctx, "target"):
        target = ctx.target
    elif isinstance(ctx, dict) and "target" in ctx:
        target = ctx["target"]
    else:
        target = "example.com"

    api_keys = _extract_api_keys(ctx)
    cfg = getattr(ctx, "config", None)
    in_scope = getattr(ctx, "in_scope", None)
    allows = getattr(ctx, "allows", None)
    allows_std = callable(allows) and allows("standard")
    rate_limit = getattr(cfg, "rate_limit", None)
    dns_rate = getattr(cfg, "dns_rate_limit", None) or None

    def host_ok(host):
        return in_scope(host) if callable(in_scope) else True

    logger.info(f"=== Starting Recon stage for target: {target} ===")

    # 1. Discover subdomains from all passive tools and sources (R1-R3)
    raw_results = discover_subdomains(target, api_keys)

    # 2. R5 + R6: permutations and DNS bruteforce. Both send DNS traffic, so
    #    they only run when the scan mode allows contacting the target -
    #    passive scans skip them, same as the port scan below.
    if allows_std:
        raw_results = asyncio.run(_expand_candidates(ctx, target, raw_results))
    else:
        logger.info("[-] Skipping permutations / DNS bruteforce (passive mode).")

    # 3. R7: resolve everything (dnsx) and drop wildcard-only generated hosts
    active_results = asyncio.run(
        filter_active_subdomains(raw_results, domain=target, rate_limit=dns_rate))

    # 4. Persist each host as an Asset, and record which sources found it as
    #    AssetSource rows (R3 wiring + R4 confidence data). Without this,
    #    nothing ever lands in the DB, so the "track" stage always sees 0
    #    assets for every scan and reports it as a fresh baseline forever.
    web_info = {}
    if hasattr(ctx, "conn") and hasattr(ctx, "scan"):
        scan_id = ctx.scan.id

        # R8: ONE httpx pass gives HTTP liveness (feeds R4) and technologies.
        # In-scope hosts only, and never in passive mode.
        sources_by_host = {host: info["sources"] for host, info in active_results.items()}
        if allows_std:
            probe_hosts = [h for h in active_results if host_ok(h)]
            web_info = asyncio.run(probe_web(probe_hosts, rate_limit))
        # R4: sources + resolved (+ HTTP liveness when we were allowed to check)
        confidence_scores = compute_source_confidence(sources_by_host, web_info.keys())

        # R9: CDN/ASN - one bulk lookup for every unique IP, not one per host
        unique_ips = {info["ip"] for info in active_results.values() if info.get("ip")}
        cdn_asn_info = asyncio.run(lookup_cdn_asn(unique_ips))

        assets = []
        for host, info in active_results.items():
            ip = info.get("ip")
            extra = cdn_asn_info.get(ip, {}) if ip else {}
            assets.append(Asset(
                scan_id=scan_id,
                host=host,
                ip=ip,
                in_scope=host_ok(host),
                source=DiscoverySource.PASSIVE,
                confidence_score=confidence_scores.get(host, 0),
                is_cdn=extra.get("is_cdn", False),
                cdn_name=extra.get("asn_owner") if extra.get("is_cdn") else None,
                asn=extra.get("asn"),
                asn_owner=extra.get("asn_owner"),
            ))

        saved = db.save_many(ctx.conn, "assets", assets)
        logger.info(f"[+] Saved {saved} assets for scan #{scan_id}")

        for host, info in active_results.items():
            db.save_asset_sources_many(ctx.conn, scan_id, host, info["sources"])

        # R8: store detected technologies (never lets a model mismatch kill recon)
        techs = [
            _make(Technology, scan_id=scan_id, host=host, name=name, version=version,
                  url=web.get("url"), source="httpx")
            for host, web in web_info.items() for name, version in web["tech"]
        ]
        if techs:
            try:
                saved_techs = db.save_many(ctx.conn, "technologies", techs)
                logger.info(f"[+] Saved {saved_techs} technolog(ies) for scan #{scan_id}")
            except Exception as e:
                logger.warning(f"[-] Could not save technologies: {e}")

        # R10 + R11: port scan + service/version/CPE. Both send real traffic
        # to the target, so only run them when the scan mode allows it.
        if allows_std:
            # Only IPs of IN-SCOPE hosts, and never CDN edges.
            non_cdn_ips = sorted({
                info["ip"] for host, info in active_results.items()
                if info.get("ip") and host_ok(host)
                and not cdn_asn_info.get(info["ip"], {}).get("is_cdn", False)
            })

            host_ports = asyncio.run(run_naabu(non_cdn_ips, rate_limit))
            nmap_results = asyncio.run(run_nmap(host_ports))

            services = []
            for ip, ports in host_ports.items():
                nmap_by_port = {e["port"]: e for e in nmap_results.get(ip, [])}
                for port in ports:
                    svc = nmap_by_port.get(port, {})
                    services.append(Service(
                        scan_id=scan_id,
                        host=ip,
                        ip=ip,
                        port=port,
                        name=svc.get("service"),
                        product=svc.get("product"),
                        version=svc.get("version"),
                        cpe=svc.get("cpe"),
                    ))

            if services:
                saved_services = db.save_many(ctx.conn, "services", services)
                logger.info(f"[+] Saved {saved_services} service(s) for scan #{scan_id}")
        else:
            logger.info("[-] Skipping port scan / nmap (passive mode - no traffic to target).")

        # R17: Missing Asset Hunter - per-source coverage + single-source hosts
        log_missing_asset_hunter(ctx.conn, scan_id)

    return {
        "subdomains": {host: info["sources"] for host, info in active_results.items()},
        "web": web_info,
    }
