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
from .revdns import reverse_dns_lookup          # 🆕 R15 Import
from .vhost import discover_vhosts              # 🆕 R16 Import
from .. import db
from ..models import Asset, DiscoverySource, Service, Technology

logger = logging.getLogger(__name__)


def _extract_api_keys(ctx) -> dict:
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
    fields = None
    if dataclasses.is_dataclass(cls):
        fields = {f.name for f in dataclasses.fields(cls)}
    elif hasattr(cls, "model_fields"):
        fields = set(cls.model_fields)
    if fields is not None:
        kw = {k: v for k, v in kw.items() if k in fields}
    return cls(**kw)


async def _expand_candidates(ctx, target: str, raw_results: dict) -> dict:
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
    wordlist = getattr(cfg, "bruteforce_wordlist", None) or None

    def host_ok(host):
        return in_scope(host) if callable(in_scope) else True

    logger.info(f"=== Starting Recon stage for target: {target} ===")

    # 1. Discover subdomains (R1-R3)
    raw_results = discover_subdomains(target, api_keys)

    # 2. R5 + R6: Permutations and Bruteforce
    if allows_std:
        raw_results = asyncio.run(_expand_candidates(ctx, target, raw_results))
    else:
        logger.info("[-] Skipping permutations / DNS bruteforce (passive mode).")

    # 3. R7: Resolve
    active_results = asyncio.run(
        filter_active_subdomains(raw_results, domain=target, rate_limit=dns_rate))

    web_info = {}
    if hasattr(ctx, "conn") and hasattr(ctx, "scan"):
        scan_id = ctx.scan.id

        sources_by_host = {host: info["sources"] for host, info in active_results.items()}
        if allows_std:
            probe_hosts = [h for h in active_results if host_ok(h)]
            web_info = asyncio.run(probe_web(probe_hosts, rate_limit))
        
        confidence_scores = compute_source_confidence(sources_by_host, web_info.keys())

        # 4. CDN & ASN (R9)
        unique_ips = {info["ip"] for info in active_results.values() if info.get("ip")}
        cdn_asn_info = asyncio.run(lookup_cdn_asn(unique_ips))

        # 🆕 5. R15: Reverse DNS on discovered IPs
        ptr_hosts = asyncio.run(reverse_dns_lookup(list(unique_ips), dns_rate))
        for host in ptr_hosts:
            if host_ok(host) and host not in active_results:
                # Add PTR findings to our active results
                active_results[host] = {"sources": ["ptr"], "ip": None, "ips": [], "cname": []}
                confidence_scores[host] = 50 # Default confidence for PTR

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

        techs = [
            _make(Technology, scan_id=scan_id, host=host, name=name, version=version,
                  url=web.get("url"), source="httpx")
            for host, web in web_info.items() for name, version in web["tech"]
        ]
        if techs:
            try:
                db.save_many(ctx.conn, "technologies", techs)
            except Exception as e:
                logger.warning(f"[-] Could not save technologies: {e}")

        # 6. Port Scan & Nmap & VHost (Active techniques)
        if allows_std:
            non_cdn_ips = sorted({
                info["ip"] for host, info in active_results.items()
                if info.get("ip") and host_ok(host)
                and not cdn_asn_info.get(info["ip"], {}).get("is_cdn", False)
            })

            # 🆕 R16: VHost Discovery on non-CDN IPs
            if wordlist:
                for ip in non_cdn_ips:
                    # Run VHost fuzzing asynchronously
                    vhosts = asyncio.run(discover_vhosts(ip, target, wordlist, rate_limit))
                    # You could save vhosts to the database here if needed!
            
            # Port Scanning
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
                db.save_many(ctx.conn, "services", services)
        else:
            logger.info("[-] Skipping port scan / vhost / nmap (passive mode).")

        # R17: Missing Asset Hunter
        log_missing_asset_hunter(ctx.conn, scan_id)

    return {
        "subdomains": {host: info["sources"] for host, info in active_results.items()},
        "web": web_info,
    }
