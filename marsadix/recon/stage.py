import asyncio
import dataclasses
import logging
from .discovery import discover_subdomains
from .resolver import filter_active_subdomains
from .coverage import log_missing_asset_hunter
from .confidence import compute_source_confidence
from .cdn_asn import lookup_cdn_asn
from .permutation import generate_permutations
from .bruteforce import bruteforce_subdomains
from .revdns import reverse_dns_lookup          # R15
from .vhost import discover_vhosts              # R16
from .. import db
from ..models import Asset, DiscoverySource
from ..core import netguard

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
        raise ValueError("Recon stage requires an explicit target; refusing to scan a fallback domain.")

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

    # 1. Discover subdomains (R1-R3 & R12 Recursion) 🆕
    max_depth = getattr(cfg, "max_depth", 1) # Default depth is 1
    raw_results = discover_subdomains(target, api_keys, max_depth=max_depth)

    # 2. R5 + R6: Permutations and Bruteforce
    if allows_std:
        raw_results = asyncio.run(_expand_candidates(ctx, target, raw_results))
    else:
        logger.info("[-] Skipping permutations / DNS bruteforce (passive mode).")

    # 3. R7: Resolve
    active_results = asyncio.run(
        filter_active_subdomains(raw_results, domain=target, rate_limit=dns_rate))

    if not (hasattr(ctx, "conn") and hasattr(ctx, "scan")):
        return {"subdomains": {host: info["sources"] for host, info in active_results.items()}, "web": {}}

    scan_id = ctx.scan.id
    sources_by_host = {host: info["sources"] for host, info in active_results.items()}
    confidence_scores = compute_source_confidence(sources_by_host)

    # Third-party ASN lookups must never receive private, loopback, link-local,
    # reserved, or otherwise non-public IPs. The explicit scan scope does not
    # make it appropriate to disclose internal addresses to Team Cymru.
    unique_ips = {info["ip"] for info in active_results.values() if info.get("ip")}
    public_ips = {ip for ip in unique_ips if netguard.blocked_reason(ip, None) is None}
    cdn_asn_info = asyncio.run(lookup_cdn_asn(public_ips)) if public_ips else {}

    # Reverse DNS is limited to public IPs and PTR names are only accepted after
    # forward-confirmation to the same IP, preventing forged PTR records from
    # being promoted into the asset inventory.
    ptr_hosts = asyncio.run(reverse_dns_lookup(sorted(public_ips), dns_rate)) if public_ips else set()
    ptr_candidates = {host: ["ptr"] for host in ptr_hosts if host_ok(host)}
    if ptr_candidates:
        ptr_resolved = asyncio.run(
            filter_active_subdomains(ptr_candidates, domain=target, rate_limit=dns_rate))
        for host, info in ptr_resolved.items():
            matched_ips = sorted(set(info.get("ips", [])) & public_ips)
            if matched_ips and host not in active_results:
                active_results[host] = {
                    "sources": ["ptr"], "ip": matched_ips[0],
                    "ips": matched_ips, "cname": info.get("cname", []),
                }
                sources_by_host[host] = ["ptr"]
                confidence_scores[host] = compute_source_confidence({host: ["ptr"]})[host]

    assets = []
    for host, info in active_results.items():
        ip = info.get("ip")
        extra = cdn_asn_info.get(ip, {}) if ip else {}
        source_names = set(info.get("sources", []))
        if source_names & {"puredns", "wordlist", "bruteforce"}:
            source_kind = DiscoverySource.BRUTEFORCE
        elif source_names & {"alterx", "permutation", "dnsgen"}:
            source_kind = DiscoverySource.PERMUTATION
        elif source_names & {"ptr", "ffuf-vhost"}:
            source_kind = DiscoverySource.ACTIVE
        else:
            source_kind = DiscoverySource.PASSIVE
        assets.append(Asset(
            scan_id=scan_id, host=host, ip=ip, in_scope=host_ok(host),
            source=source_kind, confidence_score=confidence_scores.get(host, 0),
            is_cdn=extra.get("is_cdn", False),
            cdn_name=extra.get("asn_owner") if extra.get("is_cdn") else None,
            asn=extra.get("asn"), asn_owner=extra.get("asn_owner"),
        ))

    saved = db.save_many(ctx.conn, "assets", assets)
    logger.info("[+] Saved %d assets for scan #%s", saved, scan_id)
    for host, info in active_results.items():
        db.save_asset_sources_many(ctx.conn, scan_id, host, info["sources"])

    # VHost discovery remains here because it depends on the resolved IPs from
    # recon, but it is stored as asset evidence instead of silently discarded.
    # Port scanning and HTTP probing are owned by their dedicated pipeline stages
    # to avoid duplicate requests in --mode full.
    if allows_std and wordlist:
        non_cdn_public_ips = sorted({
            info["ip"] for host, info in active_results.items()
            if info.get("ip") and host_ok(host)
            and info["ip"] in public_ips
            and not cdn_asn_info.get(info["ip"], {}).get("is_cdn", False)
        })
        vhost_assets = []
        for ip in non_cdn_public_ips:
            try:
                vhosts = asyncio.run(discover_vhosts(ip, target, wordlist, rate_limit))
            except Exception as e:
                logger.warning("[-] VHost discovery failed for %s: %s", ip, e)
                continue
            for candidate in sorted(vhosts):
                if not host_ok(candidate) or candidate in active_results:
                    continue
                active_results[candidate] = {"sources": ["ffuf-vhost"], "ip": ip, "ips": [ip], "cname": []}
                vhost_assets.append(Asset(
                    scan_id=scan_id, host=candidate, ip=ip, in_scope=True,
                    source=DiscoverySource.ACTIVE, confidence_score=50,
                    is_cdn=False, cdn_name=None, asn=cdn_asn_info.get(ip, {}).get("asn"),
                    asn_owner=cdn_asn_info.get(ip, {}).get("asn_owner"),
                ))
        if vhost_assets:
            db.save_many(ctx.conn, "assets", vhost_assets)
            for asset in vhost_assets:
                db.save_asset_sources_many(ctx.conn, scan_id, asset.host, ["ffuf-vhost"])

    log_missing_asset_hunter(ctx.conn, scan_id)

    return {
        "subdomains": {host: info["sources"] for host, info in active_results.items()},
        "web": {},
    }
