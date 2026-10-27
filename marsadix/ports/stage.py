"""
Ports stage: which ports are open on each in-scope host, and what runs on them.

    passive   -> skipped: scanning ports sends traffic to the target
    standard  -> naabu: open ports among the top 100; service NAME is only the
                 registered name of that port number (a guess, no banner was read;
                 see services.py)
    full      -> + nmap -sV on the open ports: product, version, banner, CPE
                 (read from the service itself); products also become
                 technologies so the CVE monitor can match them

Rules this stage follows:
  * only hosts that are in scope (the stored flag AND the scope rules);
  * hosts httpx found behind a CDN/WAF are not port-scanned: the ports belong
    to the CDN, not to the target;
  * only PUBLIC addresses (core/netguard.py): an in-scope NAME can be made to
    resolve to 127.0.0.1, 10.x or 169.254.169.254, which would turn the scan
    against the tester's own machine/network. An internal range is scanned only
    when the scope file lists it explicitly;
  * naabu is given the IP addresses, not the names. If it resolved the names
    itself, the address it scanned could differ from the one checked above (the
    DNS answer can change between the two lookups);
  * the scan's rate limit is passed to both tools;
  * a missing tool makes the stage "skipped" with the reason, never a crash.
"""

import ipaddress
import logging
from typing import Optional

from .. import db
from ..core import netguard
from ..core.runner import ToolNotFound
from ..models import Confidence, Service, Technology
from ..web import fingerprint
from .probe import run_naabu, run_nmap
from .services import port_name

logger = logging.getLogger(__name__)


def _valid_ip(value) -> Optional[str]:
    """
    The IP comes out of a tool's JSON and is later passed to nmap as a command
    line argument. Only a real IP address is allowed through, so a value such
    as "-oN /tmp/x" can never become an nmap option.
    """
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def run(ctx, *args, **kwargs) -> dict:
    logger.info("=== Starting Ports stage (mode: %s) ===", ctx.mode)

    if not ctx.allows("standard"):
        reason = (f"mode '{ctx.mode}' makes no contact with the target "
                  f"(use --mode standard or full to scan ports)")
        logger.info("[-] Ports stage skipped: %s", reason)
        return {"skipped": reason}

    scan_id = ctx.scan.id
    assets = db.get_assets(ctx.conn, scan_id)
    in_scope = [a for a in assets if a["in_scope"] and ctx.in_scope(a["host"])]
    behind_cdn = {a["host"] for a in assets if a["is_cdn"]}

    host_ip: dict = {}                 # host -> the (public, checked) IP that will be scanned
    n_cdn, no_ip, blocked = 0, [], []
    for a in sorted(in_scope, key=lambda r: r["host"]):
        host = a["host"]
        if host in behind_cdn:
            n_cdn += 1
            continue
        ip = netguard.asset_ip(a)
        if not ip:
            no_ip.append(host)
            continue
        why = netguard.blocked_reason(ip, ctx.scope)
        if why:
            blocked.append(host)
            logger.warning("[!] %s resolves to %s (%s): not scanned. If this is an authorised "
                           "internal test, list the address or range in the scope file.", host, ip, why)
            continue
        host_ip[host] = ip
    if n_cdn:
        logger.info("[*] %d host(s) behind a CDN/WAF are not port-scanned", n_cdn)
    if no_ip:
        logger.info("[*] %d host(s) have no resolved IP and are not port-scanned", len(no_ip))

    base = {"blocked": len(blocked), "no_ip": len(no_ip)}
    if not host_ip:
        logger.info("[-] No in-scope hosts to scan.")
        return {"hosts": 0, "open_ports": 0, "services": 0, "technologies": 0, **base}

    rate = ctx.scan.rate_limit or ctx.config.rate_limit
    timeout = ctx.config.tool_timeout
    unique_ips = sorted(set(host_ip.values()))          # one scan per address, however many names share it
    try:
        found = run_naabu(unique_ips, rate, timeout)
    except ToolNotFound as e:
        logger.warning("[-] Ports stage skipped: %s", e)
        return {"skipped": str(e)}

    # naabu answers by the IP it was given (it prints no "host" key for an IP input)
    ports_by_ip: dict = {}
    for key, entry in found.items():
        ip = _valid_ip(key) or _valid_ip(entry.get("ip"))
        if ip and entry["ports"]:
            ports_by_ip.setdefault(ip, set()).update(entry["ports"])

    ports = {h: sorted(ports_by_ip[ip]) for h, ip in host_ip.items() if ip in ports_by_ip}
    ips = {h: host_ip[h] for h in ports}
    for host, ip in ips.items():
        db.update_asset_network(ctx.conn, scan_id, host, ip=ip)

    # ---- full mode: ask each distinct IP's open ports what they are running
    details: dict = {}               # (ip, port) -> nmap record
    nmap_note = None
    if ports and ctx.allows("full"):
        try:
            for ip, plist in sorted(ports_by_ip.items()):
                if ip not in ips.values():
                    continue
                for rec in run_nmap(ip, sorted(plist), rate, timeout):
                    details[(ip, rec["port"])] = rec
        except ToolNotFound as e:
            nmap_note = str(e)
            logger.warning("[-] Service detection skipped: %s (keeping port names only)", e)
    elif ports:
        logger.info("[*] Service/version detection skipped: nmap only runs in --mode full")

    services, technologies = [], []
    for host, plist in sorted(ports.items()):
        for port in plist:
            d = details.get((ips.get(host), port))
            services.append(Service(
                scan_id=scan_id, host=host, port=port, ip=ips.get(host), protocol="tcp",
                name=(d or {}).get("name") or port_name(port),
                product=(d or {}).get("product"),
                version=(d or {}).get("version"),
                banner=(d or {}).get("extrainfo"),          # nmap's "extra info" column, e.g. "Ubuntu Linux; protocol 2.0"
                cpe=fingerprint.normalize_cpe(next(iter((d or {}).get("cpe") or []), None))))
            if d and d.get("product"):
                cpe = (fingerprint.normalize_cpe(next(iter(d.get("cpe") or []), None))
                       or fingerprint.cpe_for(d["product"], d.get("version")))
                technologies.append(Technology(
                    scan_id=scan_id, host=host, name=d["product"], version=d.get("version"),
                    cpe=cpe, category="service", source="nmap",
                    confidence=Confidence.LIKELY if d.get("version") else Confidence.POSSIBLE))

    n_services = db.save_many(ctx.conn, "services", services)
    n_tech = db.save_many(ctx.conn, "technologies", technologies)
    logger.info("[+] %d open port(s) on %d host(s); stored %d service(s), %d technology record(s)",
                sum(len(p) for p in ports.values()), len(ports), n_services, n_tech)

    out = {"hosts": len(host_ip), "open_ports": sum(len(p) for p in ports.values()),
           "services": n_services, "technologies": n_tech, **base}
    if nmap_note:
        out["note"] = nmap_note
    return out
