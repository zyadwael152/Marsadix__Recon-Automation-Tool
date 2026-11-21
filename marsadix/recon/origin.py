"""
Origin IP discovery: the real server behind a CDN / WAF.

Two steps.

1. Candidates
     * hosts of the same scan that resolve to a public IP outside any CDN
       (mail., ftp., old. ... often skip the CDN)                        every mode, no traffic
     * the addresses of the MX hosts and the ip4:/ip6: parts of the SPF
       record (one DNS query through dnsx)                                active mode
     * the other addresses of the /24 around the target's own non-CDN hosts, tested by
       hakoriginfinder (no API key; it compares what each address answers for the target's
       name with the public site)                                        active mode
2. Verification (active mode only): one request to https://<ip>/ (then http://) with the
   target's name as SNI and Host header, compared with what the CDN-fronted site answers. An IP
   is "verified" when the status is not an error and the page has the same title, the same body or
   the same redirect. Nothing else is sent to a candidate.

A candidate is evidence, not proof: only "verified" ones are drawn in the graph.
"""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import logging
import re
import socket
import ssl
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..core import netguard
from ..core.runner import ToolNotFound, parse_json_lines, run_tool

logger = logging.getLogger(__name__)

MAX_CANDIDATES = 15           # addresses that are verified
MAX_RANGES = 2                # /24 ranges handed to hakoriginfinder
MAX_VERIFY_HOSTS = 3          # CDN-fronted host names compared against them
MAX_BODY = 256 * 1024
REQUEST_TIMEOUT = 6.0
ENDPOINTS = ((443, True), (80, False))        # (port, tls) tried in this order
USER_AGENT = "Marsadix-origin-check"
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


# ------------------------------------------------------------------ candidates
def parse_spf_ips(txt_records: Iterable[str]) -> Set[str]:
    """Single addresses named by ip4:/ip6: in an SPF record. Ranges are ignored on purpose."""
    out: Set[str] = set()
    for record in txt_records or []:
        record = str(record).strip().strip('"')
        if not record.lower().startswith("v=spf1"):
            continue
        for token in record.split():
            m = re.match(r"(?i)^[+]?ip[46]:(.+)$", token)
            if not m:
                continue
            try:
                net = ipaddress.ip_network(m.group(1), strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                out.add(str(net.network_address))
    return out


def lookup_dns_records(target: str) -> Tuple[List[str], List[str]]:
    """([TXT strings], [MX host names]) of the target, through dnsx. ([], []) when dnsx is missing."""
    try:
        res = run_tool(["dnsx", "-silent", "-json", "-txt", "-mx", "-resp"],
                       timeout=60, input_text=target + "\n")
    except ToolNotFound:
        logger.info("[-] dnsx is not installed - SPF/MX origin candidates skipped.")
        return [], []
    txt: List[str] = []
    mx: List[str] = []
    for rec in parse_json_lines(res.stdout):
        txt += [str(v) for v in rec.get("txt") or []]
        for v in rec.get("mx") or []:
            parts = str(v).split()
            if parts:
                mx.append(parts[-1].rstrip(".").lower())
    return txt, sorted(set(mx))


def resolve_ipv4(hosts: Iterable[str], limit: int = 10) -> Dict[str, Set[str]]:
    """{host: {ips}} through the system resolver (a plain DNS query, nothing is sent to the host)."""
    out: Dict[str, Set[str]] = {}
    for host in list(dict.fromkeys(hosts))[:limit]:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            continue
        ips = {info[4][0] for info in infos}
        if ips:
            out[host] = ips
    return out


def sibling_candidates(active_results: dict, cdn_asn_info: dict, skip_ips: Set[str]) -> Dict[str, Set[str]]:
    """Public, non-CDN addresses of the other hosts found in this scan."""
    out: Dict[str, Set[str]] = {}
    for host, info in sorted(active_results.items()):
        ips = info.get("ips") or ([info["ip"]] if info.get("ip") else [])
        for ip in ips:
            if ip in skip_ips or (cdn_asn_info.get(ip) or {}).get("is_cdn"):
                continue
            out.setdefault(ip, set()).add(f"sibling:{host}")
    return out


def neighbour_ips(sibling_ips: Iterable[str], exclude: Iterable[str] = (), max_ranges: int = MAX_RANGES):
    """([networks], [addresses]): the /24 around each IPv4 address, at most `max_ranges` of them."""
    exclude = set(exclude)
    nets: list = []
    for ip in sorted(sibling_ips):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version != 4:
            continue
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        if net not in nets:
            nets.append(net)
        if len(nets) >= max_ranges:
            break
    return nets, [str(h) for net in nets for h in net.hosts() if str(h) not in exclude]


def parse_hakoriginfinder(text: str) -> List[Tuple[str, str, str]]:
    """[(ip, url, distance)] for the MATCH lines of hakoriginfinder ("MATCH https://1.2.3.4:443/ 0")."""
    out: List[Tuple[str, str, str]] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "MATCH":
            continue
        try:
            ip = str(ipaddress.ip_address(urllib.parse.urlsplit(parts[1]).hostname or ""))
        except ValueError:
            continue
        out.append((ip, parts[1], parts[2] if len(parts) > 2 and parts[2].isdigit() else ""))
    return out


def run_hakoriginfinder(host: str, ips: List[str], threads: int = 16, timeout: int = 300):
    """[(ip, url, distance)] for the addresses that answer like the public site; None when the tool is missing."""
    if not ips:
        return []
    try:
        res = run_tool(["hakoriginfinder", "-h", f"https://{host}/", "-p", "80,443", "-t", str(threads)],
                       timeout=timeout, input_text="\n".join(ips) + "\n")
    except ToolNotFound:
        logger.info("[-] hakoriginfinder is not installed - the range check was skipped.")
        return None
    return parse_hakoriginfinder(res.stdout)


# ---------------------------------------------------------------- verification
def _title(body: bytes) -> str:
    m = _TITLE.search(body[:65536])
    return re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:200] if m else ""


def _fetch(connect_to: str, host: str, port: int, tls: bool, timeout: float = REQUEST_TIMEOUT):
    """One GET / with `host` as Host header (and SNI). (status, headers, body) or None. Redirects are not followed."""
    try:
        sock = socket.create_connection((connect_to, port), timeout=timeout)
    except OSError:
        return None
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False               # we compare pages, we do not trust the certificate
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii", "ignore"))
        resp = http.client.HTTPResponse(sock)
        resp.begin()
        body = resp.read(MAX_BODY)
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def same_site(reference, got) -> Optional[str]:
    """Why `got` looks like the same site as `reference` (both from _fetch), or None."""
    if not reference or not got:
        return None
    (rs, rh, rb), (gs, gh, gb) = reference, got
    if rs != gs or rs >= 400:                        # two identical default error pages prove nothing
        return None
    if rb and rb == gb:
        return "identical body"
    title = _title(rb)
    if title and title == _title(gb):
        return f"same status {gs} and title {title!r}"
    if 300 <= rs < 400 and rh.get("location") and rh.get("location") == gh.get("location"):
        return f"same redirect to {rh['location']}"
    return None


def verify_candidates(host: str, ips: List[str], timeout: float = REQUEST_TIMEOUT, workers: int = 4,
                      endpoints=ENDPOINTS, reference_address: Optional[str] = None) -> List[dict]:
    """[{"ip", "verified", "evidence"}] for every ip. `reference_address`: where the public site is fetched from (default: DNS)."""
    refs = {(port, tls): _fetch(reference_address or host, host, port, tls, timeout) for port, tls in endpoints}

    def check(ip: str) -> dict:
        for port, tls in endpoints:
            ref = refs[(port, tls)]
            if not ref:
                continue
            reason = same_site(ref, _fetch(ip, host, port, tls, timeout))
            if reason:
                scheme = "https" if tls else "http"
                return {"ip": ip, "verified": True,
                        "evidence": f"{scheme}://{ip}:{port}/ answered like {scheme}://{host}/ ({reason})"}
        return {"ip": ip, "verified": False, "evidence": ""}

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ips) or 1)),
                            thread_name_prefix="origin") as pool:
        return list(pool.map(check, ips))


# ------------------------------------------------------------------- top level
def discover_origin(target: str, active_results: dict, cdn_asn_info: dict, *,
                    host_ok: Optional[Callable[[str], bool]] = None, verify: bool = False,
                    lookup_dns: bool = False, scan_ranges: bool = False,
                    timeout: float = REQUEST_TIMEOUT, max_candidates: int = MAX_CANDIDATES) -> List[dict]:
    """
    Rows for db.save_origin_ips: [{"host", "ip", "source", "verified", "evidence"}].
    Nothing happens unless at least one host of the scan is behind a CDN.
    """
    host_ok = host_ok or (lambda h: True)
    fronted = sorted(h for h, info in active_results.items()
                     if host_ok(h) and (cdn_asn_info.get(info.get("ip")) or {}).get("is_cdn"))
    if not fronted:
        logger.info("[*] Origin IP: no host is behind a CDN, nothing to look for.")
        return []
    names = ([target] if target in fronted else []) + [h for h in fronted if h != target]
    names = names[:MAX_VERIFY_HOSTS]
    skip_ips = {ip for h in fronted for ip in (active_results[h].get("ips") or [active_results[h].get("ip")]) if ip}

    cand = sibling_candidates(active_results, cdn_asn_info, skip_ips)
    if lookup_dns:
        txt, mx = lookup_dns_records(target)
        for ip in parse_spf_ips(txt):
            cand.setdefault(ip, set()).add("spf")
        for mx_host, ips in resolve_ipv4(mx).items():
            for ip in ips:
                cand.setdefault(ip, set()).add(f"mx:{mx_host}")

    cand = {ip: src for ip, src in cand.items()
            if ip not in skip_ips and netguard.blocked_reason(ip, None) is None}
    unknown = sorted(ip for ip in cand if ip not in cdn_asn_info)
    if unknown:                                       # addresses from SPF / MX: is it a CDN edge?
        from .cdn_asn import lookup_cdn_asn
        info = asyncio.run(lookup_cdn_asn(unknown))
        cand = {ip: src for ip, src in cand.items() if not (info.get(ip) or {}).get("is_cdn")}
    ordered = sorted(cand, key=lambda ip: (-len(cand[ip]), ip))[:max_candidates]
    if not ordered:
        logger.info("[*] Origin IP: no candidate address found.")
        return []
    logger.info("[*] Origin IP: %d candidate address(es) for %s.", len(ordered), ", ".join(names))

    rows: List[dict] = []
    if not verify:
        logger.info("[*] Origin IP: candidates are not verified (verification needs --mode active).")
        for ip in ordered:
            rows.append({"host": names[0], "ip": ip, "source": ",".join(sorted(cand[ip])),
                         "verified": False, "evidence": ""})
        return rows

    for name in names:
        for res in verify_candidates(name, ordered, timeout=timeout):
            if res["verified"]:
                logger.info("[+] Origin IP verified: %s serves %s (%s)", res["ip"], name, ",".join(sorted(cand[res["ip"]])))
                rows.append({"host": name, "ip": res["ip"], "source": ",".join(sorted(cand[res["ip"]])),
                             "verified": True, "evidence": res["evidence"]})
            elif name == names[0]:
                rows.append({"host": name, "ip": res["ip"], "source": ",".join(sorted(cand[res["ip"]])),
                             "verified": False, "evidence": ""})

    if scan_ranges:
        siblings = {ip for ip, src in cand.items() if any(x.startswith("sibling:") for x in src)}
        nets, neighbours = neighbour_ips(siblings, exclude=skip_ips)
        if neighbours:
            logger.info("[*] Origin IP: hakoriginfinder on %s (%d address(es)).",
                        ", ".join(str(n) for n in nets), len(neighbours))
            matches = run_hakoriginfinder(names[0], neighbours)
            by_key = {(r["host"], r["ip"]): r for r in rows}
            for ip, url, distance in matches or []:
                net = next((str(n) for n in nets if ipaddress.ip_address(ip) in n), "")
                evidence = f"hakoriginfinder: {url} answered like the public site (distance {distance or '?'})"
                row = by_key.get((names[0], ip))
                if row is None:
                    row = {"host": names[0], "ip": ip, "source": f"range:{net}", "verified": True, "evidence": evidence}
                    rows.append(row)
                    by_key[(names[0], ip)] = row
                elif not row["verified"]:
                    row.update(verified=True, evidence=evidence, source=row["source"] + f",range:{net}")
                if row["evidence"] == evidence:
                    logger.info("[+] Origin IP verified: %s serves %s (%s)", ip, names[0], row["source"])
    if not any(r["verified"] for r in rows):
        logger.info("[-] Origin IP: none of the candidates answered like the public site.")
    return rows
