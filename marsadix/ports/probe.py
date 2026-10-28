"""
Port scanning (naabu) and service/version detection (nmap).

Both go through core.runner.run_tool: no shell, always a timeout, and a
missing tool raises ToolNotFound for the caller to report instead of crashing.
The parsers are separate pure functions so they can be tested without either
tool installed.
"""

import logging
# Parses local nmap output only; entity declarations are rejected below.
import xml.etree.ElementTree as ET  # nosec B405
from typing import Optional

from ..core.runner import parse_json_lines, run_tool

log = logging.getLogger(__name__)

TOP_PORTS = 100          # naabu's own "top 100" list


def parse_naabu(text: str) -> dict:
    """
    naabu JSON lines -> {host_or_ip: {"ip": str|None, "ports": [int, ...]}}.

    The JSON has a "host" key only when the input was a hostname; for an IP
    input only "ip" is present, so that is the key then. naabu also reports the
    same open port more than once (its verification pass): ports are de-duplicated.
    """
    out: dict = {}
    for rec in parse_json_lines(text):
        port = rec.get("port")
        key = str(rec.get("host") or rec.get("ip") or "").strip().lower()
        if not key or not isinstance(port, int) or isinstance(port, bool):
            continue
        entry = out.setdefault(key, {"ip": rec.get("ip") or None, "ports": set()})
        entry["ports"].add(port)
    return {k: {"ip": v["ip"], "ports": sorted(v["ports"])} for k, v in out.items()}


def run_naabu(hosts: list, rate_limit: Optional[int], timeout: int = 600,
              top_ports: int = TOP_PORTS) -> dict:
    """Scan the top ports of every host. Connect scan (naabu's default): needs no root or libpcap."""
    if not hosts:
        return {}
    cmd = ["naabu", "-silent", "-json", "-Pn", "-duc", "-exclude-cdn", "-top-ports", str(top_ports)]
    if rate_limit:
        cmd += ["-rate", str(int(rate_limit))]
    log.info("[*] naabu: top %d ports on %d host(s), <= %s/s", top_ports, len(hosts), rate_limit or "default")
    res = run_tool(cmd, timeout=timeout, input_text="\n".join(hosts) + "\n")
    if res.timed_out:
        log.warning("[-] naabu timed out after %ss: keeping the ports it had found", timeout)
    elif not res.ok:
        log.warning("[-] naabu exited with code %s: %s", res.returncode, res.stderr.strip()[:200])
    return parse_naabu(res.stdout)


def parse_nmap_xml(xml_text: str) -> list:
    """
    nmap -oX output -> one dict per OPEN port:
    {"ip", "port", "protocol", "name", "product", "version", "extrainfo", "cpe": [..]}
    Returns [] for empty or malformed XML (a scan that timed out half way).
    """
    if not xml_text or "<nmaprun" not in xml_text:
        return []
    if "<!ENTITY" in xml_text.upper():
        # nmap never needs a document type or entity declarations. Reject them
        # before parsing untrusted tool output (which may include crafted banners).
        log.warning("[-] nmap XML contains entity declarations: ignored")
        return []
    try:
        # Entity declarations were rejected just above.
        root = ET.fromstring(  # nosec B314
            xml_text[xml_text.index("<?xml"):] if "<?xml" in xml_text else xml_text)
    except ET.ParseError as e:
        log.warning("[-] could not parse nmap XML: %s", e)
        return []
    out = []
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), None)
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            attrs = svc.attrib if svc is not None else {}
            try:
                number = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            out.append({
                "ip": addr,
                "port": number,
                "protocol": port.get("protocol") or "tcp",
                "name": attrs.get("name"),
                "product": attrs.get("product"),
                "version": attrs.get("version"),
                "extrainfo": attrs.get("extrainfo"),
                "cpe": [c.text.strip() for c in (svc.findall("cpe") if svc is not None else []) if c.text],
            })
    return out


def run_nmap(ip: str, ports: list, rate_limit: Optional[int], timeout: int = 600) -> list:
    """Identify the service and version behind the given open ports of ONE ip."""
    if not ports:
        return []
    cmd = ["nmap", "-sV", "--version-intensity", "5", "-Pn", "-n",
           "-p", ",".join(str(p) for p in sorted(ports)),
           "--host-timeout", f"{max(60, timeout - 30)}s", "-oX", "-", ip]
    if rate_limit:
        cmd[1:1] = ["--max-rate", str(int(rate_limit))]
    log.info("[*] nmap -sV on %s ports %s", ip, ",".join(str(p) for p in sorted(ports)))
    res = run_tool(cmd, timeout=timeout)
    if res.timed_out:
        log.warning("[-] nmap timed out on %s", ip)
    elif not res.ok:
        log.warning("[-] nmap exited with code %s on %s: %s", res.returncode, ip, res.stderr.strip()[:200])
    return parse_nmap_xml(res.stdout)
