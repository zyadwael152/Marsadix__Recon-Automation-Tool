"""
R10: Port scan (naabu), excluding CDN hosts.
R11: Service/version detection + CPE (nmap -sV).

Both tools send real traffic to the target, so the caller (stage.py) must
only reach this module when ctx.allows("standard") - exactly like the
R4 HTTP confidence check and web/stage.py's own httpx/katana calls. Passive
scans never run this code.

CDN exclusion (R10's "من غير بورتات الـ CDN") happens by HOST, not by port
number: the caller filters out any host R9 flagged is_cdn=True before
calling run_naabu, since scanning a CDN's edge IP finds the CDN's ports,
not the origin server's - there's nothing useful there and it burns the
rate-limit budget that should go to real hosts.
"""

import asyncio
import json
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

NAABU_TIMEOUT = 300
NMAP_TIMEOUT = 180  # per host


async def run_naabu(hosts: List[str], rate_limit: Optional[int] = None) -> Dict[str, List[int]]:
    """Port-scan hosts with naabu. Returns {host: [open_ports]}."""
    if not hosts:
        return {}

    logger.info(f"[*] Running naabu on {len(hosts)} host(s) (CDN hosts excluded)...")
    open_ports: Dict[str, List[int]] = {}
    cmd = ["naabu", "-silent", "-json"]
    if rate_limit:
        cmd += ["-rate", str(int(rate_limit))]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        input_data = "\n".join(hosts).encode()
        communicate_task = asyncio.create_task(process.communicate(input=input_data))
        try:
            stdout, _ = await asyncio.wait_for(asyncio.shield(communicate_task), timeout=NAABU_TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            # Keep stdout collected before timeout; cancelling communicate() here
            # used to discard every partial result while the log claimed otherwise.
            try:
                stdout, _ = await communicate_task
            except Exception:
                stdout = b""
            logger.warning(f"[-] naabu timed out after {NAABU_TIMEOUT}s - keeping partial results.")

        for line in stdout.decode(errors="replace").splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            host = data.get("host") or data.get("ip")
            port = data.get("port")
            if host and port:
                open_ports.setdefault(host, []).append(int(port))

        total_ports = sum(len(p) for p in open_ports.values())
        logger.info(f"[+] naabu found {total_ports} open port(s) across {len(open_ports)} host(s).")
    except Exception as e:
        logger.warning(f"[-] naabu failed: {e}")

    return open_ports


def _parse_nmap_xml(xml_text: str) -> List[dict]:
    """
    Parse nmap's -oX output for ONE host into
    [{"port":.., "service":.., "product":.., "version":.., "cpe":..}, ...].
    Pure stdlib xml.etree, no new dependency.
    """
    entries: List[dict] = []
    if "<!ENTITY" in xml_text.upper():
        logger.warning("[-] nmap XML contains entity declarations: ignored")
        return entries
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.warning(f"[-] Could not parse nmap XML output: {e}")
        return entries

    host_el = root.find("host")
    if host_el is None:
        return entries
    ports_el = host_el.find("ports")
    if ports_el is None:
        return entries

    for port_el in ports_el.findall("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        service_el = port_el.find("service")
        entry = {
            "port": int(port_el.get("portid")),
            "service": service_el.get("name") if service_el is not None else None,
            "product": service_el.get("product") if service_el is not None else None,
            "version": service_el.get("version") if service_el is not None else None,
            "cpe": None,
        }
        if service_el is not None:
            cpe_el = service_el.find("cpe")
            if cpe_el is not None and cpe_el.text:
                entry["cpe"] = cpe_el.text
        entries.append(entry)

    return entries


async def run_nmap(host_ports: Dict[str, List[int]], rate_limit: Optional[int] = None) -> Dict[str, List[dict]]:
    """
    Service/version detection + CPE (R11) for hosts naabu found open ports
    on. One nmap process per host (nmap has no clean way to give different
    port lists to different targets in a single multi-target run).
    """
    if not host_ports:
        return {}

    logger.info(f"[*] Running nmap -sV on {len(host_ports)} host(s)...")
    results: Dict[str, List[dict]] = {}

    for host, ports in host_ports.items():
        if not ports:
            continue
        port_list = ",".join(str(p) for p in sorted(set(ports)))
        try:
            cmd = ["nmap", "-sV", "-Pn", "-p", port_list, "-oX", "-", host]
            if rate_limit:
                cmd[1:1] = ["--max-rate", str(int(rate_limit))]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=NMAP_TIMEOUT)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"[-] nmap on {host} timed out after {NMAP_TIMEOUT}s - skipped.")
                continue

            entries = _parse_nmap_xml(stdout.decode(errors="replace"))
            if entries:
                results[host] = entries
        except Exception as e:
            logger.warning(f"[-] nmap on {host} failed: {e}")

    total_services = sum(len(v) for v in results.values())
    logger.info(f"[+] nmap identified {total_services} service(s) with version/CPE info.")
    return results
