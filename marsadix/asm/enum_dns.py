"""
DNS enumeration skills: zone transfer (AXFR), email-security records (SPF / DMARC / MTA-STS / DKIM), wildcard.

They run once per scan against the TARGET DOMAIN. Queries go to the system resolvers; the only thing sent to a
name server is the AXFR attempt, and only to a server whose name is in the scan scope (see dnsclient.py).
Findings need clear evidence; the inventory records every record that was seen.
"""

from __future__ import annotations

import secrets
from typing import List, Optional

from ..core import netguard
from ..models import Confidence, DetectionStatus, Finding, Severity
from ..skills import registry
from .dnsclient import DnsClient
from .skills import Target, _mk

DNS_SKILLS = {"dns-zone-transfer", "email-security", "dns-wildcard"}
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2"]


def _dns_finding(t: Target, skill, title, severity, status, confidence, evidence, param, method="DNS records inspected"):
    f = _mk(t, skill, title, severity, status, confidence, evidence, param, method)
    f.url = None                                         # a DNS finding belongs to a domain, not to a URL
    return f


# --------------------------------------------------------------------- zone transfer
@registry.register_handler("dns-zone-transfer")
def probe_zone_transfer(d: DnsClient, t: Target) -> List[Finding]:
    zone = t.host
    ns_records = d.records(zone, "NS")
    out: List[Finding] = []
    for ns in sorted({r.rdata.rstrip(".").lower() for r in ns_records or []}):
        d.record(zone, "dns_ns", ns, "", "dns-zone-transfer")
        if not d.in_scope(ns):
            d.record(zone, "axfr", ns, "not tried: name server is out of scope", "dns-zone-transfer")
            continue
        for a in d.records(ns, "A") or []:
            ip = a.rdata
            if not d.allow_private and netguard.blocked_reason(ip, d.scope):
                d.record(zone, "axfr", ns, f"not tried: {ip} is blocked by the network guard", "dns-zone-transfer")
                continue
            res = d.axfr(zone, (ip, d.axfr_port))
            d.record(zone, "axfr", ns, f"{res.status}" + (f" ({res.records} records)" if res.records else
                                                           (f" ({res.detail})" if res.detail else "")), "dns-zone-transfer")
            if res.status == "transferred":
                out.append(_dns_finding(t, "dns-zone-transfer", f"DNS zone transfer allowed by {ns}", Severity.HIGH,
                                        DetectionStatus.DETECTED, Confidence.CONFIRMED,
                                        f"{ns} ({ip}) answered an AXFR request for {zone} with {res.records} records. "
                                        f"The records were counted and discarded.", ns, "AXFR attempt"))
    return out


# --------------------------------------------------------------------- email security
def _txt(d: DnsClient, name: str) -> Optional[List[str]]:
    recs = d.records(name, "TXT")
    return None if recs is None else [r.rdata for r in recs]


@registry.register_handler("email-security")
def probe_email_security(d: DnsClient, t: Target) -> List[Finding]:
    zone = t.host
    txt = _txt(d, zone)
    if txt is None:
        return []                                        # no resolver answered: cannot conclude anything
    mx = d.records(zone, "MX") or []
    # a "null MX" (RFC 7505, exchange ".") means the domain explicitly does not receive mail
    has_mail = any(r.rdata.partition(" ")[2].strip() not in ("", ".") for r in mx)
    for r in mx:
        d.record(zone, "dns_mx", r.rdata, "", "email-security")
    low = Severity.LOW if has_mail else Severity.INFO
    note = "" if has_mail else " (the domain publishes no MX record, so this matters less)"
    out: List[Finding] = []

    spf = [v for v in txt if v.lower().startswith("v=spf1")]
    for v in spf:
        d.record(zone, "spf", v[:300], "", "email-security")
    if not spf:
        out.append(_dns_finding(t, "email-security", "No SPF record", low, DetectionStatus.DETECTED, Confidence.CONFIRMED,
                                "No TXT record starting with v=spf1 was found" + note + ".", "spf"))
    elif len(spf) > 1:
        out.append(_dns_finding(t, "email-security", "Multiple SPF records", Severity.LOW, DetectionStatus.DETECTED,
                                Confidence.CONFIRMED, "More than one v=spf1 record exists; receivers treat this as an error.", "spf"))
    else:
        rec = spf[0].lower().split()
        if "+all" in rec or "all" in rec:
            out.append(_dns_finding(t, "email-security", "SPF allows any sender (+all)", Severity.MEDIUM, DetectionStatus.DETECTED,
                                    Confidence.CONFIRMED, "The SPF record ends with +all, which authorises every server.", "spf"))
        elif "?all" in rec:
            out.append(_dns_finding(t, "email-security", "SPF is neutral (?all)", Severity.LOW, DetectionStatus.DETECTED,
                                    Confidence.CONFIRMED, "The SPF record ends with ?all, so it enforces nothing.", "spf"))
        elif not any(x.endswith("all") for x in rec) and not any(x.startswith("redirect=") for x in rec):
            out.append(_dns_finding(t, "email-security", "SPF has no 'all' mechanism", Severity.LOW, DetectionStatus.DETECTED,
                                    Confidence.CONFIRMED, "The SPF record has no all / redirect term, so unlisted senders are not rejected.", "spf"))

    dmarc_txt = _txt(d, "_dmarc." + zone)
    if dmarc_txt is not None:
        dmarc = [v for v in dmarc_txt if v.lower().startswith("v=dmarc1")]
        for v in dmarc:
            d.record(zone, "dmarc", v[:300], "", "email-security")
        if not dmarc:
            out.append(_dns_finding(t, "email-security", "No DMARC record", low, DetectionStatus.DETECTED, Confidence.CONFIRMED,
                                    "No v=DMARC1 record was found at _dmarc." + zone + note + ".", "dmarc"))
        elif "p=none" in dmarc[0].lower().replace(" ", ""):
            out.append(_dns_finding(t, "email-security", "DMARC policy is p=none (monitoring only)", Severity.INFO,
                                    DetectionStatus.DETECTED, Confidence.CONFIRMED,
                                    "DMARC is published but does not ask receivers to quarantine or reject.", "dmarc"))

    mta = _txt(d, "_mta-sts." + zone)
    if mta is not None:
        sts = [v for v in mta if v.lower().startswith("v=stsv1")]
        for v in sts:
            d.record(zone, "mta_sts", v[:300], "", "email-security")
        if not sts and has_mail:
            out.append(_dns_finding(t, "email-security", "No MTA-STS record", Severity.INFO, DetectionStatus.DETECTED,
                                    Confidence.CONFIRMED, "No v=STSv1 record was found at _mta-sts." + zone + ".", "mta-sts"))

    for sel in DKIM_SELECTORS:                           # DKIM cannot be listed: only well-known selector names are tried
        found = _txt(d, f"{sel}._domainkey.{zone}")
        if found and any("v=dkim1" in v.lower() or "p=" in v.lower() for v in found):
            d.record(zone, "dkim_selector", sel, "present", "email-security")
    return out


# --------------------------------------------------------------------------- wildcard
@registry.register_handler("dns-wildcard")
def probe_wildcard(d: DnsClient, t: Target) -> List[Finding]:
    zone = t.host
    answers = [d.records(f"mx-{secrets.token_hex(6)}.{zone}", "A") for _ in range(2)]
    if any(a is None for a in answers):
        return []                                        # no resolver answered: cannot conclude anything
    hits = [sorted(r.rdata for r in a) for a in answers]
    if not all(hits):
        d.record(zone, "dns_wildcard", "none", "", "dns-wildcard")
        return []
    ips = ", ".join(sorted(set(hits[0]) | set(hits[1]))[:4])
    d.record(zone, "dns_wildcard", f"*.{zone}", ips, "dns-wildcard")
    return [_dns_finding(t, "dns-wildcard", "Wildcard DNS record", Severity.INFO, DetectionStatus.DETECTED, Confidence.CONFIRMED,
                         f"Two random, non-existent names under {zone} both resolve ({ips}). Subdomain results for this zone "
                         f"can include names that do not really exist.", "wildcard", "random labels resolved")]
