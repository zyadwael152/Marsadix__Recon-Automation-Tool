"""
A small DNS client for the DNS enumeration skills (stdlib only: the project has no DNS library).

Supports what the skills need: A / NS / MX / TXT / SOA / CNAME / AAAA queries over UDP (with TCP
fallback when the answer is truncated) and a zone-transfer (AXFR) attempt over TCP.

Safety:
  * queries go to the system resolvers (or the ones given), never to the target's hosts;
  * an AXFR is only attempted against a name server whose NAME is in the scan scope (or whose address
    the scope lists), and never against an address the network guard blocks;
  * a transferred zone is COUNTED, never kept: the skill reports that the transfer is possible, it does
    not copy the zone.
"""

from __future__ import annotations

import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .http import RateLimiter

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "AXFR": 252}
_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH"}
MAX_AXFR_RECORDS = 50_000
AXFR_DEADLINE = 30.0


class DnsError(Exception):
    pass


@dataclass
class Record:
    name: str
    rtype: str
    rdata: str


@dataclass
class Message:
    rcode: int
    truncated: bool
    answers: List[Record] = field(default_factory=list)
    authority: List[Record] = field(default_factory=list)


@dataclass
class AxfrResult:
    status: str            # "transferred" | "refused" | "failed"
    records: int = 0
    detail: str = ""


# ------------------------------------------------------------------ wire format
def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise DnsError(f"invalid DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: str, qid: int, recursion: bool = True) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100 if recursion else 0, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", QTYPES[qtype], 1)


def _read_name(buf: bytes, off: int) -> Tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(buf):
            raise DnsError("name runs past the end of the message")
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:                       # compression pointer
            if off + 1 >= len(buf):
                raise DnsError("truncated compression pointer")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, hops = True, ptr, hops + 1
            if hops > 50:
                raise DnsError("compression loop")
            continue
        off += 1
        labels.append(buf[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels), (end if jumped else off)


def _parse_rr(buf: bytes, off: int) -> Tuple[Record, int]:
    name, off = _read_name(buf, off)
    if off + 10 > len(buf):
        raise DnsError("truncated record header")
    rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
    start, off = off + 10, off + 10 + rdlen
    if off > len(buf):
        raise DnsError("record data runs past the message")
    data = buf[start:off]
    kind = _TYPE_NAMES.get(rtype, str(rtype))
    if kind == "A" and rdlen == 4:
        text = socket.inet_ntoa(data)
    elif kind == "AAAA" and rdlen == 16:
        text = socket.inet_ntop(socket.AF_INET6, data)
    elif kind in ("NS", "CNAME"):
        text = _read_name(buf, start)[0]
    elif kind == "MX" and rdlen >= 3:
        text = f"{struct.unpack('!H', data[:2])[0]} {_read_name(buf, start + 2)[0]}"
    elif kind == "SOA":
        mname, p = _read_name(buf, start)
        rname, p = _read_name(buf, p)
        text = f"{mname} {rname}"
    elif kind == "TXT":
        parts, i = [], 0
        while i < len(data):
            ln = data[i]
            parts.append(data[i + 1:i + 1 + ln].decode("utf-8", "replace"))
            i += 1 + ln
        text = "".join(parts)
    else:
        text = ""
    return Record(name.lower(), kind, text), off


def parse_message(buf: bytes) -> Message:
    if len(buf) < 12:
        raise DnsError("message shorter than a DNS header")
    _qid, flags, qd, an, ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _name, off = _read_name(buf, off)
        off += 4
    msg = Message(rcode=flags & 0xF, truncated=bool(flags & 0x0200))
    for _ in range(an):
        rec, off = _parse_rr(buf, off)
        msg.answers.append(rec)
    for _ in range(ns):
        rec, off = _parse_rr(buf, off)
        msg.authority.append(rec)
    return msg


# --------------------------------------------------------------------- resolvers
def system_resolvers() -> List[Tuple[str, int]]:
    """The machine's own resolvers (/etc/resolv.conf), else two public ones."""
    found: List[Tuple[str, int]] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    found.append((parts[1], 53))
    except OSError:
        pass
    return found[:3] or [("1.1.1.1", 53), ("8.8.8.8", 53)]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise DnsError("connection closed early")
        data += chunk
    return data


class DnsClient:
    axfr_port = 53                                   # name servers listen on 53; tests point this at a fake server

    def __init__(self, scope=None, rate_limit: float = 10, timeout: float = 5,
                 resolvers: Optional[List[Tuple[str, int]]] = None, allow_private: bool = False):
        self.scope, self.timeout, self.allow_private = scope, timeout, allow_private
        self.resolvers = list(system_resolvers() if resolvers is None else resolvers)
        self.limiter = RateLimiter(rate_limit)
        self.requests = 0
        self.inventory: List[Dict[str, str]] = []
        self._lock = threading.Lock()

    def record(self, host: str, category: str, name: str, value: str = "", source: str = "") -> None:
        with self._lock:
            self.inventory.append({"host": host, "category": category, "name": name, "value": value, "source": source})

    def in_scope(self, host: str) -> bool:
        return self.scope is None or self.scope.is_in_scope(host)

    def _count(self) -> None:
        self.limiter.wait()
        with self._lock:
            self.requests += 1

    def _udp(self, wire: bytes, qid: int, server: Tuple[str, int]) -> Optional[bytes]:
        fam = socket.AF_INET6 if ":" in server[0] else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(wire, server)
            for _ in range(4):                       # ignore stray / spoofed answers with another id
                data, _addr = s.recvfrom(4096)
                if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                    return data
        return None

    def _tcp(self, wire: bytes, server: Tuple[str, int]) -> bytes:
        with socket.create_connection(server, self.timeout) as s:
            s.settimeout(self.timeout)
            s.sendall(struct.pack("!H", len(wire)) + wire)
            size = struct.unpack("!H", _recv_exact(s, 2))[0]
            return _recv_exact(s, size)

    def query(self, name: str, qtype: str, server: Optional[Tuple[str, int]] = None) -> Optional[Message]:
        """None = no resolver answered (cannot conclude anything); a Message with rcode 3 = the name does not exist."""
        servers = [server] if server else self.resolvers
        try:
            qid = random.randrange(1, 65535)
            wire = build_query(name, qtype, qid)
        except (DnsError, UnicodeEncodeError):
            return None
        for srv in servers:
            self._count()
            try:
                raw = self._udp(wire, qid, srv)
                if raw is not None and parse_message(raw).truncated:
                    raw = self._tcp(wire, srv)
                if raw is not None:
                    return parse_message(raw)
            except (OSError, DnsError):
                continue
        return None

    def records(self, name: str, qtype: str) -> Optional[List[Record]]:
        msg = self.query(name, qtype)
        if msg is None:
            return None
        return [r for r in msg.answers if r.rtype == qtype]

    def axfr(self, zone: str, server: Tuple[str, int]) -> AxfrResult:
        """Try ONE zone transfer. Records are counted and dropped, never stored."""
        qid = random.randrange(1, 65535)
        try:
            wire = build_query(zone, "AXFR", qid, recursion=False)
            self._count()
            total, soa = 0, 0
            deadline = time.monotonic() + AXFR_DEADLINE
            with socket.create_connection(server, self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(struct.pack("!H", len(wire)) + wire)
                while time.monotonic() < deadline and total < MAX_AXFR_RECORDS:
                    size = struct.unpack("!H", _recv_exact(s, 2))[0]
                    msg = parse_message(_recv_exact(s, size))
                    if msg.rcode != 0:
                        return AxfrResult("refused", 0, RCODES.get(msg.rcode, f"rcode {msg.rcode}"))
                    total += len(msg.answers)
                    soa += sum(1 for r in msg.answers if r.rtype == "SOA")
                    if soa >= 2:                      # the zone starts and ends with its SOA record
                        return AxfrResult("transferred", total)
            return AxfrResult("transferred", total, "stopped at the safety limit")
        except (OSError, DnsError) as e:
            return AxfrResult("failed", 0, type(e).__name__)
