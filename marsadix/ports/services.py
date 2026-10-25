"""
Service names for well-known ports.

In --mode standard the ports stage only knows WHICH ports are open, not what
runs on them, so the name it records is the one the port number is registered
under. That is a hint, not a reading: --mode full runs nmap, which asks the
service itself.

This is a fixed table on purpose. It used to come from socket.getservbyport(),
which reads the operating system's own services file, so the same scan gave
"http-alt" for 8080 on Linux and nothing on Windows (and was very slow there).
Only IANA-registered names that are certain are listed; any other port has no name.
"""

from typing import Optional

_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 6379: "redis", 8080: "http-alt",
}


def port_name(port: int) -> Optional[str]:
    return _NAMES.get(port)
