"""
The environment handed to every external tool Marsadix starts.

Why this exists: a child process inherits the parent's whole environment. If
Marsadix kept API keys (Shodan, Censys, VirusTotal, NVD, Discord webhook,
Telegram token ...) in `os.environ`, EVERY tool it starts -- subfinder, nmap,
katana, ffuf -- would receive ALL of them, whether or not it needs one.

So children get an ALLOW-LIST (just enough for a tool to run: PATH, HOME, temp
dirs, locale, proxy and CA settings, Windows system variables). Nothing else
passes -- not Marsadix's own secrets, and not unrelated secrets that happen
to be exported in the user's shell (AWS_*, GITHUB_TOKEN ...).

A tool that really needs a key gets exactly that key, named explicitly:

    child_env({"PDCP_API_KEY": cfg.chaos_api_key})     # chaos-client only
"""

from __future__ import annotations

import os
from typing import Mapping, Optional

_ALLOWED = {
    # POSIX basics
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TZ",
    "TMPDIR", "TEMP", "TMP", "TERM", "NO_COLOR",
    # Windows basics
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "HOMEDRIVE", "HOMEPATH", "USERNAME", "COMPUTERNAME", "OS",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    # Go tools keep modules/caches here
    "GOPATH", "GOCACHE",
    # networking: corporate proxy + custom CA bundles are legitimate, user-set
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR",
}
_ALLOWED_PREFIXES = ("LC_", "XDG_")


def _allowed(name: str) -> bool:
    up = name.upper()
    return up in _ALLOWED or up.startswith(_ALLOWED_PREFIXES)


def child_env(extra: Optional[Mapping[str, Optional[str]]] = None) -> dict:
    """Minimal environment for one child process, plus the explicit `extra` entries."""
    env = {k: v for k, v in os.environ.items() if _allowed(k)}
    for k, v in (extra or {}).items():
        if v is not None:
            env[str(k)] = str(v)
    return env
