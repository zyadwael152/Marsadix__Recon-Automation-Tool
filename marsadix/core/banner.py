"""
Startup banner (like msfconsole's), printed when you run `marsadix`.

CHANGE THE COLOR HERE:  ART_COLOR = "green"  (or "red", "cyan", "yellow", "magenta", "blue")

Rules:
  * printed to STDERR, so `marsadix report ... > file` or JSON output stays clean
  * only shown in a real terminal (never when piped / in cron / in tests)
  * respects the NO_COLOR environment variable and `marsadix --no-banner`
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

ART_COLOR = "green"
TAGLINE_COLOR = "cyan"

# Pure ASCII on purpose: works on every Windows console encoding.
ART = [
    r"    __  ______    ____  _____ ___    ____  _____  __",
    r"   /  |/  /   |  / __ \/ ___//   |  / __ \/  _/ |/ /",
    r"  / /|_/ / /| | / /_/ /\__ \/ /| | / / / // / |   / ",
    r" / /  / / ___ |/ _, _/___/ / ___ |/ /_/ // / /   |  ",
    r"/_/  /_/_/  |_/_/ |_|/____/_/  |_/_____/___//_/|_|  ",
]
TAGLINE = "Recon & Vuln Engine"
SUBLINE = "recon + asm + cve monitor"

_CODES = {"red": "31", "green": "32", "yellow": "33", "blue": "34",
          "magenta": "35", "cyan": "36", "white": "37"}
_RESET = "\033[0m"


def _paint(text: str, color: str, bold: bool = False, use_color: bool = True) -> str:
    if not use_color:
        return text
    code = _CODES.get(color, "32")
    return f"\033[{'1;' if bold else ''}{code}m{text}{_RESET}"


def version() -> str:
    try:
        from importlib.metadata import version as _v
        return _v("marsadix")
    except Exception:
        return "dev"


def enable_windows_ansi() -> None:
    """Old Windows consoles need 'virtual terminal' mode switched on for colors."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        for std in (-11, -12):                       # stdout, stderr
            handle = k32.GetStdHandle(std)
            mode = ctypes.c_ulong()
            if k32.GetConsoleMode(handle, ctypes.byref(mode)):
                k32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render(use_color: bool = True) -> str:
    lines = [""]
    lines += [_paint(l, ART_COLOR, bold=True, use_color=use_color) for l in ART]
    lines.append("")
    lines.append("  " + _paint(f"{TAGLINE}  |  v{version()}", TAGLINE_COLOR, use_color=use_color))
    lines.append("  " + _paint(f"[ {SUBLINE} ]", TAGLINE_COLOR, use_color=use_color))
    lines.append("")
    return "\n".join(lines)


def print_banner(stream: TextIO = None, force: bool = False) -> bool:
    """Show the banner. Returns True if it was printed."""
    stream = stream or sys.stderr
    if not force and not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    enable_windows_ansi()
    print(render(use_color=supports_color(stream)), file=stream)
    return True
