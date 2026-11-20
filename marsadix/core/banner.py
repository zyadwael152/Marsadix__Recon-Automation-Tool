"""
Startup banner (like msfconsole's), printed when you run `marsadix`.

CHANGE THE LOOK HERE:  THEME = "blood"   (or "matrix", "ocean", "violet")

Rules:
  * printed to STDERR, so `marsadix report ... > file` or JSON output stays clean
  * only shown in a real terminal (never when piped / in cron / in tests)
  * respects the NO_COLOR environment variable and `marsadix --no-banner`
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

# ---------------------------------------------------------------- settings
THEME = "blood"                 # blood | matrix | ocean | violet
NAME = "MARSADIX"
TAGLINE = "Recon & Vuln Engine"
SUBLINE = "recon + asm + cve monitor"
WARNING = "authorized targets only"

# 256-color themes: accent = emblem/name, text = main text, dim = lines/labels.
THEMES = {
    "blood":  {"accent": 196, "text": 252, "dim": 244},
    "matrix": {"accent": 46,  "text": 252, "dim": 244},
    "ocean":  {"accent": 45,  "text": 252, "dim": 244},
    "violet": {"accent": 201, "text": 252, "dim": 244},
}

# Kept for backward compatibility with older code that imports these names.
ART_COLOR = "red"
TAGLINE_COLOR = "cyan"

# ---------------------------------------------------------------- the art
# A small radar / crosshair. Pure ASCII on purpose: works on every Windows
# console encoding. The 'O' in the middle is painted in a different color.
ART = [
    r"    .-----.    ",
    r"  .' \ | / '.  ",
    r" |---- O ----| ",
    r"  '. / | \ .'  ",
    r"    '-----'    ",
]

_RESET = "\033[0m"


def _fg(code: int, bold: bool = False) -> str:
    return f"\033[{'1;' if bold else ''}38;5;{code}m"


def _paint(text: str, code: int, bold: bool = False, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{_fg(code, bold)}{text}{_RESET}"


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
    # Best-effort console mode; failure here is harmless.
    except Exception:  # nosec B110
        pass


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render(use_color: bool = True) -> str:
    t = THEMES.get(THEME, THEMES["blood"])

    def P(text, key, bold=False):
        return _paint(text, t[key], bold, use_color)

    # emblem: accent color, with the center dot in the text color
    emblem = []
    for row in ART:
        painted = P(row, "accent", True)
        if "O" in row:
            painted = painted.replace("O", (_RESET + _fg(t["text"], True) + "O" + _RESET + _fg(t["accent"], True))
                                      if use_color else "O")
        emblem.append(painted)

    name = " ".join(NAME)
    rule = "-" * 34
    right = [
        P(name, "accent", True),
        P(rule, "dim"),
        P(TAGLINE, "text", True) + "  " + P(f"v{version()}", "dim"),
        P(SUBLINE, "dim"),
        P("[!] ", "accent", True) + P(WARNING, "text"),
    ]

    lines = [""]
    for left, r in zip(emblem, right):
        lines.append("  " + left + "   " + r)
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
