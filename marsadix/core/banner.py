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
WARNING = "authorized targets only - you are responsible for your scans"

# 256-color gradients, one color per art row (dark at the top -> bright at the bottom).
THEMES = {
    "blood":  {"art": [52, 88, 124, 160, 196], "accent": 196, "text": 250, "dim": 240},
    "matrix": {"art": [22, 28, 34, 40, 46],    "accent": 46,  "text": 250, "dim": 240},
    "ocean":  {"art": [24, 31, 38, 45, 51],    "accent": 45,  "text": 250, "dim": 240},
    "violet": {"art": [54, 91, 128, 165, 201], "accent": 201, "text": 250, "dim": 240},
}

# Kept for backward compatibility with older code that imports these names.
ART_COLOR = "red"
TAGLINE_COLOR = "cyan"

# ---------------------------------------------------------------- the art
# Pure ASCII on purpose: works on every Windows console encoding.
# Each letter is 5 columns x 5 rows. Change NAME above and the art rebuilds itself.
_GLYPHS = {
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"],
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "X": ["#   #", " # # ", "  #  ", " # # ", "#   #"],
}


def _build_art(text: str, gap: int = 2) -> list[str]:
    rows = [""] * 5
    for ch in text.upper():
        glyph = _GLYPHS.get(ch, ["     "] * 5)
        for i in range(5):
            rows[i] += glyph[i] + " " * gap
    return [r.rstrip() for r in rows]


ART = _build_art(NAME)

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
    width = max(len(r) for r in ART)
    rule = "-" * max(width, 52)

    lines = [""]
    # prompt line, like a shell session
    lines.append("  " + _paint("root", t["accent"], True, use_color)
                 + _paint("@", t["dim"], False, use_color)
                 + _paint("marsadix", t["text"], True, use_color)
                 + _paint(":~# ", t["dim"], False, use_color)
                 + _paint("./recon --start", t["text"], False, use_color))
    lines.append("")

    # gradient art
    for row, color in zip(ART, t["art"]):
        lines.append("  " + _paint(row, color, True, use_color))

    lines.append("  " + _paint(rule, t["dim"], False, use_color))

    def tag(sym: str, label: str, value: str) -> str:
        return ("  " + _paint(f"[{sym}]", t["accent"], True, use_color) + " "
                + _paint(f"{label:<8}", t["dim"], False, use_color)
                + _paint(value, t["text"], False, use_color))

    lines.append(tag("*", "engine", f"{TAGLINE}"))
    lines.append(tag("*", "version", f"v{version()}"))
    lines.append(tag("*", "modules", SUBLINE))
    lines.append(tag("!", "notice", WARNING))
    lines.append("  " + _paint(rule, t["dim"], False, use_color))
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
