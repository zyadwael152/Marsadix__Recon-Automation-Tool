"""
Startup banner (like msfconsole's), printed when you run `marsadix`.

CHANGE THE LOOK HERE:  THEME = "blood"   (or "matrix", "ocean", "violet")

Rules:
  * printed to STDERR, so `marsadix report ... > file` or JSON output stays clean
  * only shown in a real terminal (never when piped / in cron / in tests)
  * respects the NO_COLOR environment variable and `marsadix --no-banner`
  * adapts to the terminal width:
      >= 84 columns  -> big logo + hacker with glasses
      >= 62 columns  -> big logo only
      otherwise      -> small radar logo
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import TextIO

# ---------------------------------------------------------------- settings
THEME = "blood"                 # blood | matrix | ocean | violet
NAME = "MARSADIX"
TAGLINE = "Recon & Vuln Engine"
MOTTO = "watch the surface. find the gap."
WARNING = "authorized targets only - you are responsible for your scans"
BANNER_VERSION = "1.0.0"       # keep in sync with pyproject.toml

# 256-color themes: accent = logo, text = main text, dim = lines/labels.
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
# Pure ASCII on purpose: works on every Windows console encoding.
LOGO = [
    r"  __  __    ___    ____    ____      _     ____    ___  __  __",
    r" |  \/  |  / _ \  |  _ \  / ___|    / \   |  _ \  |_ _| \ \/ /",
    r" | |\/| | / /_\ \ | |_) | \___ \   / _ \  | | | |  | |   \  / ",
    r" | |  | |/ / _ \ \|  _ <   ___) | / ___ \ | |_| |  | |   /  \ ",
    r" |_|  |_/_/   \_\_\_| \_\ |____/ /_/   \_\|____/  |___| /_/\_\ ",
]

# The hacker: hood + dark glasses + mask. '#' = the lenses (painted white).
HACKER = [
    r"         .-----------.         ",
    r"       .'   /     \   '.       ",
    r"     .'    /       \    '.     ",
    r"    |     |=========|     |    ",
    r"    |     |[##]---[##]|     |    ",
    r"    |      \  -----  /      |    ",
    r"     \      \       /      /     ",
    r"    .-'      '-----'      '-.  ",
    r"   /   /                 \   \ ",
]

# Small radar logo, used when the terminal is too narrow for the big one.
SMALL_ART = [
    r"    .-----.    ",
    r"  .' * | / '.  ",
    r" |---- O ----| ",
    r"  '. / | * .'  ",
    r"    '-----'    ",
]

_RESET = "\033[0m"
LOGO_W = max(len(r) for r in LOGO)
HACKER_W = max(len(r) for r in HACKER)
GAP = 3
FULL_W = LOGO_W + GAP + HACKER_W          # logo + hacker side by side


def _fg(code: int, bold: bool = False) -> str:
    return f"\033[{'1;' if bold else ''}38;5;{code}m"


def _paint(text: str, code: int, bold: bool = False, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{_fg(code, bold)}{text}{_RESET}"


def version() -> str:
    return BANNER_VERSION


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


def _terminal_width() -> int:
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def _paint_row(row: str, t: dict, use_color: bool, pop: str = "") -> str:
    """Whole row in the accent color; characters listed in `pop` shine white."""
    if not use_color:
        return row
    out = []
    for ch in row:
        if ch == " ":
            out.append(ch)
        elif ch in pop:
            out.append(_paint(ch, t["text"], True))
        else:
            out.append(_paint(ch, t["accent"], True))
    return "".join(out)


def render(use_color: bool = True, width: int | None = None) -> str:
    t = THEMES.get(THEME, THEMES["blood"])
    width = width if width is not None else _terminal_width()

    def P(text, key, bold=False):
        return _paint(text, t[key], bold, use_color)

    def chip(word: str) -> str:
        return P("[ ", "dim") + P(word, "text", True) + P(" ]", "dim")

    prompt = ("  " + P("root", "accent", True) + P("@", "dim") + P("marsadix", "text", True)
              + P(":~# ", "dim") + P("./marsadix --start", "text"))
    info_chips = chip("recon") + " " + chip("asm") + " " + chip("cve")
    ver = P(f"v{version()}", "text", True)
    motto = P("> ", "accent", True) + P(MOTTO, "dim")

    # ---------- wide terminal: big logo + hacker with glasses
    if width >= FULL_W + 5:
        bar_top = P("-" * FULL_W, "dim")
        bar_bot = P("-" * FULL_W, "dim")
        pad = (len(HACKER) - len(LOGO)) // 2          # center the logo next to the hacker
        logo = [" " * LOGO_W] * pad + LOGO + [" " * LOGO_W] * (len(HACKER) - len(LOGO) - pad)
        lines = ["", prompt, "", "  " + bar_top]
        for l, h in zip(logo, HACKER):
            lines.append("  " + _paint_row(l, t, use_color) + " " * GAP
                         + _paint_row(h, t, use_color, pop="#"))
        lines += [
            "  " + bar_bot,
            "  " + P(TAGLINE, "text", True) + P("  //  ", "dim") + ver + "    " + info_chips,
            "  " + motto,
            "  " + P("[!] ", "accent", True) + P(WARNING, "dim"),
            "",
        ]
        return "\n".join(lines)

    # ---------- medium terminal: big logo only
    if width >= LOGO_W + 9:
        bar = P("-" * LOGO_W, "dim")
        lines = ["", prompt, "", "  " + bar]
        lines += ["  " + _paint_row(r, t, use_color) for r in LOGO]
        lines += [
            "  " + bar,
            "  " + P(TAGLINE, "text", True) + P("  //  ", "dim") + ver,
            "  " + info_chips,
            "  " + motto,
            "  " + P("[!] ", "accent", True) + P("authorized targets only", "dim"),
            "",
        ]
        return "\n".join(lines)

    # ---------- narrow terminal: small radar logo
    right = [
        P(" ".join(NAME), "accent", True) + P("  //  ", "dim") + ver,
        P(TAGLINE, "text"),
        P("-=" * 17, "dim"),
        info_chips,
        motto,
    ]
    lines = ["", prompt, ""]
    for row, r in zip(SMALL_ART, right):
        lines.append("    " + _paint_row(row, t, use_color, pop="O*") + "   " + r)
    lines += ["", "  " + P("[!] ", "accent", True) + P("authorized targets only", "dim"), ""]
    return "\n".join(lines)


def print_banner(stream: TextIO = None, force: bool = False) -> bool:
    """Show the banner. Returns True if it was printed."""
    stream = stream or sys.stderr
    if not force and not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    enable_windows_ansi()
    print(render(use_color=supports_color(stream)), file=stream)
    return True
