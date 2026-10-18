
"""
Marsadix startup banner.

Features:
  * 8 distinct framed ASCII banner styles.
  * Random banner selection without repeating the previous launch.
  * Printed to STDERR by default.
  * Respects NO_COLOR and non-interactive terminals.
  * Compatible with --no-banner through the existing CLI.
"""

from __future__ import annotations

import os
import random
import sys
from importlib.metadata import version as get_version
from pathlib import Path
from typing import TextIO

# ============================================================
# CONFIGURATION
# ============================================================

ART_COLOR = "green"
TAGLINE_COLOR = "cyan"

TAGLINE = "Recon & Vuln Engine"
SUBLINE = "recon + asm + cve monitor"

_CODES = {
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
}
_RESET = "\033[0m"

# ============================================================
# ASCII FONTS
# ============================================================

FONT_BLOCK = {
    "M": ["|   |", "|| ||", "| | |", "|   |", "|   |"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"],
    "X": ["#   #", " # # ", "  #  ", " # # ", "#   #"],
}

FONT_SLASH = {
    "M": [r"\   /", r" \ / ", r"  X  ", r" / \ ", r"/   \\"],
    "A": ["  /\\ ", " /  \\", "/____\\", "|    |", "|    |"],
    "R": ["/---\\", "|   |", "|---/", "|  \\", "|   \\"],
    "S": [" /---", "|    ", " \\--\\", "    |", "---/ "],
    "D": ["/---\\", "|    |", "|    |", "|    |", "\\---/"],
    "I": ["=====", "  |  ", "  |  ", "  |  ", "====="],
    "X": ["\\   /", " \\ / ", "  X  ", " / \\ ", "/   \\"],
}

# ============================================================
# BANNER STYLES
# ============================================================

_BANNER_INFO = [
    ("MATRIX", "RECON ENGINE INITIALIZED"),
    ("SHADOW", "ATTACK SURFACE DISCOVERY"),
    ("SENTINEL", "VULNERABILITY INTELLIGENCE"),
    ("PHANTOM", "STEALTH RECON MODE"),
    ("OVERWATCH", "MONITORING DIGITAL ASSETS"),
    ("NIGHTFALL", "INTELLIGENCE MODULES READY"),
    ("ZERO DAY", "CVE CORRELATION ONLINE"),
    ("DARK OPS", "AUTHORIZED SECURITY TESTING"),
]


def _make_logo(font: dict[str, list[str]], style: int) -> list[str]:
    """Render the MARSADIX wordmark inside a selected frame."""
    word = "MARSADIX"

    rows = [
        "  ".join(font[letter][row] for letter in word).rstrip()
        for row in range(5)
    ]

    width = max(map(len, rows))
    rows = [row.center(width) for row in rows]

    if style == 0:
        return ["  " + row for row in rows]

    frames = [
        (
            "  +" + "-" * (width + 2) + "+",
            "  | ",
            " |",
            "  +" + "-" * (width + 2) + "+",
        ),
        (
            "  /" + "=" * (width + 2) + "\\",
            "  || ",
            " ||",
            "  \\" + "=" * (width + 2) + "/",
        ),
        (
            "  <" + "~" * (width + 2) + ">",
            "  < ",
            " >",
            "  <" + "~" * (width + 2) + ">",
        ),
        (
            "  [" + "#" * (width + 2) + "]",
            "  # ",
            " #",
            "  [" + "#" * (width + 2) + "]",
        ),
        (
            "  ." + "_" * (width + 2) + ".",
            "  : ",
            " :",
            "  '" + "-" * (width + 2) + "'",
        ),
        (
            "  /" + "-" * (width + 2) + "\\",
            "  | ",
            " |",
            "  \\" + "-" * (width + 2) + "/",
        ),
        (
            "  :" + "=" * (width + 2) + ":",
            "  :: ",
            " ::",
            "  :" + "=" * (width + 2) + ":",
        ),
    ]

    top, left, right, bottom = frames[(style - 1) % len(frames)]

    return [
        top,
        *[left + row.ljust(width) + right for row in rows],
        bottom,
    ]


BANNERS = [
    {
        "name": name,
        "art": _make_logo(
            FONT_BLOCK if i % 2 == 0 else FONT_SLASH,
            i,
        ),
        "status": status,
    }
    for i, (name, status) in enumerate(_BANNER_INFO)
]

# ============================================================
# UTILITIES
# ============================================================


def version() -> str:
    """Return the installed package version, or 'dev'."""
    try:
        return get_version("marsadix")
    except Exception:
        return "dev"


def _paint(
    text: str,
    color: str,
    bold: bool = False,
    use_color: bool = True,
) -> str:
    """Apply ANSI color when supported."""
    if not use_color:
        return text

    code = _CODES.get(color.lower(), "32")
    prefix = f"\033[1;{code}m" if bold else f"\033[{code}m"

    return f"{prefix}{text}{_RESET}"


def enable_windows_ansi() -> None:
    """Enable ANSI colors in supported Windows consoles."""
    if os.name != "nt":
        return

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32

        for std_handle in (-11, -12):
            handle = kernel32.GetStdHandle(std_handle)
            mode = ctypes.c_ulong()

            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(
                    handle, mode.value | 0x0004
                )
    except Exception:
        pass


def supports_color(stream: TextIO) -> bool:
    """Return whether color output is appropriate."""
    if "NO_COLOR" in os.environ:
        return False

    if os.environ.get("TERM", "").lower() == "dumb":
        return False

    try:
        if not stream.isatty():
            return False
    except (AttributeError, OSError):
        return False

    if os.name == "nt":
        return any(
            os.environ.get(key)
            for key in ("WT_SESSION", "ANSICON", "TERM")
        ) or os.environ.get("ConEmuANSI") == "ON"

    return True


def _history_path() -> Path:
    """Return the per-user banner history path."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path(
            os.environ.get(
                "XDG_CONFIG_HOME",
                Path.home() / ".config",
            )
        )

    return base / "marsadix" / "banner_history"


def _choose_banner() -> dict:
    """Choose a random banner different from the previous launch."""
    history = _history_path()
    previous = None

    try:
        previous = history.read_text(encoding="utf-8").strip()
    except OSError:
        pass

    choices = [
        banner
        for banner in BANNERS
        if banner["name"] != previous
    ]

    selected = random.choice(choices or BANNERS)

    try:
        history.parent.mkdir(parents=True, exist_ok=True)
        history.write_text(selected["name"], encoding="utf-8")
    except OSError:
        # Read-only environments can still display a banner.
        pass

    return selected


# ============================================================
# RENDERING
# ============================================================


def render(use_color: bool = True) -> str:
    """Render one randomly selected banner."""
    banner = _choose_banner()
    lines = [""]

    lines.extend(
        _paint(
            line,
            ART_COLOR,
            bold=True,
            use_color=use_color,
        )
        for line in banner["art"]
    )

    lines.append("")
    lines.append(
        "  " + _paint(
            f"Marsadix | {TAGLINE} | v{version()}",
            TAGLINE_COLOR,
            use_color=use_color,
        )
    )
    lines.append(
        "  " + _paint(
            f"[ {banner['name']} :: {banner['status']} ]",
            ART_COLOR,
            bold=True,
            use_color=use_color,
        )
    )
    lines.append(
        "  " + _paint(
            f"[ {SUBLINE} ]",
            TAGLINE_COLOR,
            use_color=use_color,
        )
    )
    lines.append("")

    return "\n".join(lines)


def print_banner(
    stream: TextIO | None = None,
    force: bool = False,
) -> bool:
    """Print the banner to stderr by default. Return True if printed."""
    stream = stream or sys.stderr

    if not force:
        try:
            if not stream.isatty():
                return False
        except (AttributeError, OSError):
            return False

    enable_windows_ansi()
    print(
        render(use_color=supports_color(stream)),
        file=stream,
    )
    return True
