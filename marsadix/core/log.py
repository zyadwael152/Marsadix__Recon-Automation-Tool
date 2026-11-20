"""Logging setup. Every module does:  log = logging.getLogger(__name__)

Console output is colored when it goes to a real terminal:
  * the line that starts each stage has its own color (see STAGE_COLORS)
  * WARNING lines are orange, ERROR lines are red
Colors are switched off automatically when output is piped / redirected to a
file, when NO_COLOR is set, or when TERM=dumb.
"""

from __future__ import annotations

import logging
import os
import re

FMT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
DATEFMT = "%H:%M:%S"

# CHANGE THE COLORS HERE (256-color codes, one per stage)
STAGE_COLORS = {
    "recon": 196,   # red
    "web":   39,    # blue
    "ports": 220,   # yellow
    "asm":   207,   # pink
    "track": 46,    # green
    "graph": 45,    # cyan
}
DEFAULT_STAGE_COLOR = 250
WARNING_COLOR = 214
ERROR_COLOR = 196

_RESET = "\033[0m"
# matches:  stage 'recon' started   and   === Starting Recon stage for target ... ===
_START_RE = re.compile(r"stage '(\w+)' started|=== Starting (\w+) stage", re.I)


def _fg(code: int, bold: bool = False) -> str:
    return f"\033[{'1;' if bold else ''}38;5;{code}m"


class ColorFormatter(logging.Formatter):
    """Same output as the plain formatter, just wrapped in color codes."""

    def __init__(self, fmt: str | None = None, datefmt: str | None = None,
                 use_color: bool = True) -> None:
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        if not self.use_color:
            return line
        m = _START_RE.search(record.getMessage())
        if m:
            stage = (m.group(1) or m.group(2)).lower()
            return f"{_fg(STAGE_COLORS.get(stage, DEFAULT_STAGE_COLOR), True)}{line}{_RESET}"
        if record.levelno >= logging.ERROR:
            return f"{_fg(ERROR_COLOR, True)}{line}{_RESET}"
        if record.levelno >= logging.WARNING:
            return f"{_fg(WARNING_COLOR)}{line}{_RESET}"
        return line


def _enable_windows_ansi() -> None:
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


def _stream_supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def setup_logging(verbose: bool = False) -> None:
    # Respect handlers installed by the host application (including pytest's
    # capture handlers). ``force=True`` would remove those handlers and can
    # leave stale handlers writing to closed capture streams. basicConfig is
    # intentionally a no-op when the host already configured logging.
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=FMT,
        datefmt=DATEFMT,
    )

    # Color only the plain console handler that basicConfig created. Handlers
    # that belong to the host (pytest's capture handlers, file handlers, ...)
    # are different classes, so they are left exactly as they were.
    for handler in logging.getLogger().handlers:
        if type(handler) is not logging.StreamHandler:
            continue
        use_color = _stream_supports_color(getattr(handler, "stream", None))
        if use_color:
            _enable_windows_ansi()
        handler.setFormatter(ColorFormatter(FMT, DATEFMT, use_color=use_color))
