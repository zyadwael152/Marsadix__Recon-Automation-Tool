"""
Read a small text file (scope.txt, .env, config.toml) the way Windows tools write it.

PowerShell's `echo example.com > scope.txt` writes UTF-16 with a BOM, and older
Notepad versions write UTF-8 with a BOM. Reading either as plain UTF-8 crashed
with UnicodeDecodeError (UTF-16) or left a invisible "\\ufeff" glued to the
first line (UTF-8 BOM), which then failed as an "invalid rule".
"""

import re
from pathlib import Path

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(value: str) -> str:
    """
    Turn arbitrary text into a single, portable file-name component.

    Targets reach file names after normalize_host(), which can still return an
    IPv6 address (':') or a wildcard ('*') -- both invalid on Windows -- and
    callers that skip validation can pass '../../x' directly.
    """
    safe = _UNSAFE_FILENAME_CHARS.sub("_", value or "").strip("._-")
    return safe or "target"


def read_text(path) -> str:
    """Decode UTF-8 (with or without BOM) or UTF-16 (BOM present). ValueError if it is neither."""
    raw = Path(path).read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        enc = "utf-16"                       # the BOM picks little/big endian and is removed
    elif raw.startswith(b"\xef\xbb\xbf"):
        enc = "utf-8-sig"
    else:
        enc = "utf-8"
    try:
        return raw.decode(enc)
    except UnicodeDecodeError as e:
        raise ValueError(f"{Path(path).name} is not valid text ({enc}): save it as UTF-8") from e
