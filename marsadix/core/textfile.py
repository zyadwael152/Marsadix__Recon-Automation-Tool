"""
Read a small text file (scope.txt, .env, config.toml) the way Windows tools write it.

PowerShell's `echo example.com > scope.txt` writes UTF-16 with a BOM, and older
Notepad versions write UTF-8 with a BOM. Reading either as plain UTF-8 crashed
with UnicodeDecodeError (UTF-16) or left a invisible "\\ufeff" glued to the
first line (UTF-8 BOM), which then failed as an "invalid rule".
"""

from pathlib import Path


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
