"""M7 - CPE parser (CPE 2.3 formatted strings and CPE 2.2 URI bindings).

Semantics
---------
* ``'*'`` is ANY, ``'-'`` is NA (not applicable).  An empty string ``''`` means
  "unspecified" (CPE 2.2 omitted/packed-empty field) and is semantically ANY.
  :meth:`CPE.normalized` maps ``''`` to ``'*'`` so that two CPEs can be compared
  semantically; :meth:`CPE.to_string` always emits ``'*'`` for ``''``.
* Values are stored *unescaped*.  Only a field that is exactly ``*`` / ``-`` is
  treated as ANY / NA; embedded wildcards (``?``/``*`` inside a value) are not
  expanded (documented limitation - NVD feeds do not use them).
* CPE 2.2 packed edition: ``~edition~sw_edition~target_sw~target_hw~other``.
  A leading ``~`` is optional (``online~win2003~x64~`` and
  ``~online~win2003~x64~`` both unpack to edition=online, sw_edition=win2003,
  target_sw=x64, target_hw='', other='').
* Truncated strings are accepted; missing trailing fields are ANY.

Every malformed input raises :class:`CPEParseError` (never ``IndexError`` /
``AttributeError``).
"""
from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import ClassVar, Tuple
from urllib.parse import quote, unquote

__all__ = ["CPE", "CPEParseError", "parse_cpe", "parse_cpe_cached", "ANY", "NA"]

ANY = "*"
NA = "-"
_PARTS = ("a", "o", "h")
_MAX_LEN = 2048


class CPEParseError(ValueError):
    """Raised for any malformed CPE string."""


@dataclass(frozen=True)
class CPE:
    part: str
    vendor: str
    product: str
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    FIELDS: ClassVar[Tuple[str, ...]] = (
        "part", "vendor", "product", "version", "update", "edition",
        "language", "sw_edition", "target_sw", "target_hw", "other",
    )

    # -- semantics ---------------------------------------------------------
    def normalized(self) -> Tuple[str, ...]:
        """Lower-cased tuple with '' folded to ANY - use for semantic equality."""
        return tuple((getattr(self, f) or ANY).lower() for f in self.FIELDS)

    @property
    def key(self) -> Tuple[str, str, str]:
        """Index key ``(part, vendor, product)`` (lower-cased)."""
        return (self.part.lower(), self.vendor.lower(), self.product.lower())

    # -- serialisation -----------------------------------------------------
    def to_string(self) -> str:
        """CPE 2.3 formatted string (all 11 attribute fields)."""
        return "cpe:2.3:" + ":".join(_escape23(getattr(self, f)) for f in self.FIELDS)

    def to_uri(self) -> str:
        """CPE 2.2 URI binding (packed edition when extended fields are set)."""
        def enc(v: str) -> str:
            if v in ("", ANY):
                return ""
            if v == NA:
                return "-"
            return quote(v, safe="")

        base = [enc(getattr(self, f)) for f in self.FIELDS[:5]]
        ext = [enc(getattr(self, f)) for f in self.FIELDS[5:6] + self.FIELDS[7:]]
        # ext order: edition, sw_edition, target_sw, target_hw, other
        ext = [ext[0]] + ext[1:]
        language = enc(self.language)
        if any(ext[1:]):
            edition = "~" + "~".join(ext)
        else:
            edition = ext[0]
        fields = base + [edition, language]
        while fields and fields[-1] == "":
            fields.pop()
        return "cpe:/" + ":".join(fields)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.to_string()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _escape23(value: str) -> str:
    if value in ("", ANY):
        return ANY
    if value == NA:
        return NA
    out = []
    for ch in value:
        if ch.isalnum() or ch in "_.":
            out.append(ch)
        else:
            out.append("\\" + ch)
    return "".join(out)


def _split_unescaped(s: str, sep: str = ":") -> list:
    parts, cur, i = [], [], 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            if i + 1 >= len(s):
                raise CPEParseError("dangling backslash at end of CPE")
            cur.append(s[i:i + 2])
            i += 2
            continue
        if c == sep:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _unescape23(tok: str) -> str:
    if tok in ("", ANY):
        return ANY
    if tok == NA:
        return NA
    out, i = [], 0
    while i < len(tok):
        c = tok[i]
        if c == "\\":
            out.append(tok[i + 1])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _check_value(name: str, v: str) -> None:
    if len(v) > 512:
        raise CPEParseError(f"CPE field '{name}' is too long")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in v):
        raise CPEParseError(f"CPE field '{name}' contains whitespace/control characters")


def _check_part(part: str) -> str:
    if part.lower() not in _PARTS:
        raise CPEParseError(f"invalid CPE part {part!r} (expected one of a, o, h)")
    return part.lower()


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------
def _parse23(s: str) -> CPE:
    toks = _split_unescaped(s)
    # toks[0]='cpe', toks[1]='2.3'
    attrs = toks[2:]
    if not attrs or attrs[0] == "":
        raise CPEParseError("CPE 2.3 string has no part")
    if len(attrs) > 11:
        raise CPEParseError(f"too many components in CPE 2.3 string ({len(attrs)} > 11)")
    vals = [_unescape23(t) for t in attrs]
    vals += [ANY] * (11 - len(vals))
    for name, v in zip(CPE.FIELDS, vals):
        _check_value(name, v)
    vals[0] = _check_part(vals[0])
    return CPE(*vals)


def _parse22(s: str) -> CPE:
    body = s[len("cpe:/"):]
    comps = body.split(":")
    if len(comps) > 7:
        raise CPEParseError(f"too many components in CPE 2.2 URI ({len(comps)} > 7)")
    if comps[0] == "":
        raise CPEParseError("CPE 2.2 URI has no part")
    try:
        dec = [unquote(c, errors="strict") for c in comps]
    except UnicodeDecodeError as exc:  # pragma: no cover - platform specific
        raise CPEParseError("invalid percent-encoding in CPE 2.2 URI") from exc
    dec += [""] * (7 - len(dec))
    part, vendor, product, version, update, edition, language = dec

    sw_edition = target_sw = target_hw = other = ""
    if "~" in edition:
        packed = edition[1:] if edition.startswith("~") else edition
        pieces = packed.split("~")
        if len(pieces) > 5:
            raise CPEParseError("too many packed edition components in CPE 2.2 URI")
        pieces += [""] * (5 - len(pieces))
        edition, sw_edition, target_sw, target_hw, other = pieces

    vals = [part, vendor, product, version, update, edition, language,
            sw_edition, target_sw, target_hw, other]
    for name, v in zip(CPE.FIELDS, vals):
        _check_value(name, v)
    vals[0] = _check_part(vals[0])
    return CPE(*vals)


def parse_cpe(value: str) -> CPE:
    """Parse a CPE 2.3 formatted string or CPE 2.2 URI."""
    if not isinstance(value, str):
        raise CPEParseError(f"CPE must be a string, got {type(value).__name__}")
    s = value.strip()
    if not s:
        raise CPEParseError("empty CPE string")
    if len(s) > _MAX_LEN:
        raise CPEParseError("CPE string is too long")
    low = s.lower()
    if low.startswith("cpe:2.3:"):
        return _parse23(s)
    if low.startswith("cpe:/"):
        return _parse22(s)
    raise CPEParseError("not a CPE 2.3 formatted string or CPE 2.2 URI")


@functools.lru_cache(maxsize=65536)
def _cached(value: str) -> CPE:
    return parse_cpe(value)


def parse_cpe_cached(value: str) -> CPE:
    """LRU-cached :func:`parse_cpe` (errors are re-raised, never cached)."""
    if not isinstance(value, str):
        raise CPEParseError(f"CPE must be a string, got {type(value).__name__}")
    return _cached(value)
