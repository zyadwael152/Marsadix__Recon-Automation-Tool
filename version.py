"""M8 - version parsing, ordering and range checks.

Ordering model
--------------
A version is ``release`` (tuple of ints, trailing zeros insignificant) plus an
ordered ``suffix``.  Each suffix element is ``(rank, label, number)``:

    rank -5 dev/snapshot < -4 alpha < -3 beta < -2 pre/preview < -1 rc
         0  (no suffix / revision number)
         +1 post-release: a single letter (OpenSSL ``1.0.2a``), or ``p``/``pl``/
            ``sp``/``patch`` followed by a number (OpenSSH ``8.2p1``).

So ``1.0.2-beta1 < 1.0.2rc1 < 1.0.2 < 1.0.2a < 1.0.2k < 1.0.3`` and
``8.2 < 8.2p1 < 8.2p2 < 8.3``.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = ["Version", "VersionParseError", "parse_version", "try_parse_version",
           "compare_versions", "version_in_range"]


class VersionParseError(ValueError):
    """Raised for invalid input."""


_PRE = {"dev": -5, "snapshot": -5, "nightly": -5, "alpha": -4, "beta": -3,
        "pre": -2, "preview": -2, "rc": -1, "cr": -1, "candidate": -1}
_POST = {"p", "pl", "patch", "sp", "post", "rev"}
_NOOP = {"final", "ga", "release", "stable", "lts"}
_TOKEN = re.compile(r"\d+|[a-z]+|[^a-z0-9]+")

Suffix = Tuple[Tuple[int, str, int], ...]


@functools.total_ordering
@dataclass(frozen=True, eq=False)
class Version:
    raw: str
    release: Tuple[int, ...]
    suffix: Suffix = ()

    def _cmp(self, other: "Version") -> int:
        n = max(len(self.release), len(other.release))
        ra = self.release + (0,) * (n - len(self.release))
        rb = other.release + (0,) * (n - len(other.release))
        if ra != rb:
            return -1 if ra < rb else 1
        m = max(len(self.suffix), len(other.suffix))
        pad = (0, "", 0)
        sa = self.suffix + (pad,) * (m - len(self.suffix))
        sb = other.suffix + (pad,) * (m - len(other.suffix))
        if sa != sb:
            return -1 if sa < sb else 1
        return 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._cmp(other) == 0

    def __lt__(self, other: "Version") -> bool:
        return self._cmp(other) < 0

    def __hash__(self) -> int:
        rel = list(self.release)
        while rel and rel[-1] == 0:
            rel.pop()
        suf = list(self.suffix)
        while suf and suf[-1] == (0, "", 0):
            suf.pop()
        return hash((tuple(rel), tuple(suf)))

    def __str__(self) -> str:
        return self.raw


def parse_version(raw: object) -> Version:
    if raw is None:
        raise VersionParseError("version is None")
    s = str(raw).strip().lower()
    if len(s) > 128:
        raise VersionParseError("version string too long")
    if len(s) > 1 and s[0] == "v" and s[1].isdigit():
        s = s[1:]
    if not s or not s[0].isdigit():
        raise VersionParseError(f"unparseable version {str(raw)[:40]!r}")
    toks = _TOKEN.findall(s)
    release: list = []
    suffix: list = []  # [rank, label, num, numbered]
    n = len(toks)
    for i, t in enumerate(toks):
        if t.isdigit():
            if not suffix:
                release.append(int(t))
            elif not suffix[-1][3] and suffix[-1][0] != 0:
                suffix[-1][2] = int(t)
                suffix[-1][3] = True
            else:
                suffix.append([0, "", int(t), True])
            continue
        if not t.isalpha():  # separator run
            continue
        attached = i > 0 and toks[i - 1].isdigit()
        next_digit_attached = i + 1 < n and toks[i + 1].isdigit()
        if t in _PRE:
            suffix.append([_PRE[t], "", 0, False])
        elif t in _NOOP:
            continue
        elif t in _POST:
            suffix.append([1, "p" if t in ("p", "pl", "patch", "post") else t, 0, False])
        elif len(t) == 1:
            if t == "a" and (next_digit_attached or not attached):
                suffix.append([-4, "", 0, False])
            elif t == "b" and (next_digit_attached or not attached):
                suffix.append([-3, "", 0, False])
            else:
                suffix.append([1, t, 0, False])
        else:
            suffix.append([1, t, 0, False])
    if not release:
        raise VersionParseError(f"unparseable version {str(raw)[:40]!r}")
    return Version(str(raw).strip(), tuple(release),
                   tuple((r, l, num) for r, l, num, _ in suffix))


def try_parse_version(raw: object) -> Optional[Version]:
    try:
        return parse_version(raw)
    except VersionParseError:
        return None


def compare_versions(a: object, b: object) -> int:
    va = a if isinstance(a, Version) else parse_version(a)
    vb = b if isinstance(b, Version) else parse_version(b)
    return va._cmp(vb)


def version_in_range(version: object, *, start_incl: object = None, start_excl: object = None,
                     end_incl: object = None, end_excl: object = None) -> bool:
    """Check ``version`` against NVD-style bounds. Raises VersionParseError."""
    v = version if isinstance(version, Version) else parse_version(version)
    if start_incl not in (None, "") and compare_versions(v, start_incl) < 0:
        return False
    if start_excl not in (None, "") and compare_versions(v, start_excl) <= 0:
        return False
    if end_incl not in (None, "") and compare_versions(v, end_incl) > 0:
        return False
    if end_excl not in (None, "") and compare_versions(v, end_excl) >= 0:
        return False
    return True
