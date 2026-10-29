"""
Skills Registry (C5c): ONE central list of every detection skill Marsadix knows.

A skill is a self-contained detection: either a Nuclei template group or a custom
check (SSTI, Open Redirect, CRLF ...), each tied to a documented methodology (A9)
and an OWASP Top 10 category (A7). The registry is what

  * `marsadix skills` prints,
  * the report's Methodology section lists ("which checks were active"),
  * the asm stage (A1-A8) reads to decide what to run.

Two separate facts per skill, and the report shows only what is TRUE of both:

  enabled      the operator wants it (this file's default, or disabled by config)
  implemented  code actually exists for it. A skill is implemented only once its
               handler is registered with @register_handler("<name>"). Listing a
               check that cannot run would make the report claim coverage Marsadix
               does not have, so a skill with no handler is shown as "planned".

How the asm stage author adds a skill:

    from marsadix.skills import register_handler

    @register_handler("ssti")
    def run_ssti(ctx, targets): ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from ..owasp import OWASP_MAPPING


@dataclass(frozen=True)
class Skill:
    name: str                         # stable id, used in findings' template_id
    title: str
    engine: str                       # "nuclei" | "custom"
    finding_type: str                 # key into owasp.OWASP_MAPPING
    source_reference: str             # documented methodology (A9)
    min_mode: str = "standard"        # passive | standard | full: lowest scan mode that may run it
    needs_opt_in: bool = False        # injection-style probes need --allow-injection
    enabled: bool = True

    @property
    def owasp_category(self) -> Optional[str]:
        return OWASP_MAPPING.get(self.finding_type)


SKILLS: List[Skill] = [
    # ---- Nuclei template groups (A1-A3) -------------------------------------------------
    Skill("nuclei-takeover", "Subdomain takeover templates", "nuclei", "subdomain_takeover",
          "ProjectDiscovery nuclei-templates (takeovers)"),
    Skill("nuclei-exposures", "Exposures and misconfigurations", "nuclei", "git_env_exposure",
          "ProjectDiscovery nuclei-templates (exposures, misconfiguration)"),
    Skill("nuclei-tech-cve", "Technology- and CVE-specific templates", "nuclei", "cve_match",
          "ProjectDiscovery nuclei-templates (cves, technologies)"),
    # ---- custom skills on top of Nuclei (A5, A8) ------------------------------------------
    Skill("xss", "Reflected XSS (reflection evidence)", "custom", "xss_detected",
          "OWASP Testing Guide; PortSwigger XSS methodology", needs_opt_in=True),
    Skill("sqli", "SQL injection (error / time-based evidence)", "custom", "sqli_detected",
          "OWASP Testing Guide; PortSwigger SQL injection methodology", needs_opt_in=True),
    Skill("ssti", "Server-side template injection", "custom", "ssti_detected",
          "PortSwigger SSTI methodology; PayloadsAllTheThings", needs_opt_in=True),
    Skill("open-redirect", "Open redirect", "custom", "open_redirect",
          "PortSwigger; PayloadsAllTheThings", needs_opt_in=True),
    Skill("crlf", "CRLF injection", "custom", "crlf_injection",
          "PayloadsAllTheThings; HackTricks", needs_opt_in=True),
    Skill("host-header", "Host header injection", "custom", "host_header_injection",
          "PortSwigger Host header attacks; HackTricks", needs_opt_in=True),
    Skill("jwt", "JWT weaknesses", "custom", "jwt_weakness",
          "PortSwigger JWT attacks; HackTricks"),
    Skill("git-env-exposure", "Exposed .git / .env files", "custom", "git_env_exposure",
          "OWASP Testing Guide; HackTricks"),
]

_HANDLERS: Dict[str, Callable] = {}


def register_handler(name: str):
    """Decorator: mark skill `name` as implemented by the decorated function."""
    if name not in {s.name for s in SKILLS}:
        raise KeyError(f"unknown skill {name!r}: add it to SKILLS first")

    def deco(fn: Callable) -> Callable:
        _HANDLERS[name] = fn
        return fn
    return deco


def is_implemented(name: str) -> bool:
    return name in _HANDLERS


def get_skill(name: str) -> Optional[Skill]:
    return next((s for s in SKILLS if s.name == name), None)


def all_skills() -> List[Skill]:
    return list(SKILLS)


def active_skills(mode: str = "full", allow_injection: bool = True,
                  disabled: Iterable[str] = ()) -> List[Skill]:
    """Skills that are enabled, implemented and allowed in this scan mode / opt-in state."""
    order = {"passive": 0, "standard": 1, "full": 2}
    off = set(disabled)
    return [s for s in SKILLS
            if s.enabled and s.name not in off and is_implemented(s.name)
            and order.get(mode, 0) >= order[s.min_mode]
            and (allow_injection or not s.needs_opt_in)]


def render_table(mode: str = "full") -> str:
    """Plain-text table for `marsadix skills`."""
    act = {s.name for s in active_skills(mode, allow_injection=True)}
    rows = [("skill", "engine", "OWASP", "state", "source")]
    for s in SKILLS:
        state = ("active" if s.name in act else
                 "planned (no handler yet)" if not is_implemented(s.name) else "off")
        rows.append((s.name, s.engine, (s.owasp_category or "-").split("-")[0], state, s.source_reference))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows)
