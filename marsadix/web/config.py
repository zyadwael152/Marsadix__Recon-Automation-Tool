"""Configuration for the Member 2 web-surface extension.

The base Marsadix `Config` remains the source of truth for `db_path`,
`output_dir`, `rate_limit`, `tool_timeout`, `scan_mode` and scope handling.
This class only adds web-surface knobs.  Values are resolved in this order:

    built-in defaults < config.toml [member2] < MARSADIX_M2_* env < CLI args

No secret is defined or read here (the extension needs no API keys).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Iterable, Optional

from .errors import ConfigError

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = None


DEFAULT_STATUS_ALLOW = "200-399,401,403,405"
DEFAULT_USER_AGENT = "Marsadix-Member2/1.0 (authorized web-surface reconnaissance)"

# Values accepted by --crawler-backend. `auto` uses katana when it is
# installed and falls back to the stdlib crawler; `both` runs both and merges.
CRAWLER_BACKENDS = ("auto", "katana", "builtin", "both")

# Archive providers are deliberately explicit: sending a target name to a
# third party is a data-sharing decision, so `commoncrawl` is opt-in in the
# CLI but still available as a named provider.
ARCHIVE_SOURCES = ("gau", "wayback", "commoncrawl")

_ENV_PREFIX = "MARSADIX_M2_"


def _package_tools_dir() -> str:
    """Sibling .tools/bin created by scripts/install_web_recon_tools.sh."""
    candidate = Path(__file__).resolve().parent.parent.parent / ".tools" / "bin"
    return str(candidate) if candidate.is_dir() else ""


def parse_status_ranges(spec: str) -> tuple[tuple[int, int], ...]:
    """Parse "200-299,301,302,401" into sorted inclusive ranges."""
    if spec is None or not str(spec).strip():
        raise ConfigError("status filter cannot be empty")
    ranges: list[tuple[int, int]] = []
    for raw in str(spec).split(","):
        token = raw.strip()
        if not token:
            continue
        try:
            if "-" in token:
                lo_s, hi_s = token.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
            else:
                lo = hi = int(token)
        except ValueError as exc:
            raise ConfigError(f"invalid status filter token: {token!r}") from exc
        if lo < 100 or hi > 599 or lo > hi:
            raise ConfigError(f"status filter out of range: {token!r}")
        ranges.append((lo, hi))
    if not ranges:
        raise ConfigError("status filter did not contain any code")
    return tuple(sorted(set(ranges)))


def status_in_ranges(code: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(lo <= int(code) <= hi for lo, hi in ranges)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def _env_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return tuple(part.strip().lower() for part in raw.split(",") if part.strip())


@dataclass
class Member2Config:
    # Storage / output
    db_path: str = "marsadix.db"
    output_dir: str = "output"
    write_outputs: bool = True

    # Network politeness
    rate_limit: int = 10                 # requests/second for internal HTTP + tools
    request_timeout: float = 10.0
    tool_timeout: int = 300
    tool_threads: int = 2                # gau/katana worker hint
    retries: int = 2                     # HTTP retries; tools get one bounded retry
    max_concurrency: int = 8

    # Discovery / archive
    archive_sources: tuple[str, ...] = ("gau", "wayback")
    archive_timeout: float = 45.0
    archive_pages: int = 2
    max_archive_urls: int = 5000
    max_urls: int = 5000
    max_per_host: int = 300
    max_hosts_for_assets: int = 500
    include_subdomains: bool = True
    discover_hosts: bool = True
    dns_timeout: float = 5.0

    # Crawling
    crawler_backend: str = "auto"
    crawl_depth: int = 2
    max_pages: int = 40
    max_links_per_page: int = 500
    respect_robots: bool = True
    user_agent: str = DEFAULT_USER_AGENT

    # JavaScript
    extract_js: bool = True
    max_js_files: int = 80
    max_js_bytes: int = 1_000_000

    # Verification
    check_status: bool = True
    status_allow: str = DEFAULT_STATUS_ALLOW
    max_http_checks: int = 2000
    verify_tls: bool = True
    follow_redirects: bool = False
    drop_tracking_params: bool = True
    allow_private: bool = False

    # Tool locations (empty = automatic PATH / .tools/bin discovery)
    tools_dir: str = field(default_factory=_package_tools_dir)
    httpx_bin: str = ""
    katana_bin: str = ""
    gau_bin: str = ""
    subfinder_bin: str = ""
    dnsx_bin: str = ""
    nuclei_bin: str = ""

    # Nuclei / ASM (A1-A4) and passive-security inspection (W7/W9/W10).
    # Nuclei is active: it never runs for a passive scan.
    nuclei_enabled: bool = True
    nuclei_tags: tuple[str, ...] = ("takeover", "exposure", "misconfig", "cve", "tech")
    nuclei_severities: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
    nuclei_timeout: int = 300
    nuclei_rate_limit: int = 0            # 0 = use rate_limit
    nuclei_max_targets: int = 50
    security_headers: bool = True
    js_secret_scan: bool = True
    tls_check: bool = True
    security_max_targets: int = 20

    # Logging
    log_level: str = "INFO"
    log_file: str = ""

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.rate_limit < 1:
            raise ConfigError("rate_limit must be >= 1 (0 would mean unlimited)")
        if self.request_timeout <= 0:
            raise ConfigError("request_timeout must be > 0")
        if self.archive_timeout <= 0:
            raise ConfigError("archive_timeout must be > 0")
        if self.archive_pages < 1 or self.archive_pages > 20:
            raise ConfigError("archive_pages must be between 1 and 20")
        if self.tool_timeout < 1:
            raise ConfigError("tool_timeout must be >= 1")
        if self.max_concurrency < 1 or self.max_concurrency > 128:
            raise ConfigError("max_concurrency must be between 1 and 128")
        if self.retries < 0 or self.retries > 10:
            raise ConfigError("retries must be between 0 and 10")
        if self.crawl_depth < 0 or self.crawl_depth > 10:
            raise ConfigError("crawl_depth must be between 0 and 10")
        if self.max_urls < 1 or self.max_archive_urls < 1 or self.max_http_checks < 0:
            raise ConfigError("URL limits must be positive")
        if self.max_js_files < 0 or self.max_js_bytes < 1024:
            raise ConfigError("invalid JavaScript limits")
        if not self.nuclei_tags:
            raise ConfigError("nuclei_tags cannot be empty")
        if self.nuclei_timeout < 1:
            raise ConfigError("nuclei_timeout must be >= 1")
        if self.nuclei_rate_limit < 0:
            raise ConfigError("nuclei_rate_limit must be >= 0")
        if self.nuclei_max_targets < 1 or self.security_max_targets < 1:
            raise ConfigError("nuclei/security target limits must be >= 1")
        if self.crawler_backend not in CRAWLER_BACKENDS:
            raise ConfigError(f"crawler_backend must be one of {CRAWLER_BACKENDS}")
        unknown = sorted(set(self.archive_sources) - set(ARCHIVE_SOURCES))
        if unknown:
            raise ConfigError(f"unknown archive source(s): {', '.join(unknown)}")
        parse_status_ranges(self.status_allow)  # fail fast

    # ------------------------------------------------------------------ helpers
    @property
    def status_ranges(self) -> tuple[tuple[int, int], ...]:
        return parse_status_ranges(self.status_allow)

    def status_allowed(self, code: Optional[int]) -> bool:
        if code is None:
            return False
        return status_in_ranges(int(code), self.status_ranges)

    def allowed_sources(self) -> tuple[str, ...]:
        return tuple(s for s in self.archive_sources if s in ARCHIVE_SOURCES)

    def with_overrides(self, **kwargs) -> "Member2Config":
        clean = {k: v for k, v in kwargs.items() if v is not None}
        return replace(self, **clean)

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_env(cls, base: Optional["Member2Config"] = None) -> "Member2Config":
        """Apply MARSADIX_M2_* variables on top of `base` (or defaults)."""
        cfg = base or cls()
        updates: dict = {}
        for f in fields(cls):
            env_name = _ENV_PREFIX + f.name.upper()
            if env_name not in os.environ:
                continue
            default = getattr(cfg, f.name)
            if isinstance(default, bool):
                updates[f.name] = _env_bool(env_name, default)
            elif isinstance(default, int):
                updates[f.name] = _env_int(env_name, default)
            elif isinstance(default, tuple):
                updates[f.name] = _env_list(env_name, default)
            elif isinstance(default, float):
                raw = os.environ.get(env_name, "")
                try:
                    updates[f.name] = float(raw)
                except ValueError as exc:
                    raise ConfigError(f"{env_name} must be a number") from exc
            else:
                updates[f.name] = os.environ.get(env_name, default)
        return cfg.with_overrides(**updates)

    @classmethod
    def from_toml(cls, path: str, base: Optional["Member2Config"] = None) -> "Member2Config":
        p = Path(path)
        if not p.is_file():
            return base or cls()
        if tomllib is None:
            raise ConfigError("Reading config.toml needs Python 3.11+")
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
        known = {f.name for f in fields(cls)}
        if "member2" in data:
            section = data["member2"]
            if not isinstance(section, dict):
                raise ConfigError("[member2] must be a table")
            unknown = sorted(set(section) - known)
            if unknown:
                raise ConfigError(f"unknown [member2] keys: {', '.join(unknown)}")
            # In a shared config.toml, base keys at the root are also accepted;
            # the explicit [member2] table wins on conflict.
            section = {**{k: v for k, v in data.items() if k in known and k != "member2"},
                       **section}
        else:
            # A normal Marsadix config.toml: accept only keys this extension
            # understands and leave the base settings to marsadix.Config.
            section = {k: v for k, v in data.items() if k in known}
        cfg = base or cls()
        updates = {}
        for key, value in section.items():
            default = getattr(cfg, key)
            if isinstance(default, tuple):
                if not isinstance(value, (list, tuple)):
                    raise ConfigError(f"[member2].{key} must be a list")
                updates[key] = tuple(str(v) for v in value)
            elif isinstance(default, bool):
                if not isinstance(value, bool):
                    raise ConfigError(f"[member2].{key} must be true/false")
                updates[key] = value
            elif isinstance(default, int) and (isinstance(value, bool) or not isinstance(value, int)):
                raise ConfigError(f"[member2].{key} must be an integer")
            elif isinstance(default, float) and not isinstance(value, (int, float)):
                raise ConfigError(f"[member2].{key} must be a number")
            else:
                updates[key] = value
        return cfg.with_overrides(**updates)


def load_member2_config(path: Optional[str] = None,
                        base: Optional[Member2Config] = None) -> Member2Config:
    """Load config.toml [member2] then environment overrides."""
    cfg = base or Member2Config()
    if path:
        cfg = Member2Config.from_toml(path, cfg)
    else:
        default = Path("config.toml")
        if default.is_file():
            cfg = Member2Config.from_toml(str(default), cfg)
    cfg = Member2Config.from_env(cfg)
    cfg.validate()
    return cfg
