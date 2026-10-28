"""
Configuration.  Priority (lowest -> highest):
    built-in defaults  <  config.toml  <  environment variables / .env

Secrets (API keys, webhooks) go in .env ONLY, never in config.toml or git.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10
    tomllib = None

from .textfile import read_text

log = logging.getLogger(__name__)


class ConfigError(ValueError):
    pass


SCAN_MODES = ("passive", "standard", "full")

# environment variable -> Config field
ENV_MAP = {
    "MARSADIX_DB": "db_path",
    "MARSADIX_OUTPUT_DIR": "output_dir",
    # Recon tuning
    "MARSADIX_DNS_RATE_LIMIT": "dns_rate_limit",
    "MARSADIX_MAX_PERMUTATIONS": "max_permutations",
    "MARSADIX_BRUTEFORCE_WORDLIST": "bruteforce_wordlist",
    "MARSADIX_RESOLVERS_FILE": "resolvers_file",
    # CVE sources
    "NVD_API_KEY": "nvd_api_key",
    # Recon data sources (R2)
    "SHODAN_API_KEY": "shodan_api_key",
    "CENSYS_API_KEY": "censys_api_key",
    "VIRUSTOTAL_API_KEY": "virustotal_api_key",
    "OTX_API_KEY": "otx_api_key",
    "CHAOS_API_KEY": "chaos_api_key",
    # Alert channels (M12, M14, M18)
    "DISCORD_WEBHOOK_URL": "discord_webhook",
    # This is the env var *name*, not a secret value.
    "TELEGRAM_BOT_TOKEN": "telegram_bot_token",  # nosec B105
    "TELEGRAM_CHAT_ID": "telegram_chat_id",
    "WEBHOOK_URL": "webhook_url",
}


@dataclass
class Config:
    db_path: str = "marsadix.db"
    output_dir: str = "output"
    max_depth: int = 2            # recursion depth limit
    rate_limit: int = 50          # requests/second handed to the tools
    tool_timeout: int = 600       # seconds allowed per external tool
    scan_mode: str = "passive"    # passive | standard | full               (C15)
    allow_injection: bool = False  # explicit opt-in for injection checks   (A5)

    # Recon tuning. recon/stage.py reads these with getattr(...) so it keeps
    # working without them -- which meant that, until they existed here, they
    # could not be set at all: DNS resolution and bruteforce ran with no rate
    # limit and the VHost step (needs a wordlist) could never run.
    dns_rate_limit: int = 0        # DNS queries/second; 0 = the tool's own default
    max_permutations: int = 20000  # cap on generated permutation candidates
    bruteforce_wordlist: str = ""  # path; "" = the small built-in list
    resolvers_file: str = ""       # path to a validated resolver list; "" = built-in public ones

    # CVE sources
    nvd_api_key: str = field(default="", repr=False)

    # Recon data sources (R2) - any of these may be empty; a source with no
    # key is skipped, never fatal (see marsadix.recon.sources for the pattern)
    shodan_api_key: str = field(default="", repr=False)
    censys_api_key: str = field(default="", repr=False)
    virustotal_api_key: str = field(default="", repr=False)
    otx_api_key: str = field(default="", repr=False)
    chaos_api_key: str = field(default="", repr=False)

    # Alert channels (M12, M14, M18)
    discord_webhook: str = field(default="", repr=False)
    telegram_bot_token: str = field(default="", repr=False)
    telegram_chat_id: str = field(default="", repr=False)
    webhook_url: str = field(default="", repr=False)

    def validate(self) -> None:
        if self.max_depth < 0:
            raise ConfigError("max_depth must be >= 0")
        if self.rate_limit < 1:
            raise ConfigError("rate_limit must be >= 1")
        if self.tool_timeout < 1:
            raise ConfigError("tool_timeout must be >= 1")
        if self.scan_mode not in SCAN_MODES:
            raise ConfigError(f"scan_mode must be one of {SCAN_MODES}")
        if self.dns_rate_limit < 0:
            raise ConfigError("dns_rate_limit must be >= 0 (0 = tool default)")
        if self.max_permutations < 1:
            raise ConfigError("max_permutations must be >= 1")

    def has_source_key(self, name: str) -> bool:
        """e.g. cfg.has_source_key('shodan') -> bool. Used to skip sources cleanly."""
        return bool(getattr(self, f"{name}_api_key", ""))


def load_dotenv(path: str = ".env") -> None:
    """
    Tiny .env reader (KEY=VALUE). Real environment variables win.

    Only the variables Marsadix knows (ENV_MAP) are read. It used to copy EVERY
    line into the process environment, and every external tool the scan starts
    inherits that environment: a .env in the current directory could set
    LD_PRELOAD (code execution), HTTPS_PROXY (traffic interception),
    PYTHONSTARTUP, PATH-like variables... so running Marsadix inside a folder you
    did not create was unsafe.
    """
    p = Path(path)
    if not p.is_file():
        return
    try:
        text = read_text(p)
    except (ValueError, OSError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    ignored = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if key not in ENV_MAP:
            ignored.append(key)
            continue
        os.environ.setdefault(key, value.strip().strip('"').strip("'"))
    if ignored:
        log.warning("%s: ignoring unknown variable(s): %s (only Marsadix's own settings are read)",
                    path, ", ".join(sorted(set(ignored))))


def load_config(path: Optional[str] = None) -> Config:
    """Load config. `path` None -> use ./config.toml if it exists."""
    load_dotenv()
    cfg = Config()
    known = {f.name: f for f in fields(Config)}

    toml_path = Path(path) if path else Path("config.toml")
    if toml_path.is_file():
        if tomllib is None:
            raise ConfigError(
                "Reading config.toml needs Python 3.11+. "
                "Upgrade Python or use environment variables instead.")
        try:
            data = tomllib.loads(read_text(toml_path))
        except (ValueError, OSError) as e:          # tomllib.TOMLDecodeError is a ValueError
            raise ConfigError(f"cannot read {toml_path}: {e}") from e
        unknown = set(data) - set(known)
        if unknown:
            raise ConfigError(f"unknown keys in {toml_path}: {', '.join(sorted(unknown))}")
        secrets = sorted(k for k in data if not known[k].repr)          # fields declared repr=False
        if secrets:
            log.warning("%s contains secret setting(s) (%s): keep keys in .env, which git ignores, "
                        "not in a file that is easy to commit", toml_path, ", ".join(secrets))
        for k, v in data.items():
            want = type(getattr(cfg, k))
            if not isinstance(v, want):
                raise ConfigError(f"{k} in {toml_path} must be {want.__name__}")
            setattr(cfg, k, v)
    elif path:
        raise ConfigError(f"config file not found: {path}")

    for env, name in ENV_MAP.items():
        raw = os.environ.get(env)
        if not raw:
            continue
        want = type(getattr(cfg, name))
        if want is int:                      # environment values are always text
            try:
                setattr(cfg, name, int(raw))
            except ValueError:
                raise ConfigError(f"{env} must be a whole number, got {raw!r}") from None
        else:
            setattr(cfg, name, raw)

    cfg.validate()
    return cfg
