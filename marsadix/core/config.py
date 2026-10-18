"""
Configuration.  Priority (lowest -> highest):
    built-in defaults  <  config.toml  <  environment variables / .env

Secrets (API keys, webhooks) go in .env ONLY, never in config.toml or git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10
    tomllib = None


class ConfigError(ValueError):
    pass


SCAN_MODES = ("passive", "standard", "full")

# environment variable -> Config field
ENV_MAP = {
    "MARSADIX_DB": "db_path",
    "MARSADIX_OUTPUT_DIR": "output_dir",
    # CVE sources
    "NVD_API_KEY": "nvd_api_key",
    # Recon data sources (R2)
    "SHODAN_API_KEY": "shodan_api_key",
    "CENSYS_API_KEY": "censys_api_key",
    "SECURITYTRAILS_API_KEY": "securitytrails_api_key",
    "VIRUSTOTAL_API_KEY": "virustotal_api_key",
    "OTX_API_KEY": "otx_api_key",
    "CHAOS_API_KEY": "chaos_api_key",
    # Alert channels (M12, M14, M18)
    "DISCORD_WEBHOOK_URL": "discord_webhook",
    "TELEGRAM_BOT_TOKEN": "telegram_bot_token",
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

    # CVE sources
    nvd_api_key: str = field(default="", repr=False)

    # Recon data sources (R2) - any of these may be empty; a source with no
    # key is skipped, never fatal (see marsadix.recon.sources for the pattern)
    shodan_api_key: str = field(default="", repr=False)
    censys_api_key: str = field(default="", repr=False)
    securitytrails_api_key: str = field(default="", repr=False)
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

    def has_source_key(self, name: str) -> bool:
        """e.g. cfg.has_source_key('shodan') -> bool. Used to skip sources cleanly."""
        return bool(getattr(self, f"{name}_api_key", ""))


def load_dotenv(path: str = ".env") -> None:
    """Tiny .env reader (KEY=VALUE). Real environment variables win."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


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
        data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        unknown = set(data) - set(known)
        if unknown:
            raise ConfigError(f"unknown keys in {toml_path}: {', '.join(sorted(unknown))}")
        for k, v in data.items():
            want = type(getattr(cfg, k))
            if not isinstance(v, want):
                raise ConfigError(f"{k} in {toml_path} must be {want.__name__}")
            setattr(cfg, k, v)
    elif path:
        raise ConfigError(f"config file not found: {path}")

    for env, name in ENV_MAP.items():
        if os.environ.get(env):
            setattr(cfg, name, os.environ[env])

    cfg.validate()
    return cfg
