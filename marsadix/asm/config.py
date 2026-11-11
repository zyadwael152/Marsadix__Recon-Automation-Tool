"""ASM-owned configuration for the Nuclei vulnerability engine.

The Web Recon configuration remains responsible for discovery and enrichment.
ASM reads only its own MARSADIX_ASM_* settings plus shared runtime limits.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ASMConfig:
    db_path: str = "marsadix.db"
    output_dir: str = "output"
    write_outputs: bool = False
    tools_dir: str = ""
    nuclei_bin: str = ""
    httpx_bin: str = ""
    katana_bin: str = ""
    gau_bin: str = ""
    subfinder_bin: str = ""
    dnsx_bin: str = ""
    rate_limit: int = 10
    tool_timeout: int = 300
    request_timeout: int = 10
    retries: int = 1
    dns_timeout: float = 5.0
    allow_private: bool = False
    nuclei_enabled: bool = True
    nuclei_tags: tuple[str, ...] = ("takeover", "exposure", "misconfig", "cve", "tech")
    nuclei_severities: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
    # Template classes that must never run in a scan that only DETECTS (they can disrupt the target).
    nuclei_exclude_tags: tuple[str, ...] = ("dos", "fuzz", "intrusive")
    nuclei_timeout: int = 300
    nuclei_rate_limit: int = 0
    nuclei_max_targets: int = 50
    nuclei_code: bool = False
    nuclei_file: bool = False
    nuclei_self_contained: bool = False
    nuclei_dast: bool = False
    nuclei_headless: bool = False

    @classmethod
    def from_runtime(cls, runtime=None) -> "ASMConfig":
        """Build ASM settings without loading or depending on Web Recon config."""
        cfg = cls()
        if runtime is not None:
            for name in ("db_path", "output_dir", "rate_limit", "tool_timeout"):
                if hasattr(runtime, name):
                    setattr(cfg, name, getattr(runtime, name))
        cfg.tools_dir = str(Path(__file__).resolve().parents[2] / ".tools" / "bin")
        for name in ("db_path", "output_dir", "nuclei_bin", "tools_dir"):
            value = os.getenv(f"MARSADIX_ASM_{name.upper()}")
            if value:
                setattr(cfg, name, value)
        for name in ("nuclei_enabled", "nuclei_code", "nuclei_file",
                     "nuclei_self_contained", "nuclei_dast", "nuclei_headless",
                     "allow_private"):
            value = os.getenv(f"MARSADIX_ASM_{name.upper()}")
            if value is not None:
                setattr(cfg, name, value.strip().lower() in {"1", "true", "yes", "on"})
        for name in ("rate_limit", "tool_timeout", "request_timeout", "retries",
                     "nuclei_timeout", "nuclei_rate_limit", "nuclei_max_targets"):
            value = os.getenv(f"MARSADIX_ASM_{name.upper()}")
            if value:
                setattr(cfg, name, int(value))
        for name in ("nuclei_tags", "nuclei_severities", "nuclei_exclude_tags"):
            value = os.getenv(f"MARSADIX_ASM_{name.upper()}")
            if value:
                setattr(cfg, name, tuple(x.strip().lower() for x in value.split(",") if x.strip()))
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.rate_limit < 1 or self.tool_timeout < 1 or self.request_timeout < 1:
            raise ValueError("ASM rate_limit, tool_timeout and request_timeout must be positive")
        if self.nuclei_timeout < 1 or self.nuclei_max_targets < 1:
            raise ValueError("ASM Nuclei timeout and max targets must be positive")
        if self.nuclei_rate_limit < 0 or self.retries < 0:
            raise ValueError("ASM Nuclei rate limit and retries cannot be negative")
        if not self.nuclei_tags:
            raise ValueError("ASM nuclei_tags cannot be empty")
