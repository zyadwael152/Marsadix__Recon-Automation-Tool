"""
Shared pytest fixtures, applied automatically to every test in tests/.

Why this exists: `marsadix scan` now runs a REAL recon stage (subprocess
tools + crt.sh/VirusTotal/AlienVault over the network). Many tests across
test_cli.py and test_pipeline.py call `scan` / run_scan(), so without this
fixture every test run performs real, slow, network-dependent work -- on a
filtering or slow network that can mean many minutes just to run `pytest`,
and the result depends on whatever network the machine happens to have at
that moment. Tests must be fast and deterministic.

This replaces ONLY the reference `discover_subdomains` that recon/stage.py
already imported into its own namespace (`from .discovery import
discover_subdomains`) -- it does not touch discovery.py itself, and a test
that wants to exercise the real discovery logic can still import and call
`marsadix.recon.discovery.discover_subdomains` directly, bypassing this.
"""

import pytest


def _fake_discover_subdomains(domain, api_keys=None, *args, **kwargs):
    # No tool calls, no HTTP requests: an empty result is enough for every
    # existing test, which only cares that the pipeline runs end-to-end,
    # not about what recon actually finds.
    return {}


@pytest.fixture(autouse=True)
def _no_real_recon_network(monkeypatch):
    monkeypatch.setattr(
        "marsadix.recon.stage.discover_subdomains", _fake_discover_subdomains)
