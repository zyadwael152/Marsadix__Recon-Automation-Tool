"""Deprecated compatibility shim for the former Web-owned Nuclei runner.

Nuclei execution belongs to ``marsadix.asm``. Import from
``marsadix.asm.nuclei`` in new code; Web Recon must not invoke this module.
"""
from marsadix.asm.nuclei import NucleiBatch, run_nuclei

__all__ = ["NucleiBatch", "run_nuclei"]
