"""
Lets teammates add a module WITHOUT editing the CLI/pipeline:
the CLI looks for 'package.module:function' and skips it if it doesn't exist yet.
"""

from __future__ import annotations

import importlib
from typing import Callable, Optional


def load_callable(path: str) -> Optional[Callable]:
    """'marsadix.monitor.runner:run' -> the function, or None if not written yet."""
    mod_name, _, func_name = path.partition(":")
    try:
        mod = importlib.import_module(mod_name)
    except ModuleNotFoundError as e:
        # Only 'the module itself is missing' counts as "not implemented yet".
        # A missing dependency INSIDE the module (e.g. jinja2) must still blow up.
        if e.name and (mod_name == e.name or mod_name.startswith(e.name + ".")):
            return None
        raise
    return getattr(mod, func_name, None)
