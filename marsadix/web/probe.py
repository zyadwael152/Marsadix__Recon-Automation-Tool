"""
Thin async wrappers around httpx and katana.

Both tools send traffic to the target. `rate_limit` (requests per second) is
passed straight to their `-rl` flag. It matters more than it looks: without it
httpx and katana both default to 150 requests/second, far more than the
config.toml / --rate value the user asked for would suggest, and enough to
knock over a small server. (Flags checked against httpx v1.12 and katana v1.8.)

What to expect from the number: it is the tools' own limiter, so it is an
AVERAGE. Measured against a local server with -rl 5, the busiest 1-second
window still saw 9-10 requests (about 2x), while without the flag the same run
peaked at 30-36 req/s. Treat --rate as "about N per second, short bursts up to
roughly 2N", and pick a lower number for fragile targets.
"""

import asyncio
import json
import logging
import os
from contextlib import suppress
from typing import List, Optional, Set
from dataclasses import dataclass
from ..core import limits, toolstatus
from ..core.aproc import MAX_OUTPUT_BYTES, kill_process
from ..core.childenv import child_env
from .tools import ArchiveRecord, CrawlRecord, VerifyRecord, ToolExecution


