"""
R17: Missing Asset Hunter.

How many hosts each discovery source (subfinder, crt.sh, amass...) found,
and which hosts only ONE source caught. A single-source host is worth a
second look: it's also a single point of *failure* - if that one tool
hadn't run, we'd never have found it, which is exactly the "what did we
miss" question this feature answers.

Uses db.get_source_coverage(), which Person 5 already built for this
purpose (see its docstring: "useful for the Missing Asset Hunter, R17").
"""

import logging
from .. import db

logger = logging.getLogger(__name__)


def log_missing_asset_hunter(conn, scan_id: int) -> dict:
    coverage = db.get_source_coverage(conn, scan_id)
    per_source = coverage["per_source"]
    singles = coverage["single_source_hosts"]

    logger.info("[*] Missing Asset Hunter (R17):")
    if not per_source:
        logger.info("    No sources recorded for this scan.")
        return coverage

    for source, count in sorted(per_source.items(), key=lambda kv: -kv[1]):
        logger.info(f"    {source}: {count} host(s)")

    if singles:
        shown = ", ".join(singles[:10])
        more = f" (+{len(singles) - 10} more)" if len(singles) > 10 else ""
        logger.info(f"    {len(singles)} host(s) found by only ONE source: {shown}{more}")
    else:
        logger.info("    No single-source hosts - every host was confirmed by 2+ sources.")

    return coverage
