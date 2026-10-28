"""
R4: Source Confidence.

A host's confidence score (0-100) blends three signals:
  - how many independent sources found it (more sources = more likely real)
  - whether it resolves over DNS (recon/resolver.py already filters to only
    resolving hosts before this runs, so every host reaching this module
    already earns that point)
  - whether it actually responds over HTTP - only checked when the scan
    mode allows contacting the target (passive mode must not send any
    traffic; see core/pipeline.py Context.allows())

Any one signal alone is weak on its own (crt.sh in particular surfaces
long-dead certificate names that still "exist" but are not live); combining
them gets closer to "this host is real and worth attention".
"""

from typing import Dict, Iterable, List

SOURCE_WEIGHT = 15    # points per independent source
SOURCE_CAP = 60       # max points from source count alone
RESOLVED_BONUS = 20   # every host here already resolved
HTTP_BONUS = 20


def compute_source_confidence(hosts_sources: Dict[str, List[str]],
                               http_live: Iterable[str] = ()) -> Dict[str, int]:
    """
    hosts_sources: {host: [source names]} - every host here already resolved.
    http_live: hosts confirmed to respond over HTTP. Empty when not checked
    (e.g. passive mode) - those hosts simply don't get the HTTP bonus.
    """
    live_set = set(http_live)
    scores = {}
    for host, sources in hosts_sources.items():
        score = min(SOURCE_CAP, len(sources) * SOURCE_WEIGHT)
        score += RESOLVED_BONUS
        if host in live_set:
            score += HTTP_BONUS
        scores[host] = min(100, score)
    return scores
