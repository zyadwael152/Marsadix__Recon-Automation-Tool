"""Read-only graph investigations from Person 3; never invent exposure edges."""
from collections import deque
from .. import db
from ..core.attackpaths import compute_attack_paths
from ..core.graph import get_shared_infrastructure, blast_radius

def attack_paths(conn, scan_id, max_hops=6):
    return compute_attack_paths(db.get_graph(conn, scan_id), max_hops=max_hops)

def shared_infrastructure(conn, scan_id):
    return get_shared_infrastructure(conn, scan_id)

def shadow_it_candidates(conn, scan_id):
    """Heuristics only: unknown ownership is NOT proof of unauthorized IT."""
    assets = db.get_assets(conn, scan_id)
    return [{'host': a['host'], 'reason': 'no owner information available', 'confidence': 'unverified'}
            for a in assets if a['in_scope'] and not a['asn_owner']]

def butterfly_effect(conn, scan_id, node_id, max_hops=2):
    if not 1 <= max_hops <= 8:
        raise ValueError('max_hops must be between 1 and 8')
    return blast_radius(conn, scan_id, node_id, max_hops)
