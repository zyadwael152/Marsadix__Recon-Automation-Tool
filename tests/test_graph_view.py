"""G5: offline interactive graph page."""
import json
import re
import shutil
import subprocess

import pytest

from marsadix.monitor.graph_view import render

GRAPH = {
    "nodes": [
        {"id": "a", "node_type": "subdomain", "label": "</script><img src=x onerror=alert(1)>", "attrs": '{"k": "v"}'},
        {"id": "b", "node_type": "cve", "label": "CVE-2021-1", "attrs": None},
    ],
    "edges": [{"src_id": "a", "dst_id": "b", "relation": "affected_by"}],
}
NODE = shutil.which("node")


def _code(page):
    return re.findall(r"<script>(.*?)</script>", page, re.S)[0]


def test_page_is_offline_and_cannot_be_broken_out_of():
    page = render(GRAPH, "T <b>x</b>")
    assert not re.findall(r"(?:src|href)=[\"']https?://", page)       # no CDN
    assert page.count("</script>") == 2                                # data block + code block only
    assert "<b>x</b>" not in page and "&lt;b&gt;" in page              # title escaped
    assert "innerHTML" not in page and "eval(" not in page


def test_page_has_directed_edges_filters_details_and_blast_radius():
    page = render(GRAPH)
    for needle in ('marker-end', 'id="arrow"', 'id="search"', 'id="hops"', 'id="legend"', "neighborhood("):
        assert needle in page


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_javascript_is_valid_and_core_logic_works(tmp_path):
    code = _code(render(GRAPH))
    (tmp_path / "g.js").write_text(code, encoding="utf-8")
    assert subprocess.run([NODE, "--check", str(tmp_path / "g.js")]).returncode == 0
    core = code[code.index("/*CORE*/"):code.index("/*ENDCORE*/")]
    js = core + r"""
const nodes=[0,1,2,3,4,5].map(i=>({id:'n'+i}));
const edges=[['n0','n1'],['n1','n2'],['n2','n3'],['n4','n5'],['n0','n0'],['n0','ghost']].map(([a,b])=>({src_id:a,dst_id:b,relation:'r'}));
const idx=buildIndex(nodes,edges), fail=m=>{console.error(m);process.exit(1)};
if(idx.links.length!==4) fail('self-loops/dangling edges must be dropped');
const d=neighborhood(idx,0,2); if(d.size!==3||d.has(3)) fail('2-hop neighbourhood');
if(neighborhood(idx,3,1).size!==2) fail('incoming edges must count');
if(neighborhood(idx,0,9).has(4)) fail('components must stay separate');
const pts=initPositions(6); let a=1; for(let i=0;i<400;i++){layoutStep(pts,idx.links,a);a*=0.985;}
if(!pts.every(p=>isFinite(p.x)&&isFinite(p.y))) fail('layout produced NaN');
const dist=(i,j)=>Math.hypot(pts[i].x-pts[j].x,pts[i].y-pts[j].y);
if(!(dist(0,1)<dist(0,4))) fail('linked nodes should be closer than unrelated ones');
"""
    (tmp_path / "core.js").write_text(js, encoding="utf-8")
    r = subprocess.run([NODE, str(tmp_path / "core.js")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
