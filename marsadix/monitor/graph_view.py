"""Offline interactive graph HTML (G5). No external CDN or target requests."""
import argparse
import html
import json
from pathlib import Path
from .. import db
from ..core.graph import build_graph

def render(graph, title='Marsadix Knowledge Graph'):
    data = json.dumps(graph).replace('<', '\u003c').replace('>', '\u003e').replace('&', '\u0026')
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{margin:0;background:#0c1220;color:#eee;font:14px system-ui}}header{{display:flex;align-items:center;gap:12px;padding:12px 18px;background:#152033}}input{{background:#25334a;color:white;border:1px solid #5d718e;border-radius:6px;padding:7px}}button{{padding:7px;cursor:pointer}}svg{{height:calc(100vh - 65px);width:100vw;touch-action:none}}.edge{{stroke:#65809e;stroke-opacity:.45}}.node{{cursor:grab}}text{{fill:white;font-size:11px;pointer-events:none}}#info{{margin-left:auto}}</style>
<header><strong>Knowledge Graph</strong><input id="search" aria-label="Filter nodes" placeholder="Filter nodes..."/><button id="reset">Reset view</button><span id="info"></span></header><svg id="canvas" role="img" aria-label="Interactive network graph"><g id="camera"><g id="links"></g><g id="vertices"></g></g></svg>
<script type="application/json" id="graph-data">{data}</script><script>
const graph=JSON.parse(document.getElementById('graph-data').textContent);
const svg=document.getElementById('canvas'), camera=document.getElementById('camera'), links=document.getElementById('links'), verts=document.getElementById('vertices');
const NS='http://www.w3.org/2000/svg', nodes=graph.nodes, edges=graph.edges;
const positions=new Map(); const colors={{subdomain:'#38bdf8',ip:'#a78bfa',cve:'#fb7185',finding:'#f59e0b',technology:'#34d399',service:'#d4d4d8'}};
const radius=Math.max(180,nodes.length*7);nodes.forEach((n,i)=>{{let angle=i*Math.PI*(3-Math.sqrt(5));positions.set(n.id,{{x:Math.cos(angle)*Math.sqrt(i+1)*27,y:Math.sin(angle)*Math.sqrt(i+1)*27}})}});
const mk=(tag,attrs,parent)=>{{let el=document.createElementNS(NS,tag);Object.entries(attrs).forEach(([k,v])=>el.setAttribute(k,v));parent.appendChild(el);return el}};
const linkEls=edges.filter(e=>positions.has(e.src_id)&&positions.has(e.dst_id)).map(e=>{{let a=positions.get(e.src_id),b=positions.get(e.dst_id);return {{e,el:mk('line',{{x1:a.x,y1:a.y,x2:b.x,y2:b.y,'class':'edge'}},links)}}}});
const nodeEls=nodes.map(n=>{{let p=positions.get(n.id),g=mk('g',{{transform:`translate(${{p.x}} ${{p.y}})`,'class':'node'}},verts);mk('circle',{{r:7,fill:colors[n.node_type]||'#94a3b8'}},g);let t=mk('text',{{x:11,y:4}},g);t.textContent=n.label.slice(0,48);let tip=mk('title',{{}},g);tip.textContent=n.node_type+': '+n.label;return {{n,g}}}});
let x=innerWidth/2,y=(innerHeight-65)/2,scale=1;function draw(){{camera.setAttribute('transform',`translate(${{x}} ${{y}}) scale(${{scale}})`)}}draw();let drag=null;
svg.addEventListener('pointerdown',e=>{{drag={{x:e.clientX,y:e.clientY}};svg.setPointerCapture(e.pointerId)}});
svg.addEventListener('pointermove',e=>{{if(drag){{x+=e.clientX-drag.x;y+=e.clientY-drag.y;drag={{x:e.clientX,y:e.clientY}};draw()}}}});
svg.addEventListener('pointerup',()=>drag=null);
svg.addEventListener('wheel',e=>{{e.preventDefault();scale=Math.max(.15,Math.min(6,scale*(e.deltaY<0?1.13:.89)));draw()}},{{passive:false}});
document.getElementById('reset').onclick=()=>{{x=innerWidth/2;y=(innerHeight-65)/2;scale=1;draw()}};
document.getElementById('search').oninput=e=>{{let q=e.target.value.toLowerCase();let found=new Set(nodeEls.filter(v=>v.n.label.toLowerCase().includes(q)||v.n.node_type.includes(q)).map(v=>v.n.id));nodeEls.forEach(v=>v.g.style.opacity=!q||found.has(v.n.id)?1:.1);linkEls.forEach(v=>v.el.style.opacity=!q||found.has(v.e.src_id)||found.has(v.e.dst_id)?1:.05)}};
document.getElementById('info').textContent=nodes.length+' nodes / '+edges.length+' relationships';
</script></html>"""

def main(argv=None):
    ap=argparse.ArgumentParser(description='Export interactive graph without network calls')
    ap.add_argument('target'); ap.add_argument('--db', default='marsadix.db'); ap.add_argument('--scan-id', type=int); ap.add_argument('--out', default='graph.html')
    args=ap.parse_args(argv);conn=db.connect(args.db)
    try:
        db.init_db(conn)
        row=(conn.execute('SELECT id FROM scans WHERE target=? ORDER BY id DESC LIMIT 1',(args.target,)).fetchone()
             if args.scan_id is None else conn.execute('SELECT id FROM scans WHERE id=? AND target=?',(args.scan_id,args.target)).fetchone())
        if row is None: ap.error('no matching scan')
        graph=db.get_graph(conn,row['id'])
        if not graph['nodes']:
            build_graph(conn,row['id']);graph=db.get_graph(conn,row['id'])
        Path(args.out).write_text(render(graph, 'Marsadix: '+args.target),encoding='utf-8')
        print(args.out);return 0
    finally: conn.close()

if __name__=='__main__': raise SystemExit(main())
