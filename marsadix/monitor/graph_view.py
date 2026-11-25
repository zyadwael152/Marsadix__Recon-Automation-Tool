"""Offline interactive graph HTML (G5): force-directed layout, directed edges, node details,
type filters, search and N-hop blast-radius highlighting. No external CDN or target requests."""
import argparse
import html
import json
from pathlib import Path
from .. import db
from ..core.graph import build_graph

TEMPLATE = r"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title>
<style>
:root{--bg:#0c1220;--panel:#152033;--line:#5d718e;--txt:#e8edf5;--mut:#9fb0c7}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px system-ui,sans-serif;overflow:hidden}
header{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:10px 14px;background:var(--panel);height:56px}
input,select,button{background:#25334a;color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
button{cursor:pointer}button:hover{background:#2f4262}
#wrap{display:flex;height:calc(100vh - 56px)}svg{flex:1;min-width:0;touch-action:none;cursor:grab}svg.panning{cursor:grabbing}
aside{width:320px;max-width:42vw;background:var(--panel);border-left:1px solid #22314a;padding:12px;overflow:auto}
h3{margin:.2em 0 .5em;font-size:14px}.mut{color:var(--mut)}.chip{display:inline-flex;align-items:center;gap:5px;margin:0 8px 6px 0;cursor:pointer;user-select:none}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.edge{stroke:#65809e;stroke-opacity:.5;fill:none}.edge.hl{stroke:#fbbf24;stroke-opacity:1;stroke-width:2}
.node{cursor:pointer}.node circle{stroke:#0c1220;stroke-width:1.5}.node.sel circle{stroke:#fff;stroke-width:3}
text.badge{display:block;fill:#fbbf24;font-weight:700;text-anchor:middle}.ring{fill:none!important;stroke:#fbbf24!important;stroke-dasharray:3 3}
text{display:none;fill:var(--txt);font-size:11px;pointer-events:none;paint-order:stroke;stroke:#0c1220;stroke-width:3px}
.node.lbl text{display:block}.dim{opacity:.08}.li{cursor:pointer;padding:2px 0;word-break:break-all}.li:hover{text-decoration:underline}
dl{margin:0}dt{color:var(--mut);margin-top:6px}dd{margin:0;word-break:break-all}
</style>
<header><strong>Knowledge Graph</strong>
<input id="search" aria-label="Filter nodes" placeholder="Search label / type...">
<label class="mut">Highlight radius <select id="hops"><option>1</option><option selected>2</option><option>3</option><option>4</option></select> hops</label>
<button id="fit">Fit</button><button id="expandAll">Expand all</button><button id="collapseAll">Collapse all</button><button id="relayout">Re-layout</button><button id="clear">Clear selection</button>
<span id="info" class="mut" style="margin-left:auto"></span></header>
<div id="wrap"><svg id="canvas" role="img" aria-label="Interactive directed network graph">
<defs><marker id="arrow" viewBox="0 0 10 10" refX="19" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#8aa4c4"/></marker></defs>
<g id="camera"><g id="links"></g><g id="vertices"></g></g></svg>
<aside><h3>Node types</h3><div id="legend"></div><h3>Details</h3><div id="details" class="mut">Click a node to see its attributes, its connections and everything within the chosen number of hops (blast radius). Drag to pin a node, scroll to zoom, drag the background to pan.</div></aside></div>
<script type="application/json" id="graph-data">__DATA__</script>
<script>
/*CORE*/
function buildIndex(nodes, edges){
  const byId=new Map(nodes.map((n,i)=>[n.id,i]));
  const out=nodes.map(()=>[]), inn=nodes.map(()=>[]), links=[];
  for(const e of edges){
    const a=byId.get(e.src_id), b=byId.get(e.dst_id);
    if(a===undefined||b===undefined||a===b) continue;
    links.push({a,b,relation:e.relation||''}); out[a].push(b); inn[b].push(a);
  }
  return {byId,out,inn,links};
}
function neighborhood(idx, start, hops){            // undirected BFS: everything a node can reach / be reached from
  const dist=new Map([[start,0]]), q=[start];
  while(q.length){
    const u=q.shift(), d=dist.get(u); if(d>=hops) continue;
    for(const v of idx.out[u].concat(idx.inn[u])) if(!dist.has(v)){dist.set(v,d+1); q.push(v);}
  }
  return dist;
}
function SCALE_FOR(n){return Math.max(1.5,Math.sqrt(n/16));}   // spacing grows with the graph so 800 nodes are not packed like 40
function initPositions(n){
  const pts=[]; for(let i=0;i<n;i++){const a=i*Math.PI*(3-Math.sqrt(5)), r=26*SCALE_FOR(n)*Math.sqrt(i+1); pts.push({x:Math.cos(a)*r,y:Math.sin(a)*r,vx:0,vy:0,fixed:false});}
  return pts;
}
function layoutStep(pts, links, alpha){                // grid-based repulsion keeps it ~O(n) for big graphs
  const SC=SCALE_FOR(pts.reduce((a,p)=>a+(p.hidden?0:1),0)), CELL=140*SC, grid=new Map(), key=(x,y)=>x+','+y;
  pts.forEach((p,i)=>{if(p.hidden)return;const k=key(Math.floor(p.x/CELL),Math.floor(p.y/CELL)); (grid.get(k)||grid.set(k,[]).get(k)).push(i);});
  pts.forEach((p,i)=>{
    if(p.hidden)return;const cx=Math.floor(p.x/CELL), cy=Math.floor(p.y/CELL);
    for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++){
      const cell=grid.get(key(cx+dx,cy+dy)); if(!cell) continue;
      for(const j of cell){ if(j<=i) continue; const q=pts[j];
        let rx=p.x-q.x, ry=p.y-q.y, d2=rx*rx+ry*ry; if(d2>CELL*CELL) continue; if(d2<1){rx=Math.random()-.5;ry=Math.random()-.5;d2=1;}
        const d=Math.sqrt(d2), f=(2600*SC*SC/d2)*alpha, fx=rx/d*f, fy=ry/d*f;
        p.vx+=fx;p.vy+=fy;q.vx-=fx;q.vy-=fy; }
    }
  });
  for(const l of links){
    if(pts[l.a].hidden||pts[l.b].hidden) continue;
    const p=pts[l.a], q=pts[l.b], rx=q.x-p.x, ry=q.y-p.y, d=Math.sqrt(rx*rx+ry*ry)||1, f=(d-70*SC)*0.04*alpha;
    p.vx+=rx/d*f;p.vy+=ry/d*f;q.vx-=rx/d*f;q.vy-=ry/d*f;
  }
  for(const p of pts){ if(p.hidden) continue; p.vx-=p.x*0.004/SC*alpha; p.vy-=p.y*0.004/SC*alpha;                // weak pull to the centre
    if(p.fixed){p.vx=p.vy=0;continue;} p.x+=p.vx*0.6; p.y+=p.vy*0.6; p.vx*=0.55; p.vy*=0.55; }
}
/*ENDCORE*/
const graph=JSON.parse(document.getElementById('graph-data').textContent);
const NS='http://www.w3.org/2000/svg', nodes=graph.nodes||[], edges=graph.edges||[];
const COLORS={subdomain:'#38bdf8',ip:'#a78bfa',cve:'#fb7185',finding:'#f59e0b',technology:'#34d399',service:'#d4d4d8'};
const color=t=>COLORS[t]||'#94a3b8';
const svg=document.getElementById('canvas'), camera=document.getElementById('camera');
const linkLayer=document.getElementById('links'), vertLayer=document.getElementById('vertices');
const idx=buildIndex(nodes,edges), pts=initPositions(nodes.length);
const mk=(tag,attrs,parent)=>{const el=document.createElementNS(NS,tag);for(const k in attrs)el.setAttribute(k,attrs[k]);if(parent)parent.appendChild(el);return el;};
// --- asset clusters: a node with a single remaining link is folded under the node it hangs from
// (technologies/findings under their subdomain, subdomains under their IP, ...). Nothing is dropped:
// a folded node shows a "+N" badge, click it to expand, search expands it automatically.
const COLLAPSE_AT=60, nbrs=nodes.map((_,i)=>[...new Set(idx.out[i].concat(idx.inn[i]))]);
const parent=nodes.map(()=>-1), kids=nodes.map(()=>[]), expanded=new Set();
{ const alive=nodes.map(()=>true), dg=nbrs.map(a=>a.length), q=[];
  dg.forEach((d,i)=>{if(d===1)q.push(i);});
  while(q.length){const u=q.shift(); if(!alive[u]||dg[u]!==1) continue;
    const p=nbrs[u].find(v=>alive[v]); if(p===undefined) continue;
    alive[u]=false;parent[u]=p;kids[p].push(u);dg[p]--; if(dg[p]===1) q.push(p);} }
const countCache=new Map();
function below(i){ if(countCache.has(i)) return countCache.get(i); const c={},add=(t,n)=>c[t]=(c[t]||0)+n;
  for(const k of kids[i]){add(nodes[k].node_type,1);const d=below(k);for(const t in d)add(t,d[t]);} countCache.set(i,c); return c; }
const total=i=>Object.values(below(i)).reduce((a,b)=>a+b,0);
function isShown(i){ for(let p=parent[i];p!==-1;p=parent[p]) if(!expanded.has(p)) return false; return true; }
function expandAncestors(i){ for(let p=parent[i];p!==-1;p=parent[p]) expanded.add(p); }
if(nodes.length<=COLLAPSE_AT) kids.forEach((k,i)=>{if(k.length)expanded.add(i);});
const degree=nodes.map((_,i)=>idx.out[i].length+idx.inn[i].length);
const linkEls=idx.links.map(l=>{const el=mk('line',{'class':'edge','marker-end':'url(#arrow)'},linkLayer);const t=mk('title',{},el);t.textContent=nodes[l.a].label+'  --'+l.relation+'-->  '+nodes[l.b].label;return el;});
const nodeEls=nodes.map((n,i)=>{const g=mk('g',{'class':'node'},vertLayer);
  if(kids[i].length){mk('circle',{'class':'ring',r:12+Math.min(9,Math.sqrt(degree[i])*2)},g);mk('text',{'class':'badge',x:0,y:-18},g);}
  mk('circle',{r:6+Math.min(9,Math.sqrt(degree[i])*2),fill:color(n.node_type)},g);
  const t=mk('text',{x:12,y:4},g);t.textContent=String(n.label).slice(0,48);
  g.addEventListener('pointerenter',()=>g.classList.add('lbl'));g.addEventListener('pointerleave',()=>updateLabels());
  const tip=mk('title',{},g);tip.textContent=n.node_type+': '+n.label; return g;});
let cam={x:innerWidth/2-160,y:(innerHeight-56)/2,k:1}, alpha=1, hidden=new Set(), selected=null, query='';
const drawCam=()=>camera.setAttribute('transform','translate('+cam.x+' '+cam.y+') scale('+cam.k+')');
function draw(){
  pts.forEach((p,i)=>nodeEls[i].setAttribute('transform','translate('+p.x+' '+p.y+')'));
  idx.links.forEach((l,i)=>{const a=pts[l.a],b=pts[l.b],e=linkEls[i];e.setAttribute('x1',a.x);e.setAttribute('y1',a.y);e.setAttribute('x2',b.x);e.setAttribute('y2',b.y);});
}
let camMoved=false, ticking=false;
function tick(){ if(alpha>0.02){layoutStep(pts,idx.links,alpha);alpha*=0.985;draw();requestAnimationFrame(tick);} else {ticking=false; if(!camMoved) fit();} }
function kick(a){ alpha=Math.max(alpha,a); if(!ticking){ticking=true;requestAnimationFrame(tick);} }
function placeNew(){ nodes.forEach((n,i)=>{ if(isShown(i)&&pts[i].hidden!==false&&parent[i]!==-1){        // newly shown: start next to its parent
  const p=pts[parent[i]],a=Math.random()*6.283,r=24*SCALE_FOR(nodes.filter((_,j)=>isShown(j)).length); pts[i].x=p.x+Math.cos(a)*r;pts[i].y=p.y+Math.sin(a)*r;pts[i].vx=pts[i].vy=0; } }); }
function toggle(i){ if(!kids[i].length) return; expanded.has(i)?expanded.delete(i):expanded.add(i); placeNew(); applyView(); kick(.7); }
function setAll(open){ expanded.clear(); if(open) kids.forEach((k,i)=>{if(k.length)expanded.add(i);}); placeNew(); applyView(); camMoved=false; kick(1); }   // re-fit once the layout has settled
function fit(){ if(!pts.length) return; let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
  const vs=pts.filter(p=>!p.hidden), xs=vs.map(p=>p.x).sort((a,b)=>a-b), ys=vs.map(p=>p.y).sort((a,b)=>a-b), lo=Math.floor(vs.length*.02), hi=Math.max(lo,Math.ceil(vs.length*.98)-1);
  if(!vs.length) return; x0=xs[lo];x1=xs[hi];y0=ys[lo];y1=ys[hi];
  const w=svg.clientWidth||800,h=svg.clientHeight||600,k=Math.min(pts.length<=60?1.2:2,.9*Math.min(w/Math.max(1,x1-x0),h/Math.max(1,y1-y0)));
  cam={k,x:w/2-k*(x0+x1)/2,y:h/2-k*(y0+y1)/2};drawCam(); }
const IMPORTANT=new Set(['finding','cve','asn','cdn']);
const HUB_DEGREE=Math.max(4,Math.round(Math.sqrt(nodes.length)/2));
function updateLabels(near){            // important nodes, the focused neighbourhood, or everything when zoomed in / small graph
  const all=nodes.length<=40||cam.k>=1.6;
  nodeEls.forEach((g,i)=>g.classList.toggle('lbl',all||IMPORTANT.has(nodes[i].node_type)||degree[i]>=HUB_DEGREE||kids[i].length>0||i===selected||!!(near&&near.has(i))));
}
function applyView(){
  const hops=+document.getElementById('hops').value, near=selected!==null?neighborhood(idx,selected,hops):null;
  const q=query.trim().toLowerCase(), match=nodes.map(n=>!q||String(n.label).toLowerCase().includes(q)||n.node_type.includes(q));
  updateLabels(near);
  const shown=nodes.map((n,i)=>!hidden.has(n.node_type)&&isShown(i));
  nodeEls.forEach((g,i)=>{const vis=shown[i];g.style.display=vis?'':'none';pts[i].hidden=!isShown(i);
    const bd=g.querySelector('.badge'),rg=g.querySelector('.ring');if(bd){const open=expanded.has(i);bd.textContent=open?'':'+'+total(i);rg.style.display=open?'none':'';}
    const dim=(near&&!near.has(i))||!match[i];g.classList.toggle('dim',!!dim);g.classList.toggle('sel',i===selected);});
  idx.links.forEach((l,i)=>{const e=linkEls[i],vis=shown[l.a]&&shown[l.b];e.style.display=vis?'':'none';
    const inNear=near&&near.has(l.a)&&near.has(l.b);e.classList.toggle('dim',!!((near&&!inNear)||(!match[l.a]&&!match[l.b])));e.classList.toggle('hl',!!inNear);});
}
function addRow(dl,k,v){const dt=document.createElement('dt');dt.textContent=k;const dd=document.createElement('dd');dd.textContent=v;dl.appendChild(dt);dl.appendChild(dd);}
function listNodes(box,title,arr){ if(!arr.length)return; const h=document.createElement('h3');h.textContent=title+' ('+arr.length+')';box.appendChild(h);
  arr.slice(0,60).forEach(j=>{const d=document.createElement('div');d.className='li';d.textContent=nodes[j].node_type+': '+nodes[j].label;d.onclick=()=>select(j);box.appendChild(d);});
  if(arr.length>60){const m=document.createElement('div');m.className='mut';m.textContent='+'+(arr.length-60)+' more';box.appendChild(m);} }
function select(i){
  selected=i;const box=document.getElementById('details');box.replaceChildren();box.className='';
  if(i===null){box.className='mut';box.textContent='No node selected.';applyView();return;}
  const n=nodes[i],near=neighborhood(idx,i,+document.getElementById('hops').value),dl=document.createElement('dl');
  addRow(dl,'Type',n.node_type);addRow(dl,'Label',n.label);addRow(dl,'Connections',idx.out[i].length+' outgoing, '+idx.inn[i].length+' incoming');
  addRow(dl,'Blast radius',(near.size-1)+' nodes within '+document.getElementById('hops').value+' hop(s)');
  let attrs=n.attrs;try{attrs=typeof attrs==='string'?JSON.parse(attrs):attrs}catch(e){}
  if(attrs&&typeof attrs==='object')for(const k of Object.keys(attrs))addRow(dl,k,typeof attrs[k]==='object'?JSON.stringify(attrs[k]):String(attrs[k]));
  else if(attrs)addRow(dl,'attrs',String(attrs));
  if(kids[i].length){const c=below(i);addRow(dl,'Contains',Object.keys(c).sort().map(t=>c[t]+' '+t).join(', '));
    const b=document.createElement('button');b.textContent=expanded.has(i)?'Collapse':'Expand';b.onclick=()=>{toggle(i);select(i);};dl.appendChild(b);}
  box.appendChild(dl);listNodes(box,'Outgoing  \u2192',idx.out[i]);listNodes(box,'Incoming  \u2190',idx.inn[i]);applyView();
}
// legend / type filters
const legend=document.getElementById('legend');
[...new Set(nodes.map(n=>n.node_type))].sort().forEach(t=>{const lab=document.createElement('label');lab.className='chip';
  const cb=document.createElement('input');cb.type='checkbox';cb.checked=true;cb.onchange=()=>{cb.checked?hidden.delete(t):hidden.add(t);applyView();};
  const dot=document.createElement('span');dot.className='dot';dot.style.background=color(t);const tx=document.createElement('span');
  tx.textContent=t+' ('+nodes.filter(n=>n.node_type===t).length+')';lab.append(cb,dot,tx);legend.appendChild(lab);});
// interaction: node drag (pins), background pan, wheel zoom
let drag=null;
svg.addEventListener('pointerdown',e=>{const g=e.target.closest&&e.target.closest('.node');
  if(g){drag={node:nodeEls.indexOf(g),moved:false};}else{drag={pan:true,x:e.clientX,y:e.clientY};svg.classList.add('panning');}
  svg.setPointerCapture(e.pointerId);});
svg.addEventListener('pointermove',e=>{if(!drag)return;
  if(drag.pan){camMoved=true;cam.x+=e.clientX-drag.x;cam.y+=e.clientY-drag.y;drag.x=e.clientX;drag.y=e.clientY;drawCam();}
  else{const r=svg.getBoundingClientRect(),p=pts[drag.node];p.x=(e.clientX-r.left-cam.x)/cam.k;p.y=(e.clientY-r.top-cam.y)/cam.k;p.fixed=true;drag.moved=true;draw();}});
svg.addEventListener('pointerup',()=>{if(drag&&!drag.pan&&!drag.moved){toggle(drag.node);select(drag.node);}drag=null;svg.classList.remove('panning');});
svg.addEventListener('wheel',e=>{e.preventDefault();const r=svg.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top,f=e.deltaY<0?1.13:.88,k=Math.max(.05,Math.min(8,cam.k*f));
  cam.x=mx-(mx-cam.x)*(k/cam.k);cam.y=my-(my-cam.y)*(k/cam.k);camMoved=true;cam.k=k;drawCam();updateLabels(selected!==null?neighborhood(idx,selected,+document.getElementById('hops').value):null);},{passive:false});
document.getElementById('search').oninput=e=>{query=e.target.value;const q=query.trim().toLowerCase();
  if(q)nodes.forEach((n,i)=>{if(String(n.label).toLowerCase().includes(q)||n.node_type.includes(q))expandAncestors(i);});
  placeNew();applyView();kick(.6);};
document.getElementById('hops').onchange=()=>selected!==null?select(selected):applyView();
document.getElementById('fit').onclick=fit;
document.getElementById('clear').onclick=()=>select(null);
document.getElementById('relayout').onclick=()=>{pts.forEach(p=>p.fixed=false);kick(1);};
document.getElementById('expandAll').onclick=()=>setAll(true);document.getElementById('collapseAll').onclick=()=>setAll(false);
document.getElementById('info').textContent=nodes.length+' nodes / '+idx.links.length+' directed relationships';
pts.forEach((p,i)=>{p.hidden=!isShown(i);});
{const vis=nodes.map((_,i)=>i).filter(isShown);vis.forEach((i,k)=>{const a=k*Math.PI*(3-Math.sqrt(5)),r=26*SCALE_FOR(vis.length)*Math.sqrt(k+1);pts[i].x=Math.cos(a)*r;pts[i].y=Math.sin(a)*r;});}   // start only the visible nodes, close together
drawCam();draw();applyView();kick(1);setTimeout(fit,900);
</script></html>"""


def render(graph, title='Marsadix Knowledge Graph'):
    """Self-contained interactive graph page: no CDN, no network. All data reaches the DOM through
    textContent / setAttribute, and the JSON blob is escaped so a hostile label cannot close the tag."""
    data = (json.dumps(graph).replace('<', '\\u003c').replace('>', '\\u003e')
            .replace('&', '\\u0026').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029'))
    return TEMPLATE.replace('__TITLE__', html.escape(title)).replace('__DATA__', data)

def export_html(conn, target, scan_id=None, out='graph.html') -> int:
    """Write the interactive page for `target` (latest scan unless scan_id) to `out`."""
    row=(conn.execute('SELECT id FROM scans WHERE target=? ORDER BY id DESC LIMIT 1',(target,)).fetchone()
         if scan_id is None else conn.execute('SELECT id FROM scans WHERE id=? AND target=?',(scan_id,target)).fetchone())
    if row is None:
        print('error: no matching scan'); return 1
    graph=db.get_graph(conn,row['id'])
    if not graph['nodes']:
        build_graph(conn,row['id']);graph=db.get_graph(conn,row['id'])
    Path(out).write_text(render(graph, 'Marsadix: '+target),encoding='utf-8')
    print(f'\nInteractive graph: {Path(out).resolve()}')
    return 0

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
