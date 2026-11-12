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
text{fill:var(--txt);font-size:11px;pointer-events:none;paint-order:stroke;stroke:#0c1220;stroke-width:3px}
.dim{opacity:.08}.li{cursor:pointer;padding:2px 0;word-break:break-all}.li:hover{text-decoration:underline}
dl{margin:0}dt{color:var(--mut);margin-top:6px}dd{margin:0;word-break:break-all}
</style>
<header><strong>Knowledge Graph</strong>
<input id="search" aria-label="Filter nodes" placeholder="Search label / type...">
<label class="mut">Highlight radius <select id="hops"><option>1</option><option selected>2</option><option>3</option><option>4</option></select> hops</label>
<button id="fit">Fit</button><button id="relayout">Re-layout</button><button id="clear">Clear selection</button>
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
function initPositions(n){
  const pts=[]; for(let i=0;i<n;i++){const a=i*Math.PI*(3-Math.sqrt(5)), r=26*Math.sqrt(i+1); pts.push({x:Math.cos(a)*r,y:Math.sin(a)*r,vx:0,vy:0,fixed:false});}
  return pts;
}
function layoutStep(pts, links, alpha){                // grid-based repulsion keeps it ~O(n) for big graphs
  const CELL=140, grid=new Map(), key=(x,y)=>x+','+y;
  pts.forEach((p,i)=>{const k=key(Math.floor(p.x/CELL),Math.floor(p.y/CELL)); (grid.get(k)||grid.set(k,[]).get(k)).push(i);});
  pts.forEach((p,i)=>{
    const cx=Math.floor(p.x/CELL), cy=Math.floor(p.y/CELL);
    for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++){
      const cell=grid.get(key(cx+dx,cy+dy)); if(!cell) continue;
      for(const j of cell){ if(j<=i) continue; const q=pts[j];
        let rx=p.x-q.x, ry=p.y-q.y, d2=rx*rx+ry*ry; if(d2>CELL*CELL) continue; if(d2<1){rx=Math.random()-.5;ry=Math.random()-.5;d2=1;}
        const d=Math.sqrt(d2), f=(2600/d2)*alpha, fx=rx/d*f, fy=ry/d*f;
        p.vx+=fx;p.vy+=fy;q.vx-=fx;q.vy-=fy; }
    }
  });
  for(const l of links){
    const p=pts[l.a], q=pts[l.b], rx=q.x-p.x, ry=q.y-p.y, d=Math.sqrt(rx*rx+ry*ry)||1, f=(d-70)*0.04*alpha;
    p.vx+=rx/d*f;p.vy+=ry/d*f;q.vx-=rx/d*f;q.vy-=ry/d*f;
  }
  for(const p of pts){ p.vx-=p.x*0.004*alpha; p.vy-=p.y*0.004*alpha;                // weak pull to the centre
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
const degree=nodes.map((_,i)=>idx.out[i].length+idx.inn[i].length);
const linkEls=idx.links.map(l=>{const el=mk('line',{'class':'edge','marker-end':'url(#arrow)'},linkLayer);const t=mk('title',{},el);t.textContent=nodes[l.a].label+'  --'+l.relation+'-->  '+nodes[l.b].label;return el;});
const nodeEls=nodes.map((n,i)=>{const g=mk('g',{'class':'node'},vertLayer);
  mk('circle',{r:6+Math.min(9,Math.sqrt(degree[i])*2),fill:color(n.node_type)},g);
  const t=mk('text',{x:12,y:4},g);t.textContent=String(n.label).slice(0,48);
  const tip=mk('title',{},g);tip.textContent=n.node_type+': '+n.label; return g;});
let cam={x:innerWidth/2-160,y:(innerHeight-56)/2,k:1}, alpha=1, hidden=new Set(), selected=null, query='';
const drawCam=()=>camera.setAttribute('transform','translate('+cam.x+' '+cam.y+') scale('+cam.k+')');
function draw(){
  pts.forEach((p,i)=>nodeEls[i].setAttribute('transform','translate('+p.x+' '+p.y+')'));
  idx.links.forEach((l,i)=>{const a=pts[l.a],b=pts[l.b],e=linkEls[i];e.setAttribute('x1',a.x);e.setAttribute('y1',a.y);e.setAttribute('x2',b.x);e.setAttribute('y2',b.y);});
}
function tick(){ if(alpha>0.02){layoutStep(pts,idx.links,alpha);alpha*=0.985;draw();requestAnimationFrame(tick);} }
function fit(){ if(!pts.length) return; let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
  pts.forEach(p=>{x0=Math.min(x0,p.x);y0=Math.min(y0,p.y);x1=Math.max(x1,p.x);y1=Math.max(y1,p.y);});
  const w=svg.clientWidth||800,h=svg.clientHeight||600,k=Math.min(2,.9*Math.min(w/Math.max(1,x1-x0),h/Math.max(1,y1-y0)));
  cam={k,x:w/2-k*(x0+x1)/2,y:h/2-k*(y0+y1)/2};drawCam(); }
function applyView(){
  const hops=+document.getElementById('hops').value, near=selected!==null?neighborhood(idx,selected,hops):null;
  const q=query.trim().toLowerCase(), match=nodes.map(n=>!q||String(n.label).toLowerCase().includes(q)||n.node_type.includes(q));
  nodeEls.forEach((g,i)=>{const vis=!hidden.has(nodes[i].node_type);g.style.display=vis?'':'none';
    const dim=(near&&!near.has(i))||!match[i];g.classList.toggle('dim',!!dim);g.classList.toggle('sel',i===selected);});
  idx.links.forEach((l,i)=>{const e=linkEls[i],vis=!hidden.has(nodes[l.a].node_type)&&!hidden.has(nodes[l.b].node_type);e.style.display=vis?'':'none';
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
  if(drag.pan){cam.x+=e.clientX-drag.x;cam.y+=e.clientY-drag.y;drag.x=e.clientX;drag.y=e.clientY;drawCam();}
  else{const r=svg.getBoundingClientRect(),p=pts[drag.node];p.x=(e.clientX-r.left-cam.x)/cam.k;p.y=(e.clientY-r.top-cam.y)/cam.k;p.fixed=true;drag.moved=true;draw();}});
svg.addEventListener('pointerup',()=>{if(drag&&!drag.pan&&!drag.moved)select(drag.node);drag=null;svg.classList.remove('panning');});
svg.addEventListener('wheel',e=>{e.preventDefault();const r=svg.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top,f=e.deltaY<0?1.13:.88,k=Math.max(.05,Math.min(8,cam.k*f));
  cam.x=mx-(mx-cam.x)*(k/cam.k);cam.y=my-(my-cam.y)*(k/cam.k);cam.k=k;drawCam();},{passive:false});
document.getElementById('search').oninput=e=>{query=e.target.value;applyView();};
document.getElementById('hops').onchange=()=>selected!==null?select(selected):applyView();
document.getElementById('fit').onclick=fit;
document.getElementById('clear').onclick=()=>select(null);
document.getElementById('relayout').onclick=()=>{pts.forEach(p=>p.fixed=false);alpha=1;tick();};
document.getElementById('info').textContent=nodes.length+' nodes / '+idx.links.length+' directed relationships';
drawCam();draw();applyView();tick();setTimeout(fit,900);
</script></html>"""


def render(graph, title='Marsadix Knowledge Graph'):
    """Self-contained interactive graph page: no CDN, no network. All data reaches the DOM through
    textContent / setAttribute, and the JSON blob is escaped so a hostile label cannot close the tag."""
    data = (json.dumps(graph).replace('<', '\\u003c').replace('>', '\\u003e')
            .replace('&', '\\u0026').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029'))
    return TEMPLATE.replace('__TITLE__', html.escape(title)).replace('__DATA__', data)

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
