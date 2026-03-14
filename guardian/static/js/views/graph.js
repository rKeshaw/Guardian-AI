const GRAPH_NODE_RADIUS = { hypothesis: 16, probe: 10, observation: 8, finding: 22, dead_end: 10 };
const GRAPH_NODE_COLORS = { hypothesis: '#f59e0b', probe: '#a855f7', observation: '#3b82f6', finding: '#22c55e', dead_end: '#6b7280' };
const EDGE_COLORS = { generated: '#6b7280', responded: '#3b82f6', confirmed: '#22c55e', spawned: '#f59e0b', derived: '#a855f7' };

const graphState = { sessionId: null, raw: null, poller: null, svg: null, g: null, simulation: null, zoom: null, selectedNodeId: null, filters: { hypothesis: true, probe: true, observation: true, finding: true, dead_end: true } };

window.initGraphView = async function initGraphView(params = {}) {
  const sessionId = params.sessionId || state.sessions?.[0]?.id;
  const root = document.getElementById('view-graph');
  if (!root) return;
  if (!sessionId) {
    root.innerHTML = '<div class="card">No session selected. Open Monitor first.</div>';
    return;
  }
  graphState.sessionId = sessionId;
  root.innerHTML = `
    <div class="graph-shell">
      <h2 class="panel-title">Attack Graph</h2>
      <div class="graph-canvas-wrap" id="graph-wrap">
        <div class="graph-toolbar" id="graph-toolbar"></div>
        <div class="graph-tooltip" id="graph-tooltip"></div>
        <svg id="graph-svg" width="100%" height="620"></svg>
      </div>
      <div class="graph-stats-bar" id="graph-stats">Nodes: 0 | Edges: 0 | Findings: 0 | Hypotheses: 0 | Dead Ends: 0 | Token Cost: 0</div>
    </div>`;

  setupToolbar();
  await loadAndRenderGraph();
  if (graphState.poller) clearInterval(graphState.poller);
  graphState.poller = setInterval(async () => {
    if (!graphState.sessionId) return;
    try {
      const status = await apiFetch(`/api/v1/scan/${graphState.sessionId}/status`);
      if (String(status.status).toLowerCase() === 'running') {
        const newData = await apiFetch(`/api/v1/scan/${graphState.sessionId}/graph`);
        updateGraph(newData);
      }
    } catch {}
  }, 8000);
};

async function loadAndRenderGraph() {
  const data = await apiFetch(`/api/v1/scan/${graphState.sessionId}/graph`);
  graphState.raw = data;
  renderGraph(data, []);
  renderStats(data);
}

function setupToolbar() {
  const root = document.getElementById('graph-toolbar');
  if (!root) return;
  const filterRow = ['hypothesis','probe','observation','finding','dead_end'].map((t)=>`<label style="display:block" class="tiny"><input type="checkbox" data-filter="${t}" checked/> ${t}</label>`).join('');
  root.innerHTML = `
    <div style="font-weight:700;margin-bottom:8px;">Controls</div>
    <button class="btn" id="fit-btn">Fit to screen</button>
    <button class="btn" id="reset-layout-btn">Reset layout</button>
    <button class="btn" id="zoom-in-btn">+</button>
    <button class="btn" id="zoom-out-btn">−</button>
    <div style="margin-top:8px;border-top:1px solid var(--border);padding-top:8px">${filterRow}</div>
    <div style="margin-top:8px;border-top:1px solid var(--border);padding-top:8px" class="tiny">
      <div><span style="color:#f59e0b">●</span> hypothesis</div>
      <div><span style="color:#a855f7">●</span> probe</div>
      <div><span style="color:#3b82f6">●</span> observation</div>
      <div><span style="color:#22c55e">●</span> finding</div>
      <div><span style="color:#6b7280">●</span> dead_end</div>
    </div>`;

  root.querySelectorAll('[data-filter]').forEach((el) => {
    el.addEventListener('change', () => {
      graphState.filters[el.dataset.filter] = !!el.checked;
      if (graphState.raw) renderGraph(graphState.raw, []);
    });
  });
  document.getElementById('fit-btn').onclick = fitToScreen;
  document.getElementById('reset-layout-btn').onclick = () => graphState.raw && renderGraph(graphState.raw, []);
  document.getElementById('zoom-in-btn').onclick = () => graphState.svg && graphState.svg.transition().call(graphState.zoom.scaleBy, 1.2);
  document.getElementById('zoom-out-btn').onclick = () => graphState.svg && graphState.svg.transition().call(graphState.zoom.scaleBy, 0.8);
}

function filteredData(data) {
  const nodes = (data.nodes || []).filter((n) => graphState.filters[n.type] !== false);
  const ids = new Set(nodes.map((n) => n.id));
  const links = (data.links || []).filter((l) => ids.has(l.source) && ids.has(l.target));
  return { ...data, nodes, links };
}

function renderGraph(inputData, newNodeIds = []) {
  const data = filteredData(inputData);
  const svg = d3.select('#graph-svg');
  svg.selectAll('*').remove();

  const width = document.getElementById('graph-wrap').clientWidth;
  const height = 620;

  const defs = svg.append('defs');
  Object.entries(EDGE_COLORS).forEach(([t, c]) => {
    defs.append('marker').attr('id', `arrow-${t}`).attr('viewBox', '0 -5 10 10').attr('refX', 18).attr('refY', 0).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', c);
  });

  const g = svg.append('g');
  graphState.g = g;

  const links = data.links.map((l) => ({ ...l }));
  const nodes = data.nodes.map((n) => ({ ...n }));

  const link = g.selectAll('line').data(links).enter().append('line')
    .attr('stroke', (d) => EDGE_COLORS[d.type] || '#555').attr('stroke-width', 1.5).attr('marker-end', (d) => `url(#arrow-${d.type || 'generated'})`);

  const node = g.selectAll('g.node').data(nodes, (d) => d.id).enter().append('g').attr('class', 'node').style('opacity', (d)=>newNodeIds.includes(d.id)?0:1);

  node.append('circle')
    .attr('r', (d) => GRAPH_NODE_RADIUS[d.type] || 10)
    .attr('fill', (d) => GRAPH_NODE_COLORS[d.type] || '#999')
    .attr('stroke', '#0b0b1b').attr('stroke-width', 1.5)
    .style('filter', (d) => d.type === 'finding' ? 'drop-shadow(0 0 8px #22c55e)' : null);

  node.filter((d)=>d.type==='finding').append('circle')
    .attr('r', (d) => (GRAPH_NODE_RADIUS[d.type] || 22) + 6)
    .attr('fill', 'none').attr('stroke', '#22c55e').attr('stroke-opacity', .55).attr('stroke-width', 2)
    .style('animation', 'pulse-green 1.6s infinite');

  node.append('title').text((d)=>`${d.type}\n${truncate(d.content || d.id, 100)}\nconfidence=${Math.round((d.confidence||0)*100)}%`);

  const tooltip = d3.select('#graph-tooltip');
  node.on('mouseenter', (evt, d) => {
    tooltip.style('display','block').style('left', `${evt.offsetX + 12}px`).style('top', `${evt.offsetY + 12}px`)
      .html(`<b>${d.type}</b><br>${truncate(d.content || d.id, 100)}<br>confidence: ${Math.round((d.confidence||0)*100)}%`);
  }).on('mousemove', (evt) => {
    tooltip.style('left', `${evt.offsetX + 12}px`).style('top', `${evt.offsetY + 12}px`);
  }).on('mouseleave', ()=> tooltip.style('display','none'));

  const neighbors = buildNeighborMaps(links);

  node.on('click', (evt, d) => {
    evt.stopPropagation();
    graphState.selectedNodeId = d.id;
    highlightSelection(d.id, node, link, neighbors);
    if (d.type === 'finding') showReasoningChain(d.id, inputData.reasoning_chains || []);
  });

  svg.on('click', () => {
    graphState.selectedNodeId = null;
    node.style('opacity', 1);
    link.style('opacity', 1);
    setDetail('Selection cleared.');
  });

  graphState.simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id((d) => d.id).distance(80))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius((d) => (GRAPH_NODE_RADIUS[d.type] || 10) + 10));

  graphState.simulation.on('tick', () => {
    link.attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y).attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
    node.attr('transform', (d) => `translate(${d.x},${d.y})`);
  });

  graphState.zoom = d3.zoom().scaleExtent([0.2, 4]).on('zoom', (event) => g.attr('transform', event.transform));
  svg.call(graphState.zoom);
  graphState.svg = svg;

  node.filter((d)=>newNodeIds.includes(d.id)).transition().duration(500).style('opacity',1);
}

function buildNeighborMaps(links) {
  const n = new Map();
  links.forEach((l) => {
    const s = typeof l.source === 'string' ? l.source : l.source.id;
    const t = typeof l.target === 'string' ? l.target : l.target.id;
    if (!n.has(s)) n.set(s, new Set());
    if (!n.has(t)) n.set(t, new Set());
    n.get(s).add(t);
    n.get(t).add(s);
  });
  return n;
}

function highlightSelection(nodeId, nodeSel, linkSel, neighbors) {
  const near = neighbors.get(nodeId) || new Set();
  near.add(nodeId);
  nodeSel.style('opacity', (d) => (near.has(d.id) ? 1 : 0.15));
  linkSel.style('opacity', (d) => {
    const s = typeof d.source === 'string' ? d.source : d.source.id;
    const t = typeof d.target === 'string' ? d.target : d.target.id;
    return (s === nodeId || t === nodeId || (near.has(s) && near.has(t))) ? 1 : 0.1;
  });
}

function showReasoningChain(findingId, chains) {
  const chain = chains.find((c) => c.finding_id === findingId);
  const right = document.getElementById('right-panel-content');
  if (!right) return;
  if (!chain) {
    right.innerHTML = `<div class="tiny">No reasoning chain found for ${findingId}</div>`;
    return;
  }
  right.innerHTML = `<h4 style="margin:0 0 8px;">Reasoning Chain</h4>` + chain.chain.map((step, idx) => `
    <div class="reasoning-step">
      <details ${idx === 0 ? 'open' : ''}>
        <summary><span class="badge badge-owasp">${step.type}</span> ${truncate(step.label || step.id, 60)}</summary>
        <div class="tiny" style="margin-top:6px;white-space:pre-wrap">${step.label || step.id}</div>
      </details>
    </div>`).join('');
}

function renderStats(data) {
  const stats = data.stats || {};
  const dist = stats.type_distribution || {};
  const line = `Nodes: ${stats.node_count || 0} | Edges: ${stats.edge_count || 0} | Findings: ${dist.finding || 0} | Hypotheses: ${dist.hypothesis || 0} | Dead Ends: ${dist.dead_end || 0} | Token Cost: ${stats.token_cost || 0}`;
  const el = document.getElementById('graph-stats');
  if (el) el.textContent = line;
}

function updateGraph(newData) {
  if (!graphState.raw) {
    graphState.raw = newData;
    renderGraph(newData, []);
    renderStats(newData);
    return;
  }
  const oldIds = new Set((graphState.raw.nodes || []).map((n) => n.id));
  const mergedNodes = [...(graphState.raw.nodes || [])];
  (newData.nodes || []).forEach((n) => {
    const idx = mergedNodes.findIndex((x) => x.id === n.id);
    if (idx >= 0) mergedNodes[idx] = { ...mergedNodes[idx], ...n };
    else mergedNodes.push(n);
  });
  const edgeKey = (e) => `${e.source}|${e.target}|${e.type}`;
  const mergedLinksMap = new Map();
  [...(graphState.raw.links || []), ...(newData.links || [])].forEach((e) => mergedLinksMap.set(edgeKey(e), e));
  const mergedLinks = [...mergedLinksMap.values()];
  const merged = { ...newData, nodes: mergedNodes, links: mergedLinks };
  const newNodeIds = mergedNodes.filter((n) => !oldIds.has(n.id)).map((n) => n.id);
  graphState.raw = merged;
  renderGraph(merged, newNodeIds);
  renderStats(merged);
}

function fitToScreen() {
  if (!graphState.raw || !graphState.svg || !graphState.g) return;
  const bounds = graphState.g.node().getBBox();
  const width = document.getElementById('graph-wrap').clientWidth;
  const height = 620;
  if (!bounds.width || !bounds.height) return;
  const scale = Math.min(width / bounds.width, height / bounds.height) * 0.85;
  const tx = width / 2 - (bounds.x + bounds.width / 2) * scale;
  const ty = height / 2 - (bounds.y + bounds.height / 2) * scale;
  graphState.svg.transition().duration(350).call(graphState.zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

