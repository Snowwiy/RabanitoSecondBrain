import {createRequestGate, requestJson, safeReference} from './cyber.js';

const ORBIT_PALETTE = ['#5de4c5', '#62c8dd', '#b39af6', '#f2a35f', '#8ed0a4', '#e7a6c9', '#a6b8e8'];
const stableKey = value => String(value ?? '').normalize('NFC').trim() || 'Sin clasificar';

// Pure projections are exported so the real frontend behavior can be tested without a live index.
export function normalizeCommandGraph(payload) {
  const sourceNodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
  const nodes = sourceNodes.map(raw => {
    const id = raw?.document_id ?? raw?.id;
    if (!(typeof id === 'string' || Number.isSafeInteger(id)) || String(id).length > 160) return null;
    return {
      ...raw, id: String(id), title: String(raw.title ?? raw.name ?? 'Sin título').slice(0, 500),
      category: String(raw.category ?? ''), source_kind: String(raw.source_kind ?? raw.source ?? ''),
      project_name: String(raw.project_name ?? raw.project ?? ''), degree: Math.max(0, Number(raw.degree) || 0),
    };
  }).filter(Boolean);
  const uniqueNodes = [...new Map(nodes.map(node => [node.id, node])).values()];
  const ids = new Set(uniqueNodes.map(node => node.id));
  const edges = (Array.isArray(payload?.edges) ? payload.edges : []).flatMap(raw => {
    const source = String(raw?.source ?? ''), target = String(raw?.target ?? '');
    if (!ids.has(source) || !ids.has(target) || source === target) return [];
    const suggested = raw.kind === 'suggested' || raw.validation === 'suggested' || raw.status === 'suggested';
    return [{...raw, source, target, kind: suggested ? 'suggested' : 'explicit'}];
  });
  const uniqueEdges = [...new Map(edges.map(edge => [`${edge.source}\u0000${edge.target}\u0000${edge.kind}\u0000${edge.relation_type || ''}`, edge])).values()];
  return {nodes: uniqueNodes, edges: uniqueEdges, totalMatches: Math.max(uniqueNodes.length, Number(payload?.total_matches) || 0), truncated: Boolean(payload?.truncated)};
}

export function orbitCoordinates(nodes, width, height, spacing = 100) {
  const ordered = [...nodes].sort((a, b) => (b.degree - a.degree) || a.title.localeCompare(b.title, 'es-MX') || a.id.localeCompare(b.id));
  const result = new Map(), count = ordered.length;
  if (!count || width <= 0 || height <= 0) return result;
  const spacingScale = Math.min(1.4, Math.max(0.7, Number(spacing) / 100));
  const radius = Math.max(20, Math.min(width, height) * 0.44 * spacingScale), goldenAngle = Math.PI * (3 - Math.sqrt(5));
  ordered.forEach((node, index) => {
    const distance = radius * Math.sqrt((index + 0.5) / count), angle = index * goldenAngle;
    result.set(node.id, {x: width / 2 + Math.cos(angle) * distance, y: height / 2 + Math.sin(angle) * distance});
  });
  return result;
}

export function hitTestOrbitNode(points, x, y, minimumRadius = 22) {
  const pointerX = Number(x), pointerY = Number(y);
  if (!Number.isFinite(pointerX) || !Number.isFinite(pointerY) || !points?.[Symbol.iterator]) return null;
  let winner = null, nearest = Infinity;
  for (const [id, point] of points) {
    const pointX = Number(point?.x), pointY = Number(point?.y);
    if (!Number.isFinite(pointX) || !Number.isFinite(pointY)) continue;
    const distance = Math.hypot(pointX - pointerX, pointY - pointerY);
    const radius = Math.max(0, Number(minimumRadius) || 0, Number(point?.hitRadius) || 0);
    if (distance <= radius && distance < nearest) { winner = id; nearest = distance; }
  }
  return winner;
}

export function safeRelativePath(value) {
  const path = String(value ?? '').trim();
  if (!path || path.length > 1000 || /^[a-z][a-z\d+.-]*:/i.test(path) || /^[\\/]/.test(path) || /^~(?:[\\/]|$)/.test(path) || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(path)) return '';
  return path;
}

export function connectedComponents(graph) {
  const adjacency = explicitAdjacency(graph), ids = [...adjacency.keys()].sort((a, b) => a.localeCompare(b, 'en'));
  const componentById = new Map(); let componentNumber = 0;
  for (const start of ids) {
    if (componentById.has(start)) continue;
    componentNumber += 1; const label = `Conectividad ${componentNumber}`, queue = [start]; componentById.set(start, label);
    for (let cursor = 0; cursor < queue.length; cursor += 1) for (const neighbor of adjacency.get(queue[cursor]) || []) if (!componentById.has(neighbor)) { componentById.set(neighbor, label); queue.push(neighbor); }
  }
  return componentById;
}

export function groupCommandNodes(nodes, groupBy = 'category', graph = null) {
  const field = groupBy === 'source' ? 'source_kind' : groupBy === 'project' ? 'project_name' : 'category';
  const components = groupBy === 'component' && graph ? connectedComponents(graph) : null;
  const groups = new Map();
  for (const node of nodes) {
    const name = components ? (components.get(node.id) || 'Sin conectar') : stableKey(node[field]);
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(node);
  }
  return [...groups].map(([name, items]) => ({name, count: items.length, nodes: items}))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'es-MX'));
}

export function explicitAdjacency(graph) {
  const adjacency = new Map(graph.nodes.map(node => [node.id, new Set()]));
  for (const edge of graph.edges) {
    if (edge.kind !== 'explicit' || !adjacency.has(edge.source) || !adjacency.has(edge.target)) continue;
    adjacency.get(edge.source).add(edge.target); adjacency.get(edge.target).add(edge.source);
  }
  return adjacency;
}

export function startCommandCenter(doc, fetcher = fetch) {
  const byId = id => doc.getElementById(id), root = byId('ncCommandCenter');
  if (!root || root.dataset.initialized === 'true') return null;
  root.dataset.initialized = 'true';
  const api = (path, body) => requestJson(path, body, fetcher);
  const graphGate = createRequestGate(), searchGate = createRequestGate(), inspectGate = createRequestGate();
  const state = {graph: normalizeCommandGraph({}), projects: [], selected: null, selectedDocument: null, componentFocus: null, groupFocus: null, query: '', offset: 0, panX: 0, panY: 0, zoom: 1, dragging: false, labels: true, reducedMotion: false};
  const make = (tag, text, className) => {
    const element = doc.createElement(tag);
    if (text !== undefined && text !== null) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  };
  const setStatus = (text, tone = '') => { const status = byId('ncStatus'); status.textContent = text; status.dataset.tone = tone; };
  const safeCount = value => Number.isFinite(Number(value)) ? Number(value).toLocaleString('es-MX') : '—';

  function preserveLegacyDashboard() {
    const main = root.parentElement;
    const legacyChildren = [...main.children].filter(child => child !== root);
    const details = make('details', undefined, 'legacy-workbench');
    const summary = make('summary', 'Herramientas y paneles existentes · búsqueda avanzada, auditoría, decisiones, fuentes e indexación');
    const grid = make('div', undefined, 'legacy-grid');
    details.append(summary, grid); main.append(details);
    for (const child of legacyChildren) grid.append(child);
    const graphSection = grid.querySelector('#graph')?.closest('section');
    if (graphSection) {
      const mount = byId('ncPanelGalaxy'), controls = make('div', undefined, 'nc-galaxy-controls');
      const canvasHost = make('div', undefined, 'nc-galaxy-canvas-host');
      for (const child of [...graphSection.children]) {
        if (child.classList.contains('graph-workspace')) canvasHost.append(child);
        else controls.append(child);
      }
      mount.append(controls, canvasHost); graphSection.remove();
      doc.dispatchEvent(new Event('rabanito-command-graph-mounted'));
    }
    root.dataset.legacyPreserved = 'true';
  }

  function setTheme(theme) {
    const allowed = new Set(['raven-neon', 'cyber-ocean', 'violet-intelligence', 'security-amber', 'minimal-dark']);
    if (!allowed.has(theme)) return;
    doc.documentElement.dataset.theme = theme; byId('ncTheme').value = theme;
    try { localStorage.setItem('rabanito.ui.theme', theme); } catch { /* storage may be disabled */ }
  }

  function loadPreferences() {
    try {
      const prefs = JSON.parse(localStorage.getItem('rabanito.ui.preferences') || '{}');
      if (Number.isFinite(prefs.zoom) && prefs.zoom >= 0.6 && prefs.zoom <= 1.5) byId('ncZoomPref').value = String(Math.round(prefs.zoom * 100));
      if (typeof prefs.labels === 'boolean') byId('ncShowLabels').checked = prefs.labels;
      if (typeof prefs.reducedMotion === 'boolean') byId('ncReducedMotion').checked = prefs.reducedMotion;
      if (Number.isFinite(prefs.density) && prefs.density >= 40 && prefs.density <= 500) byId('ncDensity').value = String(prefs.density);
      if (Number.isFinite(prefs.nodeSize) && prefs.nodeSize >= 3 && prefs.nodeSize <= 12) byId('ncNodeSize').value = String(prefs.nodeSize);
      if (Number.isFinite(prefs.minDegree) && prefs.minDegree >= 0 && prefs.minDegree <= 8) byId('ncMinDegree').value = String(prefs.minDegree);
      for (const [key, id, min, max] of [['opacity', 'ncOpacity', 60, 100], ['linkBrightness', 'ncLinkBrightness', 10, 100], ['linkWidth', 'ncLinkWidth', 1, 4], ['orbitSpacing', 'ncOrbitSpacing', 70, 140], ['renderQuality', 'ncRenderQuality', 100, 200], ['fontScale', 'ncFontScale', 90, 120]])
        if (Number.isFinite(prefs[key]) && prefs[key] >= min && prefs[key] <= max) byId(id).value = String(prefs[key]);
      if (prefs.typography === 'mono' || prefs.typography === 'system') byId('ncTypography').value = prefs.typography;
      if (Number.isFinite(prefs.leftWidth) && prefs.leftWidth >= 190 && prefs.leftWidth <= 420) root.style.setProperty('--left-width', `${prefs.leftWidth}px`);
      if (Number.isFinite(prefs.rightWidth) && prefs.rightWidth >= 220 && prefs.rightWidth <= 460) root.style.setProperty('--right-width', `${prefs.rightWidth}px`);
      state.zoom = Number(byId('ncZoomPref').value) / 100; state.labels = byId('ncShowLabels').checked;
      state.reducedMotion = byId('ncReducedMotion').checked;
      root.style.setProperty('--nc-panel-alpha', `${byId('ncOpacity').value}%`);
      root.style.fontSize = `${byId('ncFontScale').value}%`;
      root.style.fontFamily = byId('ncTypography').value === 'mono' ? 'ui-monospace,Consolas,monospace' : 'system-ui,Segoe UI,sans-serif';
      const theme = localStorage.getItem('rabanito.ui.theme'); if (theme) setTheme(theme);
    } catch { /* malformed local preferences fall back to defaults */ }
  }

  function savePreferences() {
    const prefs = {
      zoom: Number(byId('ncZoomPref').value) / 100, labels: byId('ncShowLabels').checked,
      reducedMotion: byId('ncReducedMotion').checked, density: Number(byId('ncDensity').value),
      nodeSize: Number(byId('ncNodeSize').value), leftWidth: parseInt(getComputedStyle(root).getPropertyValue('--left-width'), 10) || 258,
      minDegree: Number(byId('ncMinDegree').value),
      rightWidth: parseInt(getComputedStyle(root).getPropertyValue('--right-width'), 10) || 306,
      opacity: Number(byId('ncOpacity').value), linkBrightness: Number(byId('ncLinkBrightness').value),
      linkWidth: Number(byId('ncLinkWidth').value),
      orbitSpacing: Number(byId('ncOrbitSpacing').value), renderQuality: Number(byId('ncRenderQuality').value),
      fontScale: Number(byId('ncFontScale').value), typography: byId('ncTypography').value,
    };
    try { localStorage.setItem('rabanito.ui.preferences', JSON.stringify(prefs)); } catch { /* UI remains usable without persistence */ }
  }

  async function loadStats() {
    try {
      const stats = await api('/api/stats');
      if (stats.fixture === true) { byId('ncFixtureBanner').hidden = false; doc.body.dataset.fixture = 'true'; }
      const values = [
        [stats.documents_active, 'Documentos'], [stats.relations_resolved, 'Relaciones confirmadas'],
        [stats.projects, 'Proyectos'], [Number(stats.links_broken || 0) + Number(stats.links_ambiguous || 0), 'Enlaces pendientes'],
      ];
      byId('ncCounts').replaceChildren(...values.map(([value, label]) => {
        const button = make('button', undefined, 'nc-count'); button.type = 'button';
        button.append(make('strong', safeCount(value)), make('span', label));
        button.addEventListener('click', () => openModule(label === 'Proyectos' ? 'projects' : label === 'Enlaces pendientes' ? 'audit' : 'documents'));
        return button;
      }));
      byId('ncExplorerCount').textContent = `${safeCount(stats.documents_active)} docs`;
      const scan = stats.latest_scan;
      byId('ncGraphCount').textContent = `Índice · ${safeCount(stats.documents_active)} documentos · ${safeCount(stats.relations_resolved)} relaciones${scan?.finished_at ? ` · sincronizado ${String(scan.finished_at).slice(0, 16)}` : ''}`;
    } catch { byId('ncGraphCount').textContent = 'No se pudieron leer estadísticas locales.'; }
  }

  async function loadOptions() {
    const [projectResult, categoryResult] = await Promise.allSettled([api('/api/projects'), api('/api/categories')]);
    if (projectResult.status === 'fulfilled') {
      const records = Array.isArray(projectResult.value) ? projectResult.value : (projectResult.value.projects || []);
      state.projects = records.filter(item => item && item.status !== 'excluded');
      const options = [make('option', 'Todos los proyectos')]; options[0].value = '';
      for (const project of state.projects) {
        const option = make('option', `${project.name || 'Proyecto'}${project.relative_path ? ` · ${project.relative_path}` : ''}`);
        option.value = String(project.project_id); options.push(option);
      }
      byId('ncProject').replaceChildren(...options);
      byId('ncProjectList').replaceChildren(...state.projects.map(project => {
        const button = make('button', undefined, 'nc-category-button'); button.type = 'button';
        button.append(make('span', project.name || 'Proyecto'), make('span', project.relative_path || 'ruta relativa no disponible', 'meta'));
        button.addEventListener('click', () => { byId('ncProject').value = String(project.project_id); void loadGraph(); });
        return button;
      }));
      byId('ncProjectCount').textContent = `${state.projects.length} detectados`;
    } else byId('ncProjectList').replaceChildren(make('span', 'Inventario de proyectos no disponible.', 'meta'));
    if (categoryResult.status === 'fulfilled') {
      const categories = Array.isArray(categoryResult.value) ? categoryResult.value : (categoryResult.value.categories || []);
      for (const category of categories) { const option = make('option', category || 'Sin categoría'); option.value = String(category || ''); byId('ncCategory').append(option); }
    }
  }

  function graphRequest(limit = Number(byId('ncDensity').value)) {
    return {
      domain: 'documents', limit: Math.min(1000, Math.max(1, limit)),
      q: byId('ncQuery').value.trim() || null, source: byId('ncSource').value || null,
      project_id: byId('ncProject').value || null, category: byId('ncCategory').value || null,
      suggestions: byId('ncSuggestions').checked, min_degree: 0,
    };
  }

  async function loadGraph(limit = Number(byId('ncDensity').value)) {
    const generation = graphGate.begin(); setStatus('Consultando relaciones confirmadas del índice local…');
    byId('ncLoadMore').disabled = true;
    try {
      const payload = await api('/api/graph', graphRequest(limit));
      if (!graphGate.current(generation)) return;
      if (payload.fixture === true) { byId('ncFixtureBanner').hidden = false; doc.body.dataset.fixture = 'true'; }
      state.graph = normalizeCommandGraph(payload); state.offset = limit; state.componentFocus = null; state.groupFocus = null;
      byId('ncGraphCount').textContent = `${safeCount(payload.total_matches ?? state.graph.nodes.length)} entidades · ${safeCount(state.graph.edges.length)} relaciones visibles${payload.truncated ? ' · vista limitada' : ''}`;
      byId('ncLoadMore').hidden = !payload.truncated;
      if (!state.graph.nodes.some(node => node.id === state.selected)) { state.selected = null; state.selectedDocument = null; renderInspectorEmpty(); }
      renderHex(); renderTree(); drawOrbit();
      setStatus(state.graph.nodes.length ? `${state.graph.edges.filter(edge => edge.kind === 'explicit').length} enlaces explícitos. Las sugerencias se excluyen de la vista inicial.` : 'El índice no devolvió nodos para estos filtros.', state.graph.nodes.length ? '' : 'pending');
      byId('ncPendingNote').hidden = false;
    } catch (error) {
      if (graphGate.current(generation)) {
        state.graph = normalizeCommandGraph({}); drawOrbit(); renderHex(); renderTree();
        setStatus(`No se pudo leer el grafo local: ${String(error.message || 'error de API').slice(0, 180)}. Reintenta desde Actualizar en la vista 3D.`, 'error');
      }
    } finally { if (graphGate.current(generation)) byId('ncLoadMore').disabled = false; }
  }

  function graphNodesAtDepth() {
    const depth = Number(byId('ncDepth').value);
    const components = state.componentFocus ? connectedComponents(state.graph) : null;
    let baseNodes = components ? state.graph.nodes.filter(node => components.get(node.id) === state.componentFocus) : state.graph.nodes;
    if (state.groupFocus) {
      const field = state.groupFocus.basis === 'source' ? 'source_kind' : state.groupFocus.basis === 'project' ? 'project_name' : 'category';
      baseNodes = baseNodes.filter(node => stableKey(node[field]) === state.groupFocus.name);
    }
    const minimumDegree = Number(byId('ncMinDegree').value);
    baseNodes = baseNodes.filter(node => node.id === state.selected || node.degree >= minimumDegree);
    if (!depth || !state.selected || !baseNodes.some(node => node.id === state.selected)) return baseNodes;
    const adjacency = explicitAdjacency(state.graph), visible = new Set([state.selected]), frontier = [state.selected];
    for (let level = 0; level < depth; level += 1) {
      const next = [];
      for (let cursor = 0; cursor < frontier.length; cursor += 1) for (const neighbor of adjacency.get(frontier[cursor]) || []) if (!visible.has(neighbor)) { visible.add(neighbor); next.push(neighbor); }
      frontier.splice(0, frontier.length, ...next);
    }
    return baseNodes.filter(node => visible.has(node.id));
  }

  function categoryColor(value) {
    let hash = 2166136261;
    for (const character of stableKey(value)) { hash ^= character.codePointAt(0); hash = Math.imul(hash, 16777619); }
    return ORBIT_PALETTE[(hash >>> 0) % ORBIT_PALETTE.length];
  }

  let orbitPoints = new Map(), orbitHover = null;
  function positionOrbitTooltip(anchor) {
    const tooltip = byId('ncOrbitTooltip'), canvas = byId('ncOrbitCanvas');
    if (tooltip.hidden || !anchor) return;
    const width = canvas.clientWidth, height = canvas.clientHeight;
    const left = Math.max(8, Math.min(width - tooltip.offsetWidth - 8, anchor.x + 14));
    let top = anchor.y + 14;
    if (top + tooltip.offsetHeight > height - 8) top = anchor.y - tooltip.offsetHeight - 14;
    top = Math.max(8, Math.min(height - tooltip.offsetHeight - 8, top));
    tooltip.style.left = `${left}px`; tooltip.style.top = `${top}px`;
  }

  function renderOrbitTooltip(visibleIds) {
    const tooltip = byId('ncOrbitTooltip');
    const id = orbitHover && visibleIds.has(orbitHover.id) ? orbitHover.id : visibleIds.has(state.selected) ? state.selected : null;
    const node = id && state.graph.nodes.find(item => item.id === id), point = id && orbitPoints.get(id);
    if (!node || !point) { tooltip.hidden = true; tooltip.replaceChildren(); return; }
    const metadata = [
      node.category ? `Categoría · ${node.category}` : '',
      node.source_kind ? `Fuente · ${node.source_kind}` : '',
      node.project_name ? `Proyecto · ${node.project_name}` : '',
    ].filter(Boolean);
    const content = [make('strong', node.title)];
    if (metadata.length) content.push(make('span', metadata.join(' · '), 'nc-node-tooltip-meta'));
    const reference = safeRelativePath(node.relative_path);
    if (reference) content.push(make('span', reference, 'nc-node-tooltip-path'));
    if (Number.isFinite(Number(node.degree))) content.push(make('span', `Grado · ${safeCount(node.degree)}`, 'nc-node-tooltip-meta'));
    tooltip.replaceChildren(...content); tooltip.hidden = false;
    positionOrbitTooltip(orbitHover?.id === id ? orbitHover : point);
  }

  function drawOrbit() {
    const canvas = byId('ncOrbitCanvas');
    if (byId('ncPanelOrbit').hidden || !canvas) return;
    const rect = canvas.getBoundingClientRect(); if (!rect.width || !rect.height) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1, Number(byId('ncRenderQuality').value) / 100), width = Math.floor(rect.width * dpr), height = Math.floor(rect.height * dpr);
    if (canvas.width !== width || canvas.height !== height) { canvas.width = width; canvas.height = height; }
    const context = canvas.getContext('2d'); if (!context) { setStatus('Este navegador no pudo crear el canvas 2D.', 'error'); return; }
    context.setTransform(dpr, 0, 0, dpr, 0, 0); context.clearRect(0, 0, rect.width, rect.height);
    const centerX = rect.width / 2 + state.panX, centerY = rect.height / 2 + state.panY, scale = state.zoom;
    context.save(); context.translate(centerX, centerY); context.scale(scale, scale);
    const spacing = Number(byId('ncOrbitSpacing').value) / 100;
    const orbitRadius = Math.max(40, Math.min(rect.width, rect.height) * 0.44 * spacing);
    context.strokeStyle = '#59818a20'; context.lineWidth = 1;
    for (const fraction of [0.34, 0.68, 1]) { context.beginPath(); context.arc(0, 0, orbitRadius * fraction, 0, Math.PI * 2); context.stroke(); }
    context.fillStyle = '#7b9a9b'; context.font = '9px ui-monospace,Consolas,monospace'; context.textAlign = 'center';
    context.fillText('RABANITO · MEMORIA LOCAL', 0, -8);
    context.fillStyle = '#456269'; context.fillText(`${state.graph.nodes.length} NODOS INDEXADOS`, 0, 8);
    const visibleNodes = graphNodesAtDepth(), visibleIds = new Set(visibleNodes.map(node => node.id));
    const positions = orbitCoordinates(visibleNodes, Math.max(1, rect.width - 24), Math.max(1, rect.height - 24), byId('ncOrbitSpacing').value);
    const local = new Map([...positions].map(([id, point]) => [id, {x: point.x - rect.width / 2 + 12, y: point.y - rect.height / 2 + 12}]));
    const adjacency = explicitAdjacency(state.graph), selectedNeighbors = state.selected ? (adjacency.get(state.selected) || new Set()) : new Set();
    const components = byId('ncColor').value === 'component' ? connectedComponents(state.graph) : null;
    for (const edge of state.graph.edges) {
      if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) continue;
      const a = local.get(edge.source), b = local.get(edge.target); if (!a || !b) continue;
      const related = edge.source === state.selected || edge.target === state.selected;
      context.beginPath(); context.moveTo(a.x, a.y); context.lineTo(b.x, b.y);
      context.setLineDash(edge.kind === 'suggested' ? [3, 4] : []);
      context.strokeStyle = edge.kind === 'suggested' ? '#f2a35f' : related ? '#69ead0' : '#65a3aa';
      context.globalAlpha = Number(byId('ncLinkBrightness').value) / 100 * (edge.kind === 'suggested' ? 0.78 : related ? 1 : 0.46);
      context.lineWidth = Number(byId('ncLinkWidth').value) * (related ? 1.3 : 0.8); context.stroke(); context.globalAlpha = 1;
    }
    context.setLineDash([]); orbitPoints = new Map();
    const baseSize = Number(byId('ncNodeSize').value);
    for (const node of visibleNodes) {
      const point = local.get(node.id); if (!point) continue;
      const x = centerX + point.x * scale, y = centerY + point.y * scale;
      const selected = node.id === state.selected, hovered = node.id === orbitHover?.id, active = selected || hovered, linked = selectedNeighbors.has(node.id);
      const colorMode = byId('ncColor').value;
      const colorKey = colorMode === 'source' ? node.source_kind : colorMode === 'project' ? node.project_name : colorMode === 'component' ? components.get(node.id) : node.category;
      const radius = Math.min(18, baseSize + Math.min(7, Math.sqrt(node.degree || 0)) + (selected ? 3 : hovered ? 2 : 0));
      orbitPoints.set(node.id, {x, y, hitRadius: Math.max(22, radius * scale + 8)});
      context.beginPath(); context.arc(point.x, point.y, radius + (selected ? 5 : hovered ? 3 : 0), 0, Math.PI * 2);
      context.fillStyle = `${categoryColor(colorKey)}${active ? '40' : '18'}`; context.fill();
      context.beginPath(); context.arc(point.x, point.y, radius, 0, Math.PI * 2);
      context.fillStyle = categoryColor(colorKey); context.globalAlpha = selected || linked || !state.selected ? 0.95 : 0.22; context.fill(); context.globalAlpha = 1;
      context.strokeStyle = selected ? '#e6fffa' : hovered ? '#d3fff3' : linked ? '#9cebd9' : '#bddad660'; context.lineWidth = active ? 1.5 : 0.8; context.stroke();
      if (state.labels && (active || (scale > 1.42 && node.degree > 0))) {
        context.font = selected ? '600 10px system-ui, sans-serif' : '9px system-ui, sans-serif';
        context.textAlign = 'left'; context.fillStyle = active ? '#f0fffb' : '#c0d3d0';
        context.fillText(node.title.slice(0, 34), point.x + radius + 4, point.y + 3);
      }
    }
    context.restore(); renderOrbitTooltip(visibleIds);
  }

  function renderHex() {
    const target = byId('ncPanelHex'), groups = groupCommandNodes(state.graph.nodes, byId('ncColor').value, state.graph);
    target.replaceChildren();
    if (!groups.length) { target.append(make('p', 'No hay entidades para agrupar con los filtros actuales.', 'meta')); return; }
    const fragment = doc.createDocumentFragment();
    for (const group of groups) {
      const wrap = make('article', undefined, 'nc-hex-wrap'), card = make('div', undefined, 'nc-hex-card');
      const button = make('button', group.name, 'nc-hex-select'); button.type = 'button';
      button.setAttribute('aria-pressed', 'false');
      const basis = byId('ncColor').value;
      button.setAttribute('aria-label', `${group.name}: ${group.count} entidades, agrupadas por ${basis}`);
      button.addEventListener('click', () => {
        if (basis === 'component') {
          state.componentFocus = state.componentFocus === group.name ? null : group.name;
          state.groupFocus = null;
          setStatus(`${state.componentFocus || 'Vista completa'} · componentes calculados solo desde enlaces explícitos; no equivalen a comunidades semánticas.`);
          drawOrbit(); setView('orbit'); return;
        }
        state.componentFocus = null;
        state.groupFocus = state.groupFocus?.basis === basis && state.groupFocus.name === group.name ? null : {basis, name: group.name};
        setStatus(`${state.groupFocus ? `${basis}: ${group.name}` : 'Vista completa'} · entidades agrupadas desde metadatos del índice.`);
        drawOrbit(); setView('orbit');
      });
      card.append(button, make('span', `${group.count} ${group.count === 1 ? 'entidad' : 'entidades'}`, 'nc-hex-count'));
      const entities = make('div', undefined, 'nc-hex-entities');
      for (const node of group.nodes.slice(0, 3)) {
        const pick = make('button', node.title, 'nc-hex-entity'); pick.type = 'button'; pick.addEventListener('click', event => { event.stopPropagation(); void inspect(node.id); });
        entities.append(pick);
      }
      card.append(entities); wrap.append(card); fragment.append(wrap);
    }
    target.append(fragment);
  }

  function renderTree() {
    const target = byId('ncPanelTree'), groups = groupCommandNodes(state.graph.nodes, 'project');
    target.replaceChildren();
    if (!groups.length) { target.append(make('p', 'El árbol está vacío: el índice no contiene documentos para estos filtros.', 'meta')); return; }
    const rootList = make('ul');
    for (const group of groups) {
      const groupItem = make('li'), groupDetails = make('details'), summary = make('summary', `${group.name} · ${group.count} documento${group.count === 1 ? '' : 's'}`), docs = make('ul');
      groupDetails.append(summary);
      for (const node of group.nodes) {
        const item = make('li'), button = make('button'); button.type = 'button';
        button.append(make('strong', node.title), make('span', `${node.category || 'categoría sin dato'} · ${node.source_kind || 'fuente local'}`));
        button.addEventListener('click', () => void inspect(node.id)); item.append(button); docs.append(item);
      }
      groupDetails.append(docs); groupItem.append(groupDetails); rootList.append(groupItem);
    }
    const relationList = make('details'), relationSummary = make('summary', `Relaciones explícitas · ${state.graph.edges.filter(edge => edge.kind === 'explicit').length}`), relations = make('ul');
    for (const edge of state.graph.edges.filter(item => item.kind === 'explicit').slice(0, 160)) {
      const source = state.graph.nodes.find(node => node.id === edge.source), targetNode = state.graph.nodes.find(node => node.id === edge.target);
      if (!source || !targetNode) continue;
      const item = make('li'), button = make('button'); button.type = 'button'; button.textContent = `${source.title} ↔ ${targetNode.title} · ${edge.relation_type || 'relación explícita'}`;
      button.addEventListener('click', () => void inspect(source.id)); item.append(button); relations.append(item);
    }
    relationList.append(relationSummary, relations); const relationItem = make('li'); relationItem.append(relationList); rootList.append(relationItem);
    const note = make('p', 'Jerarquía mostrada: agrupación por metadato de proyecto. No se presupone una arquitectura inexistente; las relaciones listadas provienen únicamente de enlaces del grafo.', 'meta');
    target.append(note, rootList);
  }

  function renderInspectorEmpty() {
    byId('ncInspectorType').textContent = 'Sin selección';
    byId('ncInspectorBody').replaceChildren(make('p', 'Selecciona un nodo, resultado de búsqueda o elemento de una comunidad. Se mostrarán metadatos locales y fragmentos citados.', 'nc-inspector-intro'));
    byId('ncFragments').textContent = 'Aún no hay documento seleccionado.';
    byId('ncNeighbors').replaceChildren(make('span', 'Selecciona una entidad para explorar vecinos.', 'meta'));
    byId('ncOpenOriginal').disabled = true; byId('ncGetContext').disabled = true;
    byId('ncSourceRef').textContent = 'No se expone la ruta absoluta de la fuente.';
  }

  function dispatchSelection(id, node = null) {
    doc.dispatchEvent(new CustomEvent('rabanito-command-selection', {detail: {id: String(id), node}}));
  }

  async function inspect(id) {
    const documentId = Number(id);
    if (!Number.isSafeInteger(documentId) || documentId <= 0) return;
    state.selected = String(documentId);
    const generation = inspectGate.begin();
    byId('ncInspectorType').textContent = 'Documento';
    byId('ncInspectorBody').replaceChildren(make('p', 'Leyendo metadatos del índice local…', 'nc-inspector-intro'));
    byId('ncFragments').replaceChildren(make('span', 'Recuperando fragmentos citados…', 'meta'));
    byId('ncNeighbors').replaceChildren(make('span', 'Cargando relaciones disponibles…', 'meta'));
    byId('ncOpenOriginal').disabled = false; byId('ncGetContext').disabled = false;
    try {
      const documentData = await api(`/api/doc/${documentId}`);
      if (!inspectGate.current(generation)) return;
      state.selectedDocument = documentData;
      const body = byId('ncInspectorBody'), tags = Array.isArray(documentData.tags) ? documentData.tags : [];
      const title = make('h3', documentData.title || 'Documento sin título');
      const meta = make('p', [documentData.project_name, documentData.category, documentData.source_kind, documentData.mtime_iso].filter(Boolean).join(' · ') || 'Metadatos parciales', 'nc-inspector-meta');
      body.replaceChildren(title, meta);
      const tagList = make('div');
      for (const tag of tags.slice(0, 24)) tagList.append(make('span', `#${String(tag).replace(/^#/, '')}`, 'badge'));
      if (tags.length) body.append(tagList);
      const frontmatter = documentData.frontmatter && typeof documentData.frontmatter === 'object' ? Object.keys(documentData.frontmatter).slice(0, 12) : [];
      if (frontmatter.length) body.append(make('p', `Propiedades YAML: ${frontmatter.join(' · ')}`, 'nc-inspector-meta'));
      body.append(make('p', 'La API de esta rama entrega metadatos y fragmentos de recuperación, no el Markdown íntegro. El contenido completo se abre únicamente en la fuente original autorizada.', 'nc-inspector-intro'));
      byId('ncSourceRef').textContent = `${documentData.source_kind || 'fuente local'} · ${documentData.relative_path || 'referencia relativa no disponible'}${documentData.mtime_iso ? ` · actualizado ${documentData.mtime_iso}` : ''}`;
      await loadFragments(documentData, generation);
      await renderNeighbors(documentData, generation);
    } catch (error) {
      if (inspectGate.current(generation)) {
        byId('ncInspectorBody').replaceChildren(make('p', `No se pudo cargar el documento: ${String(error.message || 'error de API').slice(0, 180)}`, 'error'));
        byId('ncFragments').textContent = 'No hay fragmentos disponibles.';
        byId('ncNeighbors').textContent = 'No hay relaciones disponibles.';
      }
    }
  }

  async function loadFragments(documentData, generation = inspectGate.begin()) {
    const target = byId('ncFragments');
    const query = String(documentData.title || '').trim();
    if (!query) { target.textContent = 'El documento no tiene un título apto para recuperar fragmentos.'; return; }
    try {
      const payload = await api('/api/context', {
        q: query.slice(0, 500), limit: 4, max_chars: 2400,
        source: documentData.source_kind || null, category: documentData.category || null,
      });
      if (!inspectGate.current(generation)) return;
      const fragments = Array.isArray(payload.fragments) ? payload.fragments : [];
      if (!fragments.length) { target.textContent = 'La recuperación no encontró fragmentos para el título. Usa “Recuperar contexto” con una pregunta más específica.'; return; }
      const content = doc.createDocumentFragment();
      for (const fragment of fragments) {
        const excerpt = make('pre', String(fragment.text || '').slice(0, 1200), 'nc-fragment');
        const citation = make('p', `${fragment.citation || `${fragment.source_kind || 'local'}:${fragment.relative_path || '?'}:${fragment.line_start || '?'}-${fragment.line_end || '?'}`} · ${fragment.title || 'Documento'}`, 'nc-inspector-meta');
        content.append(excerpt, citation);
      }
      target.replaceChildren(content);
    } catch (error) {
      if (inspectGate.current(generation)) target.replaceChildren(make('span', `No se pudieron recuperar fragmentos: ${String(error.message || 'error').slice(0, 120)}`, 'error'));
    }
  }

  async function renderNeighbors(documentData, generation) {
    const target = byId('ncNeighbors'), entries = new Map();
    for (const edge of state.graph.edges) {
      if (edge.kind !== 'explicit') continue;
      const otherId = edge.source === state.selected ? edge.target : edge.target === state.selected ? edge.source : null;
      if (!otherId) continue;
      const node = state.graph.nodes.find(item => item.id === otherId);
      if (node) entries.set(otherId, {title: node.title, relation: edge.relation_type || 'relación explícita'});
    }
    for (const link of [...(documentData.links || []), ...(documentData.incoming_links || [])]) {
      const id = Number(link.target_document_id ?? link.source_document_id);
      const title = link.target_title || link.source_title || link.target_raw;
      if (Number.isSafeInteger(id) && id > 0 && id !== Number(state.selected)) entries.set(String(id), {title: title || 'Documento relacionado', relation: link.status === 'resolved' ? 'wikilink resuelto' : link.status || 'referencia'});
    }
    const content = doc.createDocumentFragment();
    for (const [id, item] of [...entries].slice(0, 32)) {
      const button = make('button', undefined); button.type = 'button';
      button.append(make('strong', item.title), make('span', item.relation, 'nc-inspector-meta'));
      button.addEventListener('click', () => dispatchSelection(id)); content.append(button);
    }
    if (!entries.size) content.append(make('span', 'No hay relaciones explícitas visibles para esta selección.', 'meta'));
    const suggestions = state.graph.edges.filter(edge => edge.kind === 'suggested' && (edge.source === state.selected || edge.target === state.selected));
    if (suggestions.length) content.append(make('p', `${suggestions.length} sugerencias no confirmadas permanecen fuera de las relaciones explícitas.`, 'nc-pending'));
    if (inspectGate.current(generation)) target.replaceChildren(content);
  }

  async function search(query = byId('ncQuery').value.trim()) {
    const generation = searchGate.begin(), normalized = String(query).trim().slice(0, 500);
    state.query = normalized;
    const target = byId('ncSearchResults'); target.replaceChildren();
    if (!normalized) { byId('ncSearchStatus').textContent = 'Escribe términos para buscar en el índice local.'; return; }
    byId('ncSearchStatus').textContent = 'Buscando localmente…'; target.setAttribute('aria-busy', 'true');
    try {
      const payload = await api('/api/search', {
        q: normalized, limit: 20, project_id: byId('ncProject').value || null,
        source: byId('ncSource').value || null, category: byId('ncCategory').value || null,
      });
      if (!searchGate.current(generation)) return;
      const results = Array.isArray(payload.results) ? payload.results : [];
      if (!results.length) target.append(make('span', 'Sin resultados verificados para esa consulta.', 'meta'));
      for (const item of results) {
        const id = item.document_id, button = make('button', undefined, 'nc-hit'); button.type = 'button';
        button.append(make('strong', item.title || 'Documento sin título'), make('span', `${item.source_kind || 'fuente local'} · ${item.category || 'sin categoría'}`, 'nc-inspector-meta'));
        const citation = [item.relative_path, item.line_start ? `líneas ${item.line_start}${item.line_end && item.line_end !== item.line_start ? `–${item.line_end}` : ''}` : ''].filter(Boolean).join(' · ');
        if (citation) button.append(make('span', citation, 'nc-inspector-meta'));
        if (item.snippet) button.append(make('span', String(item.snippet).slice(0, 240), 'nc-inspector-meta'));
        button.addEventListener('click', () => dispatchSelection(id)); target.append(button);
      }
      byId('ncSearchStatus').textContent = `${results.length} resultados con citas locales. Consulta enviada en el cuerpo POST, no en la URL.`;
    } catch (error) {
      if (searchGate.current(generation)) byId('ncSearchStatus').textContent = `Búsqueda no disponible: ${String(error.message || 'error').slice(0, 140)}`;
    } finally { if (searchGate.current(generation)) target.setAttribute('aria-busy', 'false'); }
  }

  async function retrieveContext() {
    const item = state.selectedDocument;
    if (!item) return;
    const query = byId('ncQuery').value.trim() || item.title || '';
    if (!query) { setStatus('Escribe una pregunta para recuperar contexto citado.', 'pending'); return; }
    byId('ncGetContext').disabled = true;
    try {
      const payload = await api('/api/context', {q: query.slice(0, 500), limit: 8, max_chars: 6000, source: item.source_kind || null, category: item.category || null});
      const fragments = Array.isArray(payload.fragments) ? payload.fragments : [];
      const content = doc.createDocumentFragment();
      for (const fragment of fragments) content.append(make('pre', fragment.text || '', 'nc-fragment'), make('p', fragment.citation || `${fragment.relative_path || '?'}:${fragment.line_start || '?'}-${fragment.line_end || '?'}`, 'nc-inspector-meta'));
      byId('ncFragments').replaceChildren(content.childNodes.length ? content : make('span', 'No se encontraron fragmentos citables.', 'meta'));
      setStatus(`${fragments.length} fragmentos · ${safeCount(payload.characters)} caracteres · límite solicitado 6,000.`, fragments.length ? '' : 'pending');
    } catch (error) { setStatus(`No se pudo recuperar contexto: ${String(error.message || 'error').slice(0, 160)}`, 'error'); }
    finally { byId('ncGetContext').disabled = false; }
  }

  function setView(name) {
    const views = {orbit: 'ncPanelOrbit', hex: 'ncPanelHex', galaxy: 'ncPanelGalaxy', tree: 'ncPanelTree'};
    const titles = {orbit: 'NEURAL ORBIT', hex: 'HEX KNOWLEDGE', galaxy: 'KNOWLEDGE GALAXY 3D', tree: 'KNOWLEDGE TREE'};
    if (!Object.hasOwn(views, name)) return;
    for (const [view, panelId] of Object.entries(views)) {
      const active = view === name, panel = byId(panelId), tab = byId(`ncTab${view[0].toUpperCase()}${view.slice(1)}`);
      panel.hidden = !active; tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1;
    }
    byId('ncViewTitle').textContent = titles[name];
    if (name === 'orbit') drawOrbit();
    if (name === 'hex') renderHex();
    if (name === 'tree') renderTree();
    if (name === 'galaxy') {
      requestAnimationFrame(() => window.dispatchEvent(new Event('resize')));
      byId('graphStatus')?.focus?.({preventScroll: true});
    }
  }

  function openModule(name) {
    const legacy = root.parentElement.querySelector('.legacy-workbench');
    if (legacy) legacy.open = true;
    const map = {
      projects: '#projectInventory', decisions: '#decisionPanel', coding: '#knowledgePanel', security: '#knowledgePanel',
      cyber: '#cyberPanel', sources: '#sourcesPanel', audit: '#auditPanel', documents: '#results',
    };
    if (name === 'coding' || name === 'security') {
      byId('knowledgeMode').value = name === 'coding' ? 'coding' : 'security';
      byId('knowledgeMode').dispatchEvent(new Event('change', {bubbles: true}));
    }
    const target = legacy?.querySelector(map[name] || '#results');
    target?.scrollIntoView({behavior: state.reducedMotion ? 'auto' : 'smooth', block: 'start'});
    target?.focus?.({preventScroll: true});
  }

  function selectOrbitNode(id) {
    const node = state.graph.nodes.find(item => item.id === String(id)); if (!node) return;
    orbitHover = null; state.selected = node.id; drawOrbit(); setStatus(`Seleccionado: ${node.title}. Pulsa Enter para abrir la ficha.`); dispatchSelection(node.id, node);
  }

  function bindOrbitCanvas() {
    const canvas = byId('ncOrbitCanvas'); let pointerStart = null, moved = false;
    const updateHover = event => {
      const rect = canvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
      const id = hitTestOrbitNode(orbitPoints, x, y), changed = id !== (orbitHover?.id || null);
      orbitHover = id === null ? null : {id, x, y}; canvas.style.cursor = id === null ? 'grab' : 'pointer';
      if (changed) drawOrbit(); else if (orbitHover) positionOrbitTooltip(orbitHover);
    };
    const clearHover = () => {
      if (state.dragging || !orbitHover) return;
      orbitHover = null; canvas.style.cursor = 'grab'; drawOrbit();
    };
    canvas.addEventListener('pointerdown', event => {
      updateHover(event); state.dragging = true; moved = false; pointerStart = {x: event.clientX, y: event.clientY, panX: state.panX, panY: state.panY}; canvas.style.cursor = 'grabbing';
      canvas.setPointerCapture(event.pointerId);
    });
    canvas.addEventListener('pointermove', event => {
      if (!state.dragging || !pointerStart) { updateHover(event); return; }
      const dx = event.clientX - pointerStart.x, dy = event.clientY - pointerStart.y;
      if (Math.abs(dx) + Math.abs(dy) > 4) moved = true;
      if (moved) { orbitHover = null; state.panX = pointerStart.panX + dx; state.panY = pointerStart.panY + dy; drawOrbit(); }
    });
    const endPointer = event => {
      const wasMoved = moved; state.dragging = false; pointerStart = null;
      if (event.type === 'pointerup' && !wasMoved) updateHover(event);
      else { orbitHover = null; drawOrbit(); if (event.type !== 'pointerup') moved = false; }
      canvas.style.cursor = orbitHover ? 'pointer' : 'grab';
    };
    canvas.addEventListener('pointerup', endPointer); canvas.addEventListener('pointercancel', endPointer);
    canvas.addEventListener('pointerleave', clearHover);
    canvas.addEventListener('wheel', event => {
      event.preventDefault(); state.zoom = Math.max(0.45, Math.min(3, state.zoom * (event.deltaY < 0 ? 1.09 : 0.92)));
      byId('ncZoomPref').value = String(Math.max(60, Math.min(150, Math.round(state.zoom * 100)))); savePreferences(); drawOrbit(); updateHover(event);
    }, {passive: false});
    canvas.addEventListener('click', event => {
      if (moved) { moved = false; return; }
      const rect = canvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
      const winner = hitTestOrbitNode(orbitPoints, x, y);
      if (winner !== null) selectOrbitNode(winner);
    });
    canvas.addEventListener('keydown', event => {
      if (event.key === 'Escape') { state.selected = null; state.selectedDocument = null; inspectGate.begin(); renderInspectorEmpty(); drawOrbit(); return; }
      if (event.key === 'Enter' && state.selected) { void inspect(state.selected); return; }
      const direction = ['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : ['ArrowLeft', 'ArrowUp'].includes(event.key) ? -1 : 0;
      if (!direction) return;
      event.preventDefault(); const visible = graphNodesAtDepth(), index = visible.findIndex(node => node.id === state.selected);
      const next = visible[(index + direction + visible.length) % visible.length]; if (next) selectOrbitNode(next.id);
    });
    if (typeof ResizeObserver !== 'undefined') new ResizeObserver(drawOrbit).observe(canvas);
  }

  function bindPanelResizers() {
    for (const separator of root.querySelectorAll('.nc-resizer')) {
      const side = separator.dataset.panel;
      const property = side === 'left' ? '--left-width' : '--right-width';
      const defaultWidth = side === 'left' ? 258 : 306;
      const bounds = side === 'left' ? [190, 420] : [220, 460];
      const currentWidth = () => parseInt(getComputedStyle(root).getPropertyValue(property), 10) || defaultWidth;
      separator.setAttribute('aria-valuenow', String(currentWidth()));
      const adjust = delta => {
        const value = Math.max(bounds[0], Math.min(bounds[1], currentWidth() + delta));
        root.style.setProperty(property, `${value}px`); separator.setAttribute('aria-valuenow', String(value)); savePreferences();
      };
      let start = null;
      separator.addEventListener('pointerdown', event => { start = {x: event.clientX, width: currentWidth()}; separator.setPointerCapture(event.pointerId); separator.dataset.dragging = 'true'; });
      separator.addEventListener('pointermove', event => {
        if (!start) return; const direction = side === 'left' ? 1 : -1, value = Math.max(bounds[0], Math.min(bounds[1], start.width + direction * (event.clientX - start.x)));
        root.style.setProperty(property, `${value}px`); separator.setAttribute('aria-valuenow', String(value));
      });
      const end = () => { if (start) savePreferences(); start = null; separator.dataset.dragging = 'false'; };
      separator.addEventListener('pointerup', end); separator.addEventListener('pointercancel', end);
      separator.addEventListener('keydown', event => { if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') { event.preventDefault(); adjust((event.key === 'ArrowRight' ? 1 : -1) * (event.shiftKey ? 24 : 8) * (side === 'left' ? 1 : -1)); } });
    }
  }

  function bind() {
    byId('ncTheme').addEventListener('change', event => setTheme(event.target.value));
    byId('ncToggleExplorer').addEventListener('click', event => {
      const collapsed = root.dataset.leftCollapsed !== 'true'; root.dataset.leftCollapsed = String(collapsed);
      event.currentTarget.setAttribute('aria-pressed', String(collapsed)); event.currentTarget.setAttribute('aria-expanded', String(!collapsed)); requestAnimationFrame(drawOrbit);
    });
    byId('ncToggleInspector').addEventListener('click', event => {
      const collapsed = root.dataset.rightCollapsed !== 'true'; root.dataset.rightCollapsed = String(collapsed);
      event.currentTarget.setAttribute('aria-pressed', String(collapsed)); event.currentTarget.setAttribute('aria-expanded', String(!collapsed)); requestAnimationFrame(drawOrbit);
    });
    for (const tab of root.querySelectorAll('[role="tab"]')) {
      tab.tabIndex = tab.getAttribute('aria-selected') === 'true' ? 0 : -1;
      tab.addEventListener('click', () => setView(tab.dataset.view));
      tab.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault(); const tabs = [...root.querySelectorAll('[role="tab"]')], index = tabs.indexOf(tab);
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        tabs[next].focus(); tabs[next].click();
      });
    }
    let composing = false, searchTimer;
    byId('ncGlobalSearch').addEventListener('submit', event => { event.preventDefault(); void search(); void loadGraph(); });
    byId('ncQuery').addEventListener('input', event => { byId('ncClearSearch').hidden = !event.currentTarget.value.trim(); });
    byId('ncGlobalSearch').addEventListener('reset', event => {
      if (event.target !== byId('ncGlobalSearch')) return;
      clearTimeout(searchTimer);
      queueMicrotask(() => {
        const input = byId('ncQuery');
        input.value = '';
        byId('ncClearSearch').hidden = true;
        void search(''); void loadGraph();
        input.focus();
      });
    });
    byId('ncQuery').addEventListener('compositionstart', () => { composing = true; clearTimeout(searchTimer); });
    byId('ncQuery').addEventListener('compositionend', () => { composing = false; byId('ncQuery').dispatchEvent(new Event('input')); });
    byId('ncQuery').addEventListener('input', () => {
      if (composing) return; clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { void search(); void loadGraph(); }, 280);
    });
    for (const id of ['ncProject', 'ncSource', 'ncCategory']) byId(id).addEventListener('change', () => { void loadGraph(); if (byId('ncQuery').value.trim()) void search(); });
    byId('ncColor').addEventListener('change', () => { renderHex(); drawOrbit(); });
    byId('ncSuggestions').addEventListener('change', () => void loadGraph());
    byId('ncDepth').addEventListener('change', drawOrbit);
    byId('ncMinDegree').addEventListener('input', () => { drawOrbit(); savePreferences(); });
    byId('ncDensity').addEventListener('change', event => { void loadGraph(Number(event.target.value)); savePreferences(); });
    for (const id of ['ncNodeSize', 'ncOpacity', 'ncLinkBrightness', 'ncLinkWidth', 'ncOrbitSpacing', 'ncRenderQuality', 'ncFontScale']) {
      byId(id).addEventListener('input', () => {
        if (id === 'ncOpacity') root.style.setProperty('--nc-panel-alpha', `${byId(id).value}%`);
        if (id === 'ncFontScale') root.style.fontSize = `${byId(id).value}%`;
        drawOrbit(); savePreferences();
      });
    }
    byId('ncTypography').addEventListener('change', event => {
      root.style.fontFamily = event.target.value === 'mono' ? 'ui-monospace,Consolas,monospace' : 'system-ui,Segoe UI,sans-serif'; savePreferences();
    });
    byId('ncCenter').addEventListener('click', () => { state.panX = 0; state.panY = 0; state.zoom = 1; state.componentFocus = null; state.groupFocus = null; byId('ncZoomPref').value = '100'; drawOrbit(); savePreferences(); });
    byId('ncLoadMore').addEventListener('click', () => { const next = Math.min(1000, state.offset + 120); if (next > state.offset) void loadGraph(next); });
    byId('ncShowLabels').addEventListener('change', event => { state.labels = event.target.checked; drawOrbit(); savePreferences(); });
    byId('ncReducedMotion').addEventListener('change', event => { state.reducedMotion = event.target.checked; event.currentTarget.setAttribute('aria-pressed', String(event.target.checked)); savePreferences(); });
    byId('ncLowMotion').addEventListener('click', event => { const toggle = byId('ncReducedMotion'); toggle.checked = !toggle.checked; toggle.dispatchEvent(new Event('change', {bubbles: true})); event.currentTarget.setAttribute('aria-pressed', String(toggle.checked)); });
    byId('ncZoomPref').addEventListener('input', event => { state.zoom = Number(event.target.value) / 100; drawOrbit(); savePreferences(); });
    byId('ncResetPrefs').addEventListener('click', () => {
      try { localStorage.removeItem('rabanito.ui.theme'); localStorage.removeItem('rabanito.ui.preferences'); } catch { /* continue with defaults */ }
      root.style.removeProperty('--left-width'); root.style.removeProperty('--right-width');
      byId('ncDensity').value = '180'; byId('ncNodeSize').value = '6'; byId('ncMinDegree').value = '0'; byId('ncZoomPref').value = '100'; byId('ncOpacity').value = '92'; byId('ncLinkBrightness').value = '62'; byId('ncLinkWidth').value = '1'; byId('ncOrbitSpacing').value = '100'; byId('ncRenderQuality').value = '150'; byId('ncFontScale').value = '100'; byId('ncTypography').value = 'system'; byId('ncShowLabels').checked = true; byId('ncReducedMotion').checked = false;
      root.style.setProperty('--nc-panel-alpha', '92%'); root.style.fontSize = '100%'; root.style.fontFamily = 'system-ui,Segoe UI,sans-serif';
      state.zoom = 1; state.labels = true; state.reducedMotion = false; setTheme('raven-neon'); drawOrbit();
    });
    byId('ncOpenOriginal').addEventListener('click', async () => {
      if (!state.selectedDocument) return;
      byId('ncOpenOriginal').disabled = true;
      try { await api(`/api/open/${Number(state.selected)}`, {}); setStatus('El documento se abrió mediante la ruta autorizada del servidor local.'); }
      catch (error) { setStatus(`No se pudo abrir la fuente autorizada: ${String(error.message || 'error').slice(0, 160)}`, 'error'); }
      finally { byId('ncOpenOriginal').disabled = false; }
    });
    byId('ncGetContext').addEventListener('click', () => void retrieveContext());
    for (const button of root.querySelectorAll('[data-module]')) button.addEventListener('click', () => openModule(button.dataset.module));
    doc.addEventListener('rabanito-command-selection', event => { const id = event.detail?.id ?? event.detail?.node?.document_id; if (id != null) void inspect(id); });
    bindOrbitCanvas(); bindPanelResizers();
  }

  preserveLegacyDashboard(); loadPreferences(); bind();
  void Promise.allSettled([loadOptions(), loadStats()]).then(() => loadGraph());
  return {state, search, loadGraph, inspect, setView, drawOrbit};
}

export function startKnowledge(doc, fetcher = fetch) {
  const byId = id => doc.getElementById(id);
  if (!byId('knowledgePanel')) return;
  const api = (path, body) => requestJson(path, body, fetcher);
  const listGate = createRequestGate(), detailGate = createRequestGate();
  let offset = 0, total = 0, busy = false, loaded = false, timer, composing = false;
  const node = (tag, text, className) => {
    const item = doc.createElement(tag);
    if (text !== undefined) item.textContent = String(text);
    if (className) item.className = className;
    return item;
  };
  const mode = () => byId('knowledgeMode').value;
  function pageState() {
    byId('knowledgePrev').disabled = busy || mode() !== 'security' || offset === 0;
    byId('knowledgeNext').disabled = busy || mode() !== 'security' || offset + 20 >= total;
  }
  function reference(container, url) {
    const safe = safeReference(url);
    if (!safe) return;
    const link = node('a', 'Abrir referencia oficial');
    link.href = safe; link.target = '_blank'; link.rel = 'noopener noreferrer'; container.append(link);
  }
  async function detail(id) {
    const generation = detailGate.begin();
    byId('knowledgeDetail').setAttribute('aria-busy', 'true');
    try {
      const item = await api('/api/security/get', {id});
      if (!detailGate.current(generation)) return;
      const content = doc.createDocumentFragment();
      content.append(node('h3', item.title), node('p', `${item.id} · ${item.edition} · ${item.edition_status}`, 'meta'),
        node('p', item.summary), node('p', `Procedencia: ${item.source_url} · ${item.locator}`, 'meta'),
        node('p', `Revisión: ${item.reviewed_on} · resumen propio de fuente citada`, 'meta'));
      reference(content, item.source_url);
      for (const relation of item.relations || []) content.append(node('p', `${relation.source_id} → ${relation.target_id}: ${relation.relation_type} · ${relation.validation}`, 'meta'));
      content.append(node('p', 'Las relaciones editoriales son sugerencias conceptuales, no equivalencias normativas ni cumplimiento demostrado.', 'meta'));
      byId('knowledgeDetail').replaceChildren(content);
      byId('knowledgeDetail').focus();
    } catch {
      if (detailGate.current(generation)) byId('knowledgeDetail').textContent = 'No se pudo recuperar la ficha. Selecciónala de nuevo para reintentar.';
    } finally {
      if (detailGate.current(generation)) byId('knowledgeDetail').setAttribute('aria-busy', 'false');
    }
  }
  function render(data, selectedMode) {
    const content = doc.createDocumentFragment();
    const results = selectedMode === 'patterns' ? data.patterns : data.results;
    for (const item of results || []) {
      const card = node('article', undefined, 'result'); card.setAttribute('role', 'listitem');
      if (selectedMode === 'security') {
        const button = node('button', item.title); button.type = 'button'; button.addEventListener('click', () => detail(item.id));
        card.append(button, node('div', `${item.id} · ${item.edition_status} · revisión ${item.reviewed_on}`, 'meta'), node('p', item.summary));
      } else if (selectedMode === 'coding') {
        card.append(node('h3', item.title), node('div', `${item.project} · ${item.recorded_date} · validación registrada, no ejecutada de nuevo`, 'meta'));
        for (const fragment of item.fragments || []) card.append(node('pre', fragment.text), node('p', fragment.citation, 'meta'));
        card.append(node('p', `Evidencias: ${(item.evidence || []).join(' · ')}`, 'meta'));
      } else {
        card.append(node('h3', item.technology), node('p', `${item.record_count_in_examined_sample} registros en la muestra · ${(item.projects || []).join(', ')}`),
          node('p', 'Revisa las soluciones citadas y sus precondiciones antes de reutilizarlas. La recurrencia no demuestra una causa común.', 'meta'));
        for (const citation of item.citations || []) card.append(node('p', citation, 'meta'));
      }
      content.append(card);
    }
    if (!(results || []).length) content.append(node('p', selectedMode === 'security' ? 'Sin coincidencias en el catálogo local.' : 'Sin experiencias o recurrencias revisadas para estos filtros. No se han generado datos de ejemplo.', 'meta'));
    byId('knowledgeResults').replaceChildren(content);
  }
  async function search(reset = true) {
    clearTimeout(timer);
    if (reset) offset = 0;
    const selectedMode = mode(), query = byId('knowledgeQuery').value.trim();
    if (selectedMode === 'coding' && !query && !byId('knowledgeTechnology').value.trim()) {
      listGate.begin(); detailGate.begin(); busy = false;
      byId('knowledgeResults').replaceChildren();
      byId('knowledgeResults').setAttribute('aria-busy', 'false');
      byId('knowledgeDetail').setAttribute('aria-busy', 'false');
      byId('knowledgeDetail').textContent = 'Describe un problema o selecciona una tecnología; no se generan experiencias de ejemplo.';
      byId('knowledgeStatus').textContent = 'Escribe un problema o una tecnología para recuperar experiencias revisadas.';
      pageState(); return;
    }
    const generation = listGate.begin(); detailGate.begin(); busy = true; pageState();
    byId('knowledgeResults').setAttribute('aria-busy', 'true');
    byId('knowledgeDetail').setAttribute('aria-busy', 'false');
    byId('knowledgeDetail').textContent = 'Selecciona una ficha. Los fragmentos de experiencias incluyen sus citas.';
    byId('knowledgeStatus').textContent = 'Consultando memoria local…';
    try {
      const body = selectedMode === 'security' ? {q: query, status: byId('knowledgeEdition').value, limit: 20, offset} :
        {project: byId('knowledgeProject').value.trim() || null, limit: selectedMode === 'coding' ? 5 : 10};
      if (selectedMode === 'coding') Object.assign(body, {q: query, technology: byId('knowledgeTechnology').value.trim() || null, max_chars: 6000});
      const path = selectedMode === 'security' ? '/api/security/search' : selectedMode === 'coding' ? '/api/coding/similar' : '/api/coding/patterns';
      const data = await api(path, body);
      if (!listGate.current(generation)) return;
      total = selectedMode === 'security' ? data.total : (data.results || data.patterns || []).length;
      render(data, selectedMode);
      byId('knowledgeCount').textContent = selectedMode === 'security' ? `${total ? offset + 1 : 0}–${Math.min(offset + 20, total)} de ${total} fichas` : `${total} resultados acotados`;
      const coverage = data.coverage || {};
      const limited = coverage.candidate_limit_reached || coverage.byte_budget_reached;
      byId('knowledgeStatus').textContent = selectedMode === 'security' ? `Catálogo ${data.catalog_version || 'sin indexar'} · fuentes públicas citadas, consulta sin red.` :
        `Solo registros revisados con evidencia local. ${coverage.candidates_examined || 0} candidatos examinados; ${coverage.stale_or_unverifiable_skipped || 0} omitidos por hash/evidencia. ${limited ? 'Cobertura parcial por límite.' : ''} La similitud es léxica, no causal.`;
    } catch {
      if (listGate.current(generation)) byId('knowledgeStatus').textContent = 'No se pudo consultar. Los resultados anteriores pueden estar desactualizados; vuelve a consultar para reintentar.';
    } finally {
      if (listGate.current(generation)) {busy = false; byId('knowledgeResults').setAttribute('aria-busy', 'false'); pageState();}
    }
  }
  byId('knowledgePanel').addEventListener('toggle', () => {if (byId('knowledgePanel').open && !loaded) {loaded = true; search();}});
  byId('knowledgeForm').addEventListener('submit', event => {event.preventDefault(); search();});
  byId('knowledgeMode').addEventListener('change', () => {
    const security = mode() === 'security', coding = mode() === 'coding';
    for (const id of ['knowledgeEdition', 'knowledgeEditionLabel']) byId(id).hidden = !security;
    for (const id of ['knowledgeProject', 'knowledgeProjectLabel']) byId(id).hidden = security;
    for (const id of ['knowledgeTechnology', 'knowledgeTechnologyLabel']) byId(id).hidden = !coding;
    byId('knowledgeQuery').disabled = !security && !coding;
    byId('knowledgeQuery').placeholder = security ? 'Zero Trust, MFA, control…' : 'Describe el problema técnico…';
    byId('knowledgeQuery').value = ''; byId('knowledgeClear').hidden = true;
    byId('knowledgeResults').replaceChildren(); search();
  });
  const input = () => {byId('knowledgeClear').hidden = !byId('knowledgeQuery').value; if (!composing) {clearTimeout(timer); timer = setTimeout(() => search(), 300);}};
  byId('knowledgeQuery').addEventListener('compositionstart', () => {composing = true; clearTimeout(timer);});
  byId('knowledgeQuery').addEventListener('compositionend', () => {composing = false; input();});
  byId('knowledgeQuery').addEventListener('input', input);
  byId('knowledgeClear').addEventListener('click', () => {byId('knowledgeQuery').value = ''; byId('knowledgeClear').hidden = true; search(); byId('knowledgeQuery').focus();});
  for (const id of ['knowledgeEdition', 'knowledgeProject', 'knowledgeTechnology']) byId(id).addEventListener('change', () => search());
  byId('knowledgePrev').addEventListener('click', () => {if (!busy && offset > 0) {offset -= 20; search(false);}});
  byId('knowledgeNext').addEventListener('click', () => {if (!busy && offset + 20 < total) {offset += 20; search(false);}});
  return {search, detail};
}

if (typeof document !== 'undefined') {
  startKnowledge(document);
  startCommandCenter(document);
}
