import {createRequestGate, requestJson, safeReference} from './cyber.js';

const ORBIT_PALETTE = ['#5de4c5', '#62c8dd', '#b39af6', '#f2a35f', '#8ed0a4', '#e7a6c9', '#a6b8e8'];
export const TYPED_GRAPH_MAX_NODES = 1000, TYPED_GRAPH_MAX_EDGES = 4000;
const stableKey = value => String(value ?? '').normalize('NFC').trim() || 'Sin clasificar';
const ENTITY_KIND_LABELS = Object.freeze({
  project: 'Proyecto', document: 'Documento', decision: 'Decisión', solution: 'Experiencia revisada',
  vulnerability: 'Vulnerabilidad', observation: 'Observación pública', weakness: 'Debilidad (CWE)',
  package: 'Paquete', security_concept: 'Concepto de seguridad', reference: 'Referencia',
  product_condition: 'Condición de producto', standard: 'Estándar', control: 'Control',
  dependency: 'Dependencia', dependency_declaration: 'Declaración de dependencia', technology: 'Tecnología',
  snapshot: 'Captura de versión', review: 'Revisión', security_advisory: 'Aviso de seguridad',
  attack_technique: 'Técnica ATT&CK', attack_campaign: 'Campaña ATT&CK', attack_mitigation: 'Mitigación ATT&CK',
  threat_group: 'Grupo de intrusión', attack_software: 'Software ATT&CK', attack_matrix: 'Matriz ATT&CK',
  attack_tactic: 'Táctica ATT&CK', attack_analytic: 'Analítica ATT&CK',
  attack_data_component: 'Componente de datos ATT&CK', attack_data_source: 'Fuente de datos ATT&CK',
  attack_detection_strategy: 'Estrategia de detección ATT&CK', attack_asset: 'Activo ATT&CK',
  attack_collection: 'Colección ATT&CK',
});
export function entityKindLabel(value) {
  const kind = String(value ?? '').slice(0, 80);
  return ENTITY_KIND_LABELS[kind] || kind.replaceAll('_', ' ') || 'Entidad';
}

// Pure projections are exported so the real frontend behavior can be tested without a live index.
export function normalizeCommandGraph(payload) {
  const typed = Number(payload?.schema_version) === 1;
  const sourceNodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
  const nodes = sourceNodes.map(raw => {
    const id = raw?.document_id ?? raw?.id;
    if (!(typeof id === 'string' || Number.isSafeInteger(id)) || String(id).length > 160) return null;
    const data = raw.data && typeof raw.data === 'object' && !Array.isArray(raw.data) ? raw.data : {};
    const typedDocumentId = Number(data.document_id ?? (/^(?:document|solution):(\d+)$/.exec(String(id)) || [])[1]);
    const citation = safeGraphCitation(raw.citation);
    return {
      ...raw, id: String(id), title: String(raw.title ?? raw.name ?? 'Sin título').slice(0, 500),
      category: String(raw.category ?? ''), source_kind: String(raw.source_kind ?? raw.source ?? ''),
      project_name: String(raw.project_name ?? raw.project ?? (raw.contributor_project_id ? `Proyecto ${raw.contributor_project_id}` : '')),
      entity_kind: String(raw.entity_kind ?? (typed ? raw.kind : 'document') ?? 'document').slice(0, 80),
      document_id: Number.isSafeInteger(typedDocumentId) && typedDocumentId > 0 ? typedDocumentId : null,
      citation: citation.display, relative_path: safeRelativePath(raw.relative_path || citation.relativePath),
      data, degree: Math.max(0, Number(raw.degree) || 0),
    };
  }).filter(Boolean);
  const uniqueNodes = [...new Map(nodes.map(node => [node.id, node])).values()];
  const ids = new Set(uniqueNodes.map(node => node.id));
  const edges = (Array.isArray(payload?.edges) ? payload.edges : []).flatMap(raw => {
    const source = String(raw?.source ?? ''), target = String(raw?.target ?? '');
    if (!ids.has(source) || !ids.has(target) || source === target) return [];
    const classification = String(raw.classification ?? raw.kind ?? '');
    const validation = String(raw.validation ?? '');
    const kind = ['suggested', 'inferred', 'reviewed_claim', 'explicit'].includes(classification)
      ? classification
      : classification === 'suggested' || validation === 'suggested' ? 'suggested'
        : classification === 'inferred' || validation.startsWith('inferred') ? 'inferred'
          : classification === 'reviewed_claim' || validation === 'reviewed_claim' || validation.startsWith('reviewed_') ? 'reviewed_claim'
            : 'explicit';
    return [{...raw, source, target, kind}];
  });
  const uniqueEdges = [...new Map(edges.map(edge => [`${edge.source}\u0000${edge.target}\u0000${edge.kind}\u0000${edge.relation_type || ''}`, edge])).values()];
  const degrees = new Map(uniqueNodes.map(node => [node.id, 0]));
  for (const edge of uniqueEdges) { degrees.set(edge.source, degrees.get(edge.source) + 1); degrees.set(edge.target, degrees.get(edge.target) + 1); }
  const normalizedNodes = uniqueNodes.map(node => ({...node, degree: Math.max(node.degree, degrees.get(node.id) || 0)}));
  return {
    nodes: normalizedNodes, edges: uniqueEdges,
    totalMatches: Math.max(normalizedNodes.length, Number(payload?.total_matches ?? payload?.total_candidates) || 0),
    truncated: Boolean(payload?.truncated ?? payload?.has_more),
    typed, coverage: payload?.coverage || null, projectionAvailable: payload?.projection_available,
    nextCursor: typeof payload?.next_cursor === 'string' ? payload.next_cursor : null,
  };
}

export function safeGraphCitation(citation) {
  const value = String(citation ?? '').trim();
  if (!value || value.length > 4000 || /[\x00-\x1f\x7f]/.test(value)) return {display: '', relativePath: ''};
  if (/^https:\/\//i.test(value)) {
    try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? {display: url.href.slice(0, 1000), relativePath: ''} : {display: '', relativePath: ''}; }
    catch { return {display: '', relativePath: ''}; }
  }
  const match = /^(obsidian|projects|internal|index|cyber|security|attack):(.+)$/i.exec(value);
  if (!match) return {display: '', relativePath: ''};
  let relative = match[2];
  if (match[1].toLowerCase() === 'projects') relative = relative.replace(/^\d+:/, '');
  const safe = safeRelativePath(relative);
  return safe ? {display: value.slice(0, 1000), relativePath: safe} : {display: '', relativePath: ''};
}

export function mergeBoundedTypedGraph(current, incoming, {maxNodes = TYPED_GRAPH_MAX_NODES, maxEdges = TYPED_GRAPH_MAX_EDGES} = {}) {
  const safeNodeCap = Math.min(TYPED_GRAPH_MAX_NODES, Math.max(1, Math.floor(Number(maxNodes) || 1)));
  const safeEdgeCap = Math.min(TYPED_GRAPH_MAX_EDGES, Math.max(0, Math.floor(Number(maxEdges) || 0)));
  const oldNodes = Array.isArray(current?.nodes) ? current.nodes.slice(0, safeNodeCap) : [];
  const newNodes = Array.isArray(incoming?.nodes) ? incoming.nodes.slice(0, safeNodeCap) : [];
  const nodes = [...new Map([...oldNodes, ...newNodes].map(node => [String(node.id), node])).values()].slice(0, safeNodeCap);
  const ids = new Set(nodes.map(node => String(node.id)));
  const oldEdges = Array.isArray(current?.edges) ? current.edges.slice(0, safeEdgeCap) : [];
  const newEdges = Array.isArray(incoming?.edges) ? incoming.edges.slice(0, safeEdgeCap) : [];
  const edges = [...new Map([...oldEdges, ...newEdges]
    .filter(edge => ids.has(String(edge.source)) && ids.has(String(edge.target)))
    .map(edge => [`${edge.source}\u0000${edge.target}\u0000${edge.kind}\u0000${edge.relation_type || ''}`, edge])).values()].slice(0, safeEdgeCap);
  return normalizeCommandGraph({schema_version: 1, projection_available: true, nodes, edges,
    total_candidates: Math.max(Number(current?.totalMatches) || 0, Number(incoming?.total_candidates ?? incoming?.total_matches) || 0),
    has_more: Boolean(incoming?.has_more), next_cursor: incoming?.next_cursor ?? null,
    coverage: incoming?.coverage ?? current?.coverage ?? null});
}

export function typedPageContinuation(current, incoming, {update = true} = {}) {
  if (!update) return {hasMore: Boolean(current?.hasMore), cursor: current?.cursor ?? null};
  return {hasMore: Boolean(incoming?.truncated), cursor: incoming?.nextCursor ?? null};
}

export function typedPageLimit(current, requested, append = false) {
  const normalized = Math.min(200, Math.max(0, Math.floor(Number(requested) || 0)));
  return append && Number.isInteger(current) && current >= 0 && current <= 200 ? current : normalized;
}

export function orbitLayoutKey({width, height, spacing, depth, minimumDegree, selectedId, componentFocus, groupBasis, groupName}) {
  const selectionAffectsVisibility = Number(depth) > 0 || Number(minimumDegree) > 0;
  return JSON.stringify([width, height, spacing, String(depth), String(minimumDegree), selectionAffectsVisibility ? selectedId : null, componentFocus, groupBasis, groupName]);
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

const MARKDOWN_MAX_CHARACTERS = 65_536;
const MARKDOWN_MAX_BLOCKS = 2_048;
const MARKDOWN_MAX_LINES = 4_096;
const normalizeReference = value => String(value ?? '').normalize('NFC').trim().replace(/\\/g, '/').replace(/^\.\//, '').toLocaleLowerCase('en');

function resolveMarkdownReference(target, references) {
  const lookup = normalizeReference(String(target ?? '').split('#', 1)[0]);
  if (!lookup || lookup.length > 1000) return null;
  for (const reference of references) {
    const id = Number(reference?.target_document_id ?? reference?.document_id);
    if (!Number.isSafeInteger(id) || id <= 0) continue;
    const candidates = [reference.target_raw, reference.title, safeRelativePath(reference.relative_path)].filter(value => typeof value === 'string' && value.length > 0 && value.length <= 1000).map(normalizeReference);
    if (candidates.includes(lookup)) return {documentId: id, title: String(reference.title || reference.target_raw || `Documento ${id}`).slice(0, 500)};
  }
  return null;
}

function parseMarkdownInline(value, references, depth = 0) {
  const text = String(value ?? '');
  const tokens = [];
  const addText = part => {
    if (!part) return;
    const previous = tokens.at(-1);
    if (previous?.type === 'text') previous.text += part;
    else tokens.push({type: 'text', text: part});
  };
  let index = 0;
  while (index < text.length) {
    if (text[index] === '\\' && index + 1 < text.length) { addText(text[index + 1]); index += 2; continue; }
    if (text.startsWith('[[', index)) {
      const close = text.indexOf(']]', index + 2);
      if (close !== -1 && close - index <= 1000) {
        const [target, ...alias] = text.slice(index + 2, close).split('|');
        const resolved = resolveMarkdownReference(target, references);
        if (resolved) tokens.push({type: 'document', ...resolved, label: String(alias.join('|') || resolved.title).slice(0, 500)});
        else addText(String(alias.join('|') || target));
        index = close + 2; continue;
      }
    }
    if (text[index] === '`') {
      let run = 1; while (text[index + run] === '`') run += 1;
      const fence = '`'.repeat(run), close = text.indexOf(fence, index + run);
      if (close !== -1) { tokens.push({type: 'code', text: text.slice(index + run, close).replace(/\n/g, ' ')}); index = close + run; continue; }
    }
    const link = text.slice(index).match(/^\[([^\]]{1,500})\]\(([^)\s]{1,1000})(?:\s+"[^"]{0,200}")?\)/);
    if (link) {
      const destination = link[2], resolved = resolveMarkdownReference(destination, references), href = safeReference(destination);
      if (resolved) tokens.push({type: 'document', ...resolved, label: link[1].slice(0, 500)});
      else if (href) tokens.push({type: 'link', href, children: depth < 4 ? parseMarkdownInline(link[1], references, depth + 1) : [{type: 'text', text: link[1]}]});
      else addText(link[1]);
      index += link[0].length; continue;
    }
    if (depth < 4) {
      const marker = text.startsWith('**', index) ? '**' : text.startsWith('__', index) ? '__' : text[index] === '*' ? '*' : text[index] === '_' ? '_' : '';
      if (marker) {
        const close = text.indexOf(marker, index + marker.length);
        if (close > index + marker.length && !/\s/.test(text[index + marker.length])) {
          const children = parseMarkdownInline(text.slice(index + marker.length, close), references, depth + 1);
          tokens.push({type: marker.length === 2 ? 'strong' : 'emphasis', children}); index = close + marker.length; continue;
        }
      }
    }
    addText(text[index]); index += 1;
  }
  return tokens;
}

// Parse only a bounded Markdown subset. The returned tree contains no HTML nodes or caller paths.
export function parseSafeMarkdown(markdown, references = []) {
  if (typeof markdown !== 'string' || markdown.length > MARKDOWN_MAX_CHARACTERS) throw new Error('El Markdown excede el límite seguro de 65,536 caracteres.');
  const lines = markdown.replace(/\r\n?/g, '\n').split('\n').slice(0, MARKDOWN_MAX_LINES);
  const refs = Array.isArray(references) ? references.slice(0, 512) : [];
  const blocks = [];
  const inline = text => parseMarkdownInline(text, refs);
  const isTableSeparator = value => /^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(value);
  const isList = value => /^\s{0,3}(?:[-+*]|\d+[.)])\s+/.test(value);
  const startsBlock = value => /^\s{0,3}(?:#{1,6}\s|```+|~~~+|>\s?|(?:-{3,}|\*{3,}|_{3,})\s*$)/.test(value) || isList(value);
  const cells = value => value.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').slice(0, 20).map(cell => cell.trim());
  let index = 0;
  while (index < lines.length && blocks.length < MARKDOWN_MAX_BLOCKS) {
    const line = lines[index];
    if (!line.trim()) { index += 1; continue; }
    const fence = line.match(/^\s{0,3}(`{3,}|~{3,})\s*([\w.+-]{0,40})[^\n]*$/);
    if (fence) {
      const content = []; index += 1;
      while (index < lines.length && !new RegExp(`^\\s{0,3}${fence[1][0]}{${fence[1].length},}\\s*$`).test(lines[index])) { if (content.length < MARKDOWN_MAX_LINES) content.push(lines[index]); index += 1; }
      if (index < lines.length) index += 1;
      blocks.push({type: 'codeBlock', language: fence[2], text: content.join('\n')}); continue;
    }
    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (heading) { blocks.push({type: 'heading', level: heading[1].length, children: inline(heading[2])}); index += 1; continue; }
    if (/^\s{0,3}(?:(?:-\s*){3,}|(?:\*\s*){3,}|(?:_\s*){3,})$/.test(line)) { blocks.push({type: 'rule'}); index += 1; continue; }
    if (/^\s*>/.test(line)) {
      const quote = [];
      while (index < lines.length && /^\s*>/.test(lines[index])) quote.push(lines[index++].replace(/^\s*>\s?/, ''));
      blocks.push({type: 'blockquote', children: inline(quote.join(' '))}); continue;
    }
    if (isList(line)) {
      const ordered = /^\s{0,3}\d+[.)]/.test(line), items = [];
      while (index < lines.length && isList(lines[index]) && /^\s{0,3}\d+[.)]/.test(lines[index]) === ordered && items.length < 200) {
        items.push(inline(lines[index].replace(/^\s{0,3}(?:[-+*]|\d+[.)])\s+/, ''))); index += 1;
      }
      blocks.push({type: 'list', ordered, items}); continue;
    }
    if (line.includes('|') && index + 1 < lines.length && isTableSeparator(lines[index + 1])) {
      const headers = cells(line), rows = []; index += 2;
      while (index < lines.length && lines[index].includes('|') && rows.length < 200) { rows.push(cells(lines[index]).slice(0, headers.length)); index += 1; }
      blocks.push({type: 'table', headers: headers.map(inline), rows: rows.map(row => Array.from({length: headers.length}, (_, cellIndex) => inline(row[cellIndex] || '')))}); continue;
    }
    const paragraph = [line.trim()]; index += 1;
    while (index < lines.length && lines[index].trim() && !startsBlock(lines[index]) && !(lines[index].includes('|') && index + 1 < lines.length && isTableSeparator(lines[index + 1]))) paragraph.push(lines[index++].trim());
    blocks.push({type: 'paragraph', children: inline(paragraph.join(' '))});
  }
  if (lines.length >= MARKDOWN_MAX_LINES || blocks.length >= MARKDOWN_MAX_BLOCKS) blocks.push({type: 'notice', text: 'Se alcanzó el límite de elementos mostrados.'});
  return blocks;
}

const MARKDOWN_RESPONSE_KEYS = ['document_id', 'content_markdown', 'bytes_returned', 'truncated', 'references'];
const MARKDOWN_REFERENCE_KEYS = ['target_document_id', 'title', 'target_raw', 'relative_path', 'status'];

function hasExactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function safeDocumentPath(value) {
  if (typeof value !== 'string' || !value || value.length > 1000
      || /^[\\/]|^~(?:[\\/]|$)|^[a-z][a-z\d+.-]*:/i.test(value)) return false;
  const parts = value.replace(/\\/g, '/').split('/');
  return parts.every(part => part && part !== '.' && part !== '..' && !/[<>:"|?*\x00-\x1f\x7f]/.test(part) && !/[ .]$/.test(part));
}

function safeReferenceTarget(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 1000
    && !/^[\\/]|^~|^[a-z][a-z\d+.-]*:/i.test(value)
    && !/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(value)
    && !/[\x00-\x1f\x7f]/.test(value);
}

export function validateMarkdownResponse(payload, expectedDocumentId) {
  if (!hasExactKeys(payload, MARKDOWN_RESPONSE_KEYS)
      || !Number.isSafeInteger(expectedDocumentId) || expectedDocumentId <= 0
      || payload.document_id !== expectedDocumentId
      || typeof payload.content_markdown !== 'string' || payload.content_markdown.length > MARKDOWN_MAX_CHARACTERS
      || !Number.isSafeInteger(payload.bytes_returned) || payload.bytes_returned < 0
      || payload.bytes_returned > MARKDOWN_MAX_CHARACTERS || typeof payload.truncated !== 'boolean'
      || !Array.isArray(payload.references) || payload.references.length > 512) {
    throw new Error('La respuesta del lector no cumple el contrato seguro documentado.');
  }
  const actualBytes = new TextEncoder().encode(payload.content_markdown).byteLength;
  if (actualBytes !== payload.bytes_returned || actualBytes > MARKDOWN_MAX_CHARACTERS) {
    throw new Error('La longitud UTF-8 de la respuesta no cumple el límite del lector.');
  }
  for (const reference of payload.references) {
    if (!hasExactKeys(reference, MARKDOWN_REFERENCE_KEYS)
        || !Number.isSafeInteger(reference.target_document_id) || reference.target_document_id <= 0
        || typeof reference.title !== 'string' || !reference.title || reference.title.length > 1000
        || !safeReferenceTarget(reference.target_raw) || !safeDocumentPath(reference.relative_path)
        || reference.status !== 'resolved') {
      throw new Error('La respuesta incluye una referencia fuera del contrato autorizado.');
    }
  }
  return payload.content_markdown;
}

export async function openAuthorizedSource(documentId, request, setStatus) {
  const failure = 'No se pudo confirmar la apertura de la fuente autorizada. Reintenta desde el panel.';
  try {
    const result = await request(`/api/open/${Number(documentId)}`, {});
    if (result?.opened !== true) { setStatus(failure, 'error'); return false; }
    setStatus('El documento se abrió mediante la ruta autorizada del servidor local.');
    return true;
  } catch {
    setStatus(failure, 'error');
    return false;
  }
}

function componentsFromAdjacency(adjacency) {
  const ids = [...adjacency.keys()].sort((a, b) => a.localeCompare(b, 'en'));
  const componentById = new Map(); let componentNumber = 0;
  for (const start of ids) {
    if (componentById.has(start)) continue;
    componentNumber += 1; const label = `Conectividad ${componentNumber}`, queue = [start]; componentById.set(start, label);
    for (let cursor = 0; cursor < queue.length; cursor += 1) for (const neighbor of adjacency.get(queue[cursor]) || []) if (!componentById.has(neighbor)) { componentById.set(neighbor, label); queue.push(neighbor); }
  }
  return componentById;
}

export function connectedComponents(graph) {
  return componentsFromAdjacency(explicitAdjacency(graph));
}

export function detectGraphCommunities(graph) {
  let adjacency = new Map([...explicitAdjacency(graph)].map(([id, neighbors]) => [id, new Map([...neighbors].map(neighbor => [neighbor, 1]))]));
  let members = new Map([...adjacency.keys()].map(id => [id, [id]]));
  let finalCommunities = null;
  for (let level = 0; level < 8; level += 1) {
    const ids = [...adjacency.keys()].sort((a, b) => a.localeCompare(b, 'en'));
    const neighbors = new Map(ids.map(id => [id, [...adjacency.get(id).keys()].filter(neighbor => neighbor !== id).sort((a, b) => a.localeCompare(b, 'en'))]));
    const degree = new Map(ids.map(id => [id, [...adjacency.get(id).values()].reduce((sum, weight) => sum + weight, 0)]));
    const totalDegree = [...degree.values()].reduce((sum, value) => sum + value, 0);
    const community = new Map(ids.map(id => [id, id]));
    if (totalDegree) {
      const communityDegree = new Map(ids.map(id => [id, degree.get(id) || 0]));
      for (let pass = 0; pass < 12; pass += 1) {
        let movedAny = false;
        for (const id of ids) {
          const nodeDegree = degree.get(id) || 0;
          if (!nodeDegree) continue;
          const current = community.get(id), currentDegree = (communityDegree.get(current) || 0) - nodeDegree;
          const selfLoop = adjacency.get(id).get(id) || 0, neighborWeight = new Map([[current, selfLoop]]);
          for (const neighbor of neighbors.get(id)) {
            const neighborCommunity = community.get(neighbor);
            neighborWeight.set(neighborCommunity, (neighborWeight.get(neighborCommunity) || 0) + adjacency.get(id).get(neighbor));
          }
          let best = current, bestGain = (neighborWeight.get(current) || 0) - nodeDegree * currentDegree / totalDegree;
          for (const [candidate, weight] of neighborWeight) {
            const candidateDegree = (communityDegree.get(candidate) || 0) - (candidate === current ? nodeDegree : 0);
            const gain = weight + (candidate === current ? 0 : selfLoop) - nodeDegree * candidateDegree / totalDegree;
            if (gain > bestGain + 1e-9) { best = candidate; bestGain = gain; }
          }
          if (best !== current) {
            communityDegree.set(current, currentDegree);
            communityDegree.set(best, (communityDegree.get(best) || 0) + nodeDegree);
            community.set(id, best); movedAny = true;
          }
        }
        if (!movedAny) break;
      }
    }
    finalCommunities = community;
    const labels = [...new Set(community.values())];
    if (labels.length === ids.length || level === 7) break;
    const nextAdjacency = new Map(labels.map(label => [label, new Map()]));
    const nextMembers = new Map(labels.map(label => [label, []]));
    for (const id of ids) nextMembers.get(community.get(id)).push(...members.get(id));
    for (const [id, linked] of adjacency) {
      const from = community.get(id);
      for (const [neighbor, weight] of linked) {
        const to = community.get(neighbor), row = nextAdjacency.get(from);
        row.set(to, (row.get(to) || 0) + weight);
      }
    }
    adjacency = nextAdjacency; members = nextMembers;
  }
  const originalGroups = new Map();
  for (const [id, originalIds] of members) {
    const label = finalCommunities.get(id);
    if (!originalGroups.has(label)) originalGroups.set(label, []);
    originalGroups.get(label).push(...originalIds);
  }
  const orderedLabels = [...originalGroups].sort((a, b) => a[1].sort((x, y) => x.localeCompare(y, 'en'))[0].localeCompare(b[1].sort((x, y) => x.localeCompare(y, 'en'))[0], 'en'));
  const names = new Map(orderedLabels.map(([label], index) => [label, `Comunidad ${index + 1}`]));
  return new Map([...originalGroups].flatMap(([label, originalIds]) => originalIds.map(id => [id, names.get(label)])));
}
export function groupCommandNodes(nodes, groupBy = 'category', graph = null, componentMap = null) {
  const field = groupBy === 'source' ? 'source_kind' : groupBy === 'project' ? 'project_name' : groupBy === 'kind' ? 'entity_kind' : 'category';
  const groupsByNode = groupBy === 'component' && graph
    ? (componentMap || connectedComponents(graph))
    : groupBy === 'community' && graph ? (componentMap || detectGraphCommunities(graph)) : null;
  const groups = new Map();
  for (const node of nodes) {
    const name = groupsByNode ? (groupsByNode.get(node.id) || 'Sin conectar') : stableKey(node[field]);
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(node);
  }
  return [...groups].map(([name, items]) => ({name, count: items.length, nodes: items}))
    .sort((a, b) => {
      if (groupBy === 'community') {
        const aIndex = Number(a.name.match(/\d+$/)?.[0] || 0), bIndex = Number(b.name.match(/\d+$/)?.[0] || 0);
        return aIndex - bIndex || a.name.localeCompare(b.name, 'es-MX');
      }
      return b.count - a.count || a.name.localeCompare(b.name, 'es-MX');
    });
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
  const graphGate = createRequestGate(), searchGate = createRequestGate(), inspectGate = createRequestGate(), markdownGate = createRequestGate();
  const state = {graph: normalizeCommandGraph({}), graphMode: 'documents', typedHasMore: false, typedCursor: null, typedPageSize: null, typedNeighborCursors: new Map(), typedInFlight: new Set(), typedExpanded: new Set(), projects: [], selected: null, selectedDocument: null, componentFocus: null, groupFocus: null, query: '', offset: 0, nodeDirectoryPage: 0, panX: 0, panY: 0, zoom: 1, dragging: false, labels: true, reducedMotion: false};
  const NODE_DIRECTORY_PAGE_SIZE = 25;
  const TYPED_EXPANSION_CAP = 40;
  let derivedGraph = null, adjacencyCache = null, componentCache = null, communityCache = null;
  let orbitLayoutCache = {graph: null, key: '', value: null};
  const make = (tag, text, className) => {
    const element = doc.createElement(tag);
    if (text !== undefined && text !== null) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  };
  const setStatus = (text, tone = '') => { const status = byId('ncStatus'); status.textContent = text; status.dataset.tone = tone; };
  const safeCount = value => Number.isFinite(Number(value)) ? Number(value).toLocaleString('es-MX') : '—';
  let markdownMatchIndex = 0;

  function renderInline(parent, tokens) {
    for (const token of tokens || []) {
      if (token.type === 'text') { parent.append(doc.createTextNode(token.text)); continue; }
      if (token.type === 'code' || token.type === 'emphasis' || token.type === 'strong') {
        const element = doc.createElement(token.type === 'emphasis' ? 'em' : token.type === 'strong' ? 'strong' : 'code');
        if (token.type === 'code') element.textContent = token.text;
        else renderInline(element, token.children);
        parent.append(element); continue;
      }
      if (token.type === 'link') {
        const href = safeReference(token.href);
        if (!href) { renderInline(parent, token.children); continue; }
        const anchor = doc.createElement('a'); anchor.href = href; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; renderInline(anchor, token.children); parent.append(anchor); continue;
      }
      if (token.type === 'document') {
        const id = Number(token.documentId);
        if (!Number.isSafeInteger(id) || id <= 0) { parent.append(doc.createTextNode(token.label || token.title || 'Referencia')); continue; }
        const button = doc.createElement('button'); button.type = 'button'; button.className = 'nc-markdown-document-link'; button.textContent = token.label || token.title || `Documento ${id}`;
        button.setAttribute('aria-label', `Abrir documento relacionado: ${button.textContent}`); button.addEventListener('click', () => dispatchSelection(id)); parent.append(button);
      }
    }
  }

  function renderMarkdownContent(blocks) {
    const fragment = doc.createDocumentFragment();
    for (const block of blocks) {
      let element;
      if (block.type === 'heading') { element = doc.createElement(`h${block.level}`); renderInline(element, block.children); }
      else if (block.type === 'paragraph') { element = doc.createElement('p'); renderInline(element, block.children); }
      else if (block.type === 'blockquote') { element = doc.createElement('blockquote'); renderInline(element, block.children); }
      else if (block.type === 'rule') element = doc.createElement('hr');
      else if (block.type === 'notice') { element = doc.createElement('p'); element.className = 'nc-pending'; element.textContent = block.text; }
      else if (block.type === 'codeBlock') { element = doc.createElement('pre'); const code = doc.createElement('code'); if (/^[\w.+-]{1,40}$/.test(block.language || '')) code.dataset.language = block.language; code.textContent = block.text; element.append(code); }
      else if (block.type === 'list') {
        element = doc.createElement(block.ordered ? 'ol' : 'ul');
        for (const children of block.items) { const item = doc.createElement('li'); renderInline(item, children); element.append(item); }
      } else if (block.type === 'table') {
        element = doc.createElement('table'); const head = doc.createElement('thead'), headRow = doc.createElement('tr');
        for (const children of block.headers) { const cell = doc.createElement('th'); cell.scope = 'col'; renderInline(cell, children); headRow.append(cell); }
        head.append(headRow); const body = doc.createElement('tbody');
        for (const row of block.rows) { const rowElement = doc.createElement('tr'); for (const children of row) { const cell = doc.createElement('td'); renderInline(cell, children); rowElement.append(cell); } body.append(rowElement); }
        element.append(head, body);
      } else continue;
      fragment.append(element);
    }
    return fragment;
  }

  function clearMarkdownHighlights() {
    const content = byId('ncMarkdownContent');
    for (const mark of content.querySelectorAll('mark[data-reader-match]')) mark.replaceWith(doc.createTextNode(mark.textContent || ''));
    content.normalize();
  }

  function focusMarkdownMatch(index) {
    const matches = [...byId('ncMarkdownContent').querySelectorAll('mark[data-reader-match]')];
    const previous = byId('ncMarkdownPrev'), next = byId('ncMarkdownNext'), status = byId('ncMarkdownSearchStatus');
    previous.disabled = next.disabled = matches.length <= 1;
    if (!matches.length) { status.textContent = '0 coincidencias en este documento.'; return; }
    markdownMatchIndex = (index + matches.length) % matches.length;
    matches.forEach((mark, current) => { mark.setAttribute('aria-current', String(current === markdownMatchIndex)); if (current === markdownMatchIndex) mark.tabIndex = -1; else mark.removeAttribute('tabindex'); });
    const active = matches[markdownMatchIndex]; active.focus?.({preventScroll: true}); active.scrollIntoView?.({block: 'nearest'});
    status.textContent = `Coincidencia ${markdownMatchIndex + 1} de ${matches.length}.`;
  }

  function searchMarkdown() {
    clearMarkdownHighlights();
    const query = String(byId('ncMarkdownQuery').value || '').slice(0, 100).trim();
    if (!query) { markdownMatchIndex = 0; byId('ncMarkdownPrev').disabled = byId('ncMarkdownNext').disabled = true; byId('ncMarkdownSearchStatus').textContent = 'Escribe un término para buscar en el documento actual.'; return; }
    const content = byId('ncMarkdownContent'), walker = doc.createTreeWalker(content, doc.defaultView?.NodeFilter?.SHOW_TEXT || 4), textNodes = [];
    while (walker.nextNode()) if (walker.currentNode.nodeValue) textNodes.push(walker.currentNode);
    const needle = query.toLocaleLowerCase('es-MX');
    for (const textNode of textNodes) {
      const value = textNode.nodeValue || '', lower = value.toLocaleLowerCase('es-MX'), fragment = doc.createDocumentFragment();
      let offset = 0, found = false;
      while (offset < value.length) {
        const match = lower.indexOf(needle, offset);
        if (match < 0) { fragment.append(doc.createTextNode(value.slice(offset))); break; }
        found = true;
        if (match > offset) fragment.append(doc.createTextNode(value.slice(offset, match)));
        const mark = doc.createElement('mark'); mark.dataset.readerMatch = 'true'; mark.textContent = value.slice(match, match + query.length); fragment.append(mark); offset = match + query.length;
      }
      if (found) textNode.replaceWith(fragment);
    }
    markdownMatchIndex = 0;
    focusMarkdownMatch(0);
  }

  function renderMarkdownReferences(references) {
    const list = byId('ncMarkdownReferences'), fragment = doc.createDocumentFragment();
    for (const reference of (Array.isArray(references) ? references : []).slice(0, 100)) {
      const id = Number(reference?.target_document_id ?? reference?.document_id), title = String(reference?.title || reference?.target_raw || 'Referencia sin título').slice(0, 500);
      const item = doc.createElement('li');
      if (Number.isSafeInteger(id) && id > 0) {
        const button = doc.createElement('button'); button.type = 'button'; button.textContent = title; button.setAttribute('aria-label', `Abrir referencia: ${title}`); button.addEventListener('click', () => dispatchSelection(id)); item.append(button);
      } else item.textContent = title;
      const path = safeRelativePath(reference?.relative_path);
      if (path) { const citation = doc.createElement('span'); citation.className = 'nc-inspector-meta'; citation.textContent = ` · ${path}`; item.append(citation); }
      const status = String(reference?.status || '').slice(0, 80);
      if (status) { const state = doc.createElement('span'); state.className = 'nc-inspector-meta'; state.textContent = ` · ${status}`; item.append(state); }
      fragment.append(item);
    }
    list.replaceChildren(fragment.childNodes.length ? fragment : make('li', 'La API no devolvió referencias reconocidas para este documento.', 'meta'));
  }

  function resetMarkdownReader(message = 'Selecciona un documento para consultar el lector completo.') {
    markdownGate.begin(); markdownMatchIndex = 0;
    byId('ncReadMarkdown').disabled = !state.selectedDocument;
    byId('ncMarkdownStatus').textContent = message;
    byId('ncMarkdownReader').hidden = true; byId('ncMarkdownSearch').hidden = true;
    byId('ncMarkdownQuery').value = ''; byId('ncMarkdownContent').replaceChildren(); byId('ncMarkdownReferences').replaceChildren();
    byId('ncMarkdownSearchStatus').textContent = '';
  }

  async function readMarkdown() {
    const documentId = Number(state.selectedDocument?.document_id ?? state.selected), gate = markdownGate.begin();
    if (!Number.isSafeInteger(documentId) || documentId <= 0 || !state.selectedDocument) return;
    const reader = byId('ncMarkdownReader'), button = byId('ncReadMarkdown');
    reader.hidden = false; button.disabled = true; byId('ncMarkdownStatus').textContent = 'Leyendo la vista Markdown autorizada…';
    byId('ncMarkdownSearch').hidden = true; byId('ncMarkdownContent').replaceChildren(); byId('ncMarkdownReferences').replaceChildren();
    try {
      const payload = await api('/api/doc/content', {document_id: documentId, max_bytes: MARKDOWN_MAX_CHARACTERS});
      if (!markdownGate.current(gate) || Number(state.selectedDocument?.document_id ?? state.selected) !== documentId) return;
      const content = validateMarkdownResponse(payload, documentId);
      const tree = parseSafeMarkdown(content, payload.references);
      byId('ncMarkdownContent').replaceChildren(renderMarkdownContent(tree)); renderMarkdownReferences(payload.references);
      byId('ncMarkdownSearch').hidden = false; byId('ncMarkdownQuery').value = ''; byId('ncMarkdownSearchStatus').textContent = 'Escribe un término para buscar en el documento actual.';
      byId('ncMarkdownStatus').textContent = payload.truncated ? `Vista parcial: ${Number(payload.bytes_returned).toLocaleString('es-MX')} bytes. El servidor indicó que el documento continúa.` : `Vista Markdown del documento ${documentId} cargada · ${Number(payload.bytes_returned).toLocaleString('es-MX')} bytes.`;
    } catch (error) {
      if (!markdownGate.current(gate) || Number(state.selectedDocument?.document_id ?? state.selected) !== documentId) return;
      const message = String(error.message || 'error de API');
      const httpStatus = /^HTTP (\d{3})$/.exec(message)?.[1];
      const status = ({
        400: 'La API rechazó la solicitud o la codificación del documento. La fuente original no se modificó.',
        403: 'La API local rechazó el origen o el formato de la solicitud. Abre el dashboard desde el mismo servidor local.',
        404: 'El documento no está disponible o ya no pertenece al ámbito autorizado. Sus metadatos y citas permanecen en el inspector.',
        409: 'La fuente cambió o dejó de estar disponible desde la indexación. No se reindexó automáticamente; actualiza el índice explícitamente antes de volver a leer.',
        413: 'La nota supera el tamaño configurado para lectura o el límite del lector de 65,536 bytes. El resto del inspector permanece disponible.',
        503: 'El índice local no está disponible. La API no lo creó ni lo actualizó.',
      })[httpStatus] || (message.includes('contrato seguro') || message.includes('referencia fuera del contrato') || message.includes('no cumple el límite')
        ? 'La respuesta local no cumple el contrato seguro del lector. No se mostró su contenido.'
        : 'No se pudo leer el Markdown. Los metadatos y fragmentos citados permanecen disponibles; puedes volver a intentarlo.');
      byId('ncMarkdownStatus').textContent = status; reader.hidden = true; byId('ncMarkdownContent').replaceChildren(); byId('ncMarkdownReferences').replaceChildren();
    } finally { if (markdownGate.current(gate) && Number(state.selectedDocument?.document_id ?? state.selected) === documentId) button.disabled = false; }
  }

  function updateAccessibleNodeSelection() {
    for (const button of byId('ncAccessibleNodes').querySelectorAll('[data-node-id]')) {
      button.setAttribute('aria-pressed', String(button.dataset.nodeId === state.selected));
    }
  }

  function renderAccessibleNodeList() {
    const target = byId('ncAccessibleNodes'), previous = byId('ncNodePagePrev'), next = byId('ncNodePageNext');
    const nodes = state.graph.nodes, pageCount = Math.ceil(nodes.length / NODE_DIRECTORY_PAGE_SIZE);
    state.nodeDirectoryPage = Math.max(0, Math.min(state.nodeDirectoryPage, Math.max(0, pageCount - 1)));
    const start = state.nodeDirectoryPage * NODE_DIRECTORY_PAGE_SIZE, end = Math.min(nodes.length, start + NODE_DIRECTORY_PAGE_SIZE);
    const entries = doc.createDocumentFragment();
    for (const node of nodes.slice(start, end)) {
      const item = make('li'), button = make('button', node.title, 'nc-node-directory-item');
      button.type = 'button'; button.dataset.nodeId = node.id;
      const metadata = [entityKindLabel(node.entity_kind), node.category, node.source_kind, node.project_name, graphCommunities().get(node.id)].filter(Boolean).join(' · ');
      if (metadata) {
        button.setAttribute('aria-label', `${node.title}. ${metadata}`);
        item.append(button, make('span', metadata, 'nc-node-directory-meta'));
      } else item.append(button);
      button.setAttribute('aria-pressed', String(node.id === state.selected));
      button.addEventListener('click', () => selectOrbitNode(node.id));
      entries.append(item);
    }
    target.replaceChildren(entries);
    byId('ncNodeDirectoryStatus').textContent = nodes.length
      ? `Nodos ${safeCount(start + 1)}–${safeCount(end)} de ${safeCount(nodes.length)} cargados${state.graph.truncated ? `; ${safeCount(state.graph.totalMatches)} coincidencias totales. Usa “Cargar más nodos” para ampliar la lista.` : '.'}`
      : 'No hay nodos para los filtros actuales.';
    previous.disabled = state.nodeDirectoryPage === 0;
    next.disabled = end >= nodes.length;
  }

  function bindAccessibleNodeDirectory() {
    byId('ncNodePagePrev').addEventListener('click', () => {
      state.nodeDirectoryPage = Math.max(0, state.nodeDirectoryPage - 1); renderAccessibleNodeList();
    });
    byId('ncNodePageNext').addEventListener('click', () => {
      const pageCount = Math.ceil(state.graph.nodes.length / NODE_DIRECTORY_PAGE_SIZE);
      state.nodeDirectoryPage = Math.min(pageCount - 1, state.nodeDirectoryPage + 1); renderAccessibleNodeList();
    });
  }

  function ensureGraphDerivatives() {
    if (derivedGraph === state.graph) return;
    derivedGraph = state.graph; adjacencyCache = null; componentCache = null; communityCache = null; orbitLayoutCache = {graph: null, key: '', value: null};
  }

  function graphAdjacency() {
    ensureGraphDerivatives();
    if (!adjacencyCache) adjacencyCache = explicitAdjacency(state.graph);
    return adjacencyCache;
  }

  function graphComponents() {
    ensureGraphDerivatives();
    if (!componentCache) componentCache = componentsFromAdjacency(graphAdjacency());
    return componentCache;
  }

  function graphCommunities() {
    ensureGraphDerivatives();
    if (!communityCache) communityCache = detectGraphCommunities(state.graph);
    return communityCache;
  }

  function prefersReducedMotion() {
    return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function syncReducedMotion(enabled) {
    const reduced = Boolean(enabled);
    state.reducedMotion = reduced;
    byId('ncReducedMotion').checked = reduced;
    byId('ncLowMotion').setAttribute('aria-pressed', String(reduced));
  }

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
    byId('ncReducedMotion').checked = prefersReducedMotion();
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
      syncReducedMotion(byId('ncReducedMotion').checked);
      root.style.setProperty('--nc-panel-alpha', `${byId('ncOpacity').value}%`);
      root.style.fontSize = `${byId('ncFontScale').value}%`;
      root.style.fontFamily = byId('ncTypography').value === 'mono' ? 'ui-monospace,Consolas,monospace' : 'system-ui,Segoe UI,sans-serif';
      const theme = localStorage.getItem('rabanito.ui.theme'); if (theme) setTheme(theme);
    } catch { syncReducedMotion(byId('ncReducedMotion').checked); /* malformed local preferences fall back to defaults */ }
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

  function typedGraphRequest(limit = Number(byId('ncDensity').value), cursor = null) {
    const body = {
      kind: byId('ncKindFilter').value || 'all',
      limit: Math.min(200, Math.max(0, Math.floor(Number(limit) || 0))),
      suggestions: byId('ncSuggestions').checked,
    };
    const query = byId('ncQuery').value.trim().slice(0, 200);
    const source = byId('ncSource').value || '';
    const category = byId('ncCategory').value || '';
    const projectId = Number(byId('ncProject').value);
    if (query) body.q = query;
    if (source) body.source = source;
    if (category) body.category = category;
    if (Number.isSafeInteger(projectId) && projectId > 0) body.project_id = projectId;
    if (typeof cursor === 'string' && cursor) body.cursor = cursor;
    return body;
  }

  function updateTypedExpansionControl() {
    const button = byId('ncExpandNeighbors');
    if (state.graphMode !== 'typed' || !state.selected || !state.graph.nodes.some(node => node.id === state.selected)) {
      button.disabled = true; return;
    }
    const hasCursor = state.typedNeighborCursors.has(state.selected);
    const alreadyExpanded = state.typedExpanded.has(state.selected) && !hasCursor;
    button.disabled = state.typedInFlight.size > 0 && state.typedInFlight.has(state.selected)
      || alreadyExpanded || state.typedExpanded.size >= TYPED_EXPANSION_CAP
      || state.graph.nodes.length >= TYPED_GRAPH_MAX_NODES;
    button.textContent = hasCursor ? 'Cargar más vecinos' : 'Expandir vecinos';
  }

  function commitTypedPayload(payload, {append = false, updatePagination = true} = {}) {
    const incoming = normalizeCommandGraph(payload);
    state.graph = mergeBoundedTypedGraph(append ? state.graph : null, payload);
    const continuation = typedPageContinuation(
      {hasMore: state.typedHasMore, cursor: state.typedCursor}, incoming,
      {update: updatePagination},
    );
    state.typedHasMore = continuation.hasMore;
    state.typedCursor = continuation.cursor;
    return incoming;
  }

  async function loadTypedGraph(limit = Number(byId('ncDensity').value), {append = false} = {}) {
    const generation = graphGate.begin();
    const pageSize = typedPageLimit(state.typedPageSize, limit, append);
    if (!append) {
      state.typedGeneration = (state.typedGeneration || 0) + 1;
      state.typedNeighborCursors.clear(); state.typedInFlight.clear(); state.typedExpanded.clear();
      state.typedCursor = null; state.typedHasMore = false; state.typedPageSize = pageSize;
    }
    const viewGeneration = state.typedGeneration || 0;
    setStatus(append ? 'Cargando la siguiente página del Knowledge Graph tipado…' : 'Consultando la proyección tipada local…');
    byId('ncLoadMore').disabled = true;
    try {
      const payload = await api('/api/knowledge-graph', typedGraphRequest(pageSize, append ? state.typedCursor : null));
      if (!graphGate.current(generation) || state.graphMode !== 'typed' || viewGeneration !== state.typedGeneration) return;
      if (payload.projection_available !== true) {
        state.graph = normalizeCommandGraph({...payload, schema_version: 1});
        state.typedHasMore = false; state.typedCursor = null; state.selected = null; state.selectedDocument = null;
        renderInspectorEmpty(); renderAccessibleNodeList(); renderHex(); renderTree(); drawOrbit();
        byId('ncGraphSync').hidden = false; byId('ncLoadMore').hidden = true;
        byId('ncGraphCount').textContent = 'La proyección tipada todavía no está disponible.';
        setStatus('El índice tipado requiere una actualización explícita. No se escribió ni se sincronizó nada al abrir esta vista.', 'pending');
        return;
      }
      const incoming = commitTypedPayload(payload, {append});
      byId('ncGraphSync').hidden = !Boolean(incoming.coverage?.requires_sync);
      byId('ncTypedGraphNote').hidden = false;
      byId('ncLoadMore').hidden = !state.typedHasMore;
      byId('ncLoadMore').textContent = 'Cargar más entidades tipadas';
      byId('ncGraphCount').textContent = `${safeCount(state.graph.nodes.length)} nodos visibles · ${safeCount(state.graph.edges.length)} relaciones expandidas · ${safeCount(incoming.totalMatches)} candidatos${state.typedHasMore ? ' · hay más páginas' : ''}`;
      if (!state.graph.nodes.some(node => node.id === state.selected)) { state.selected = null; state.selectedDocument = null; renderInspectorEmpty(); }
      state.componentFocus = null; state.groupFocus = null;
      state.nodeDirectoryPage = 0; renderAccessibleNodeList(); renderHex(); renderTree(); drawOrbit(); updateTypedExpansionControl();
      const coverageNote = incoming.coverage?.requires_sync ? ' · algunas entradas necesitan actualización explícita' : '';
      setStatus(state.graph.nodes.length
        ? `Knowledge Graph tipado: ${state.graph.nodes.length} nodos visibles. La expansión de vecinos es de un salto y tiene límites locales${coverageNote}.`
        : 'No se encontraron entidades tipadas para estos filtros.', state.graph.nodes.length ? '' : 'pending');
      byId('ncPendingNote').hidden = false;
    } catch (error) {
      if (graphGate.current(generation)) {
        if (!append) state.graph = normalizeCommandGraph({schema_version: 1});
        renderAccessibleNodeList(); drawOrbit(); renderHex(); renderTree();
        setStatus(`No se pudo leer el Knowledge Graph tipado: ${String(error.message || 'error de API').slice(0, 180)}. Revisa el contrato local y vuelve a intentarlo.`, 'error');
      }
    } finally { if (graphGate.current(generation)) byId('ncLoadMore').disabled = false; }
  }

  async function expandTypedNeighbors(id = state.selected) {
    const nodeId = String(id ?? '');
    if (state.graphMode !== 'typed' || !state.graph.nodes.some(node => node.id === nodeId)) return;
    const cursor = state.typedNeighborCursors.get(nodeId) || null;
    if (state.typedExpanded.has(nodeId) && !cursor) return;
    if (state.typedInFlight.has(nodeId) || state.typedExpanded.size >= TYPED_EXPANSION_CAP) return;
    if (state.graph.nodes.length >= TYPED_GRAPH_MAX_NODES) { setStatus('Se alcanzó el límite visual de nodos; reduce filtros antes de expandir más.', 'pending'); return; }
    const key = `${nodeId}\u0000${cursor || ''}`, generation = state.typedGeneration;
    state.typedInFlight.add(nodeId); updateTypedExpansionControl();
    setStatus(`Expandiendo un salto desde ${state.graph.nodes.find(node => node.id === nodeId)?.title || 'la entidad'}…`);
    try {
      const payload = await api('/api/knowledge-graph/neighbors', {...typedGraphRequest(200, cursor), id: nodeId});
      if (state.graphMode !== 'typed' || generation !== state.typedGeneration) return;
      if (payload.anchor_visible !== true) { state.typedExpanded.add(nodeId); state.typedNeighborCursors.delete(nodeId); setStatus('La entidad ya no está visible en el ámbito autorizado. Actualiza la página del grafo.'); return; }
      commitTypedPayload(payload, {append: true, updatePagination: false});
      state.typedExpanded.add(nodeId);
      if (payload.has_more && typeof payload.next_cursor === 'string') state.typedNeighborCursors.set(nodeId, payload.next_cursor);
      else state.typedNeighborCursors.delete(nodeId);
      byId('ncGraphCount').textContent = `${safeCount(state.graph.nodes.length)} nodos visibles · ${safeCount(state.graph.edges.length)} relaciones expandidas · límite ${TYPED_GRAPH_MAX_NODES} nodos`;
      state.nodeDirectoryPage = 0; renderAccessibleNodeList(); renderHex(); renderTree(); drawOrbit(); updateTypedExpansionControl();
      setStatus(`${safeCount(payload.edges?.length || 0)} relaciones cargadas para la entidad seleccionada · clasificación y cita conservadas.`);
    } catch (error) {
      if (generation === state.typedGeneration) setStatus(`No se pudieron cargar los vecinos: ${String(error.message || 'error de API').slice(0, 160)}. La proyección no se modificó.`, 'error');
    } finally {
      state.typedInFlight.delete(nodeId); updateTypedExpansionControl();
    }
  }

  function openTypedGraphSyncConfirmation() {
    if (state.graphMode !== 'typed' || byId('ncGraphSync').disabled) return;
    const dialog = byId('ncGraphSyncDialog');
    if (!dialog || typeof dialog.showModal !== 'function') {
      setStatus('Este navegador no permite abrir la confirmación accesible; no se actualizó la proyección.', 'error');
      return;
    }
    dialog.returnValue = '';
    dialog.showModal();
  }

  async function syncTypedGraph() {
    const dialog = byId('ncGraphSyncDialog');
    if (state.graphMode !== 'typed' || dialog?.returnValue !== 'sync') return;
    dialog.returnValue = '';
    const button = byId('ncGraphSync'); button.disabled = true;
    setStatus('Actualizando una tanda acotada de la proyección tipada…');
    try {
      const result = await api('/api/knowledge-graph/sync', {confirm_graph_sync: true, max_inputs: 1000, max_bytes: 32 * 1024 * 1024});
      const summary = `${result.status || 'resultado'} · ${safeCount(result.examined)} entradas revisadas${result.errors ? ` · ${safeCount(result.errors)} errores` : ''}`;
      setStatus(`Proyección tipada: ${summary}. Solo se procesó una tanda; no hay sincronización ilimitada.` , result.status === 'error' ? 'error' : 'pending');
      await loadTypedGraph();
    } catch (error) {
      setStatus(`No se pudo actualizar la proyección: ${String(error.message || 'error de API').slice(0, 160)}.`, 'error');
    } finally { button.disabled = false; }
  }

  async function loadGraph(limit = Number(byId('ncDensity').value)) {
    if (state.graphMode === 'typed') return loadTypedGraph(limit);
    byId('ncLoadMore').textContent = 'Cargar más nodos';
    const generation = graphGate.begin(); setStatus('Consultando relaciones confirmadas del índice local…');
    byId('ncLoadMore').disabled = true;
    try {
      const payload = await api('/api/graph', graphRequest(limit));
      if (!graphGate.current(generation)) return;
      if (payload.fixture === true) { byId('ncFixtureBanner').hidden = false; doc.body.dataset.fixture = 'true'; }
      state.graph = normalizeCommandGraph(payload); state.offset = limit; state.componentFocus = null; state.groupFocus = null;
      byId('ncGraphSync').hidden = true; byId('ncTypedGraphNote').hidden = true;
      byId('ncGraphCount').textContent = `${safeCount(payload.total_matches ?? state.graph.nodes.length)} entidades encontradas · ${safeCount(state.graph.edges.length)} relaciones cargadas${payload.truncated ? ' · vista limitada' : ''}`;
      byId('ncLoadMore').hidden = !payload.truncated;
      if (!state.graph.nodes.some(node => node.id === state.selected)) { state.selected = null; state.selectedDocument = null; renderInspectorEmpty(); }
      state.nodeDirectoryPage = 0; renderAccessibleNodeList(); renderHex(); renderTree(); drawOrbit();
      const communityCount = new Set(graphCommunities().values()).size;
      const communityLabel = communityCount === 1 ? '1 comunidad detectada' : `${safeCount(communityCount)} comunidades detectadas`;
      setStatus(state.graph.nodes.length
        ? `${state.graph.edges.filter(edge => edge.kind === 'explicit').length} enlaces explícitos · ${communityLabel} por densidad de enlaces; es una estimación topológica.`
        : 'El índice no devolvió nodos para estos filtros.', state.graph.nodes.length ? '' : 'pending');
      byId('ncPendingNote').hidden = false;
    } catch (error) {
      if (graphGate.current(generation)) {
        state.graph = normalizeCommandGraph({}); state.nodeDirectoryPage = 0; renderAccessibleNodeList(); drawOrbit(); renderHex(); renderTree();
        setStatus(`No se pudo leer el grafo local: ${String(error.message || 'error de API').slice(0, 180)}. Reintenta desde Actualizar en la vista 3D.`, 'error');
      }
    } finally { if (graphGate.current(generation)) byId('ncLoadMore').disabled = false; }
  }

  function graphNodesAtDepth() {
    const depth = Number(byId('ncDepth').value);
    const components = state.componentFocus ? graphComponents() : null;
    let baseNodes = components ? state.graph.nodes.filter(node => components.get(node.id) === state.componentFocus) : state.graph.nodes;
    if (state.groupFocus) {
      if (state.groupFocus.basis === 'community') baseNodes = baseNodes.filter(node => graphCommunities().get(node.id) === state.groupFocus.name);
      else {
        const field = state.groupFocus.basis === 'source' ? 'source_kind' : state.groupFocus.basis === 'project' ? 'project_name' : state.groupFocus.basis === 'kind' ? 'entity_kind' : 'category';
        baseNodes = baseNodes.filter(node => stableKey(node[field]) === state.groupFocus.name);
      }
    }
    const minimumDegree = Number(byId('ncMinDegree').value);
    baseNodes = baseNodes.filter(node => node.id === state.selected || node.degree >= minimumDegree);
    if (!depth || !state.selected || !baseNodes.some(node => node.id === state.selected)) return baseNodes;
    const adjacency = graphAdjacency(), visible = new Set([state.selected]), frontier = [state.selected];
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
      node.entity_kind ? `Tipo · ${node.entity_kind}` : '',
      node.category ? `Categoría · ${node.category}` : '',
      node.source_kind ? `Fuente · ${node.source_kind}` : '',
      node.project_name ? `Proyecto · ${node.project_name}` : '',
      `Comunidad detectada · ${graphCommunities().get(node.id) || 'Sin conectar'}`,
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
    const spacingPercent = Number(byId('ncOrbitSpacing').value) / 100;
    const orbitRadius = Math.max(40, Math.min(rect.width, rect.height) * 0.44 * spacingPercent);
    context.strokeStyle = '#59818a20'; context.lineWidth = 1;
    for (const fraction of [0.34, 0.68, 1]) { context.beginPath(); context.arc(0, 0, orbitRadius * fraction, 0, Math.PI * 2); context.stroke(); }
    context.fillStyle = '#7b9a9b'; context.font = '9px ui-monospace,Consolas,monospace'; context.textAlign = 'center';
    context.fillText('RABANITO · MEMORIA LOCAL', 0, -8);
    context.fillStyle = '#456269'; context.fillText(`${state.graph.nodes.length} NODOS INDEXADOS`, 0, 8);
    const spacing = byId('ncOrbitSpacing').value;
    const layoutKey = orbitLayoutKey({
      width: rect.width, height: rect.height, spacing, depth: byId('ncDepth').value,
      minimumDegree: byId('ncMinDegree').value, selectedId: state.selected,
      componentFocus: state.componentFocus, groupBasis: state.groupFocus?.basis, groupName: state.groupFocus?.name,
    });
    if (orbitLayoutCache.graph !== state.graph || orbitLayoutCache.key !== layoutKey) {
      const visibleNodes = graphNodesAtDepth();
      const positions = orbitCoordinates(visibleNodes, Math.max(1, rect.width - 24), Math.max(1, rect.height - 24), spacing);
      const local = new Map([...positions].map(([id, point]) => [id, {x: point.x - rect.width / 2 + 12, y: point.y - rect.height / 2 + 12}]));
      orbitLayoutCache = {graph: state.graph, key: layoutKey, value: {visibleNodes, visibleIds: new Set(visibleNodes.map(node => node.id)), local}};
    }
    const {visibleNodes, visibleIds, local} = orbitLayoutCache.value;
    const adjacency = graphAdjacency(), selectedNeighbors = state.selected ? (adjacency.get(state.selected) || new Set()) : new Set();
    const colorMode = byId('ncColor').value;
    const colorGroups = colorMode === 'component' ? graphComponents() : colorMode === 'community' ? graphCommunities() : null;
    for (const edge of state.graph.edges) {
      if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) continue;
      const a = local.get(edge.source), b = local.get(edge.target); if (!a || !b) continue;
      const related = edge.source === state.selected || edge.target === state.selected;
      context.beginPath(); context.moveTo(a.x, a.y); context.lineTo(b.x, b.y);
      context.setLineDash(edge.kind === 'suggested' ? [3, 4] : edge.kind === 'inferred' ? [2, 4] : edge.kind === 'reviewed_claim' ? [6, 3] : []);
      context.strokeStyle = edge.kind === 'suggested' ? '#f2a35f' : edge.kind === 'inferred' ? '#b39af6' : edge.kind === 'reviewed_claim' ? '#78a8ee' : related ? '#69ead0' : '#65a3aa';
      context.globalAlpha = Number(byId('ncLinkBrightness').value) / 100 * (edge.kind === 'suggested' ? 0.78 : related ? 1 : 0.46);
      context.lineWidth = Number(byId('ncLinkWidth').value) * (related ? 1.3 : 0.8); context.stroke(); context.globalAlpha = 1;
    }
    context.setLineDash([]); orbitPoints = new Map();
    const baseSize = Number(byId('ncNodeSize').value);
    for (const node of visibleNodes) {
      const point = local.get(node.id); if (!point) continue;
      const x = centerX + point.x * scale, y = centerY + point.y * scale;
      const selected = node.id === state.selected, hovered = node.id === orbitHover?.id, active = selected || hovered, linked = selectedNeighbors.has(node.id);
      const colorKey = colorMode === 'source' ? node.source_kind : colorMode === 'project' ? node.project_name : colorMode === 'kind' ? node.entity_kind : colorGroups ? colorGroups.get(node.id) : node.category;
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
    const target = byId('ncPanelHex'), basis = byId('ncColor').value;
    const groups = groupCommandNodes(state.graph.nodes, basis, state.graph, basis === 'component' ? graphComponents() : basis === 'community' ? graphCommunities() : null);
    target.replaceChildren();
    if (!groups.length) { target.append(make('p', 'No hay entidades para agrupar con los filtros actuales.', 'meta')); return; }
    const fragment = doc.createDocumentFragment();
    for (const group of groups) {
      const wrap = make('article', undefined, 'nc-hex-wrap'), card = make('div', undefined, 'nc-hex-card');
      const displayName = basis === 'kind' ? entityKindLabel(group.name) : group.name;
      const button = make('button', displayName, 'nc-hex-select'); button.type = 'button';
      const selected = basis === 'component'
        ? state.componentFocus === group.name && !state.groupFocus
        : state.groupFocus?.basis === basis && state.groupFocus.name === group.name;
      button.setAttribute('aria-pressed', String(Boolean(selected)));
      card.dataset.selected = String(Boolean(selected));
      const groupLabel = basis === 'community' ? 'comunidad detectada' : basis === 'component' ? 'componente conectado' : basis === 'source' ? 'fuente' : basis === 'project' ? 'proyecto' : basis === 'kind' ? 'tipo de entidad' : 'categoría';
      button.setAttribute('aria-label', `${displayName}: ${group.count} entidades, agrupadas por ${groupLabel}`);
      button.addEventListener('click', () => {
        if (basis === 'component') {
          state.componentFocus = state.componentFocus === group.name ? null : group.name;
          state.groupFocus = null;
          setStatus(`${state.componentFocus || 'Vista completa'} · componentes calculados solo desde enlaces explícitos; no equivalen a comunidades semánticas.`);
          drawOrbit(); setView('orbit'); return;
        }
        state.componentFocus = null;
        state.groupFocus = state.groupFocus?.basis === basis && state.groupFocus.name === group.name ? null : {basis, name: group.name};
        setStatus(basis === 'community'
          ? `${state.groupFocus ? `${displayName} seleccionada` : 'Vista completa'} · estimación topológica calculada solo desde enlaces explícitos; no es una comunidad semántica confirmada.`
          : `${state.groupFocus ? `${basis === 'kind' ? 'tipo de entidad' : basis}: ${displayName}` : 'Vista completa'} · entidades agrupadas desde metadatos del índice.`);
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
    const target = byId('ncPanelTree'), groups = groupCommandNodes(state.graph.nodes, state.graph.typed ? 'kind' : 'project');
    target.replaceChildren();
    if (!groups.length) { target.append(make('p', 'El árbol está vacío: el índice no contiene documentos para estos filtros.', 'meta')); return; }
    const rootList = make('ul');
    for (const group of groups) {
      const displayGroupName = state.graph.typed ? entityKindLabel(group.name) : group.name;
      const groupItem = make('li'), groupDetails = make('details'), summary = make('summary', `${displayGroupName} · ${group.count} ${state.graph.typed ? 'entidades' : 'documentos'}`), docs = make('ul');
      groupDetails.append(summary);
      for (const node of group.nodes) {
        const item = make('li'), button = make('button'); button.type = 'button';
        button.append(make('strong', node.title), make('span', `${entityKindLabel(node.entity_kind || 'document')} · ${node.category || 'categoría sin dato'} · ${node.source_kind || 'fuente local'}`));
        button.addEventListener('click', () => void inspect(node.id)); item.append(button); docs.append(item);
      }
      groupDetails.append(docs); groupItem.append(groupDetails); rootList.append(groupItem);
    }
    const includedEdges = state.graph.typed ? state.graph.edges : state.graph.edges.filter(edge => edge.kind === 'explicit');
    const relationList = make('details'), relationSummary = make('summary', `${state.graph.typed ? 'Relaciones clasificadas' : 'Relaciones explícitas'} · ${includedEdges.length}`), relations = make('ul');
    for (const edge of includedEdges.slice(0, 160)) {
      const source = state.graph.nodes.find(node => node.id === edge.source), targetNode = state.graph.nodes.find(node => node.id === edge.target);
      if (!source || !targetNode) continue;
      const item = make('li'), button = make('button'); button.type = 'button'; button.textContent = `${source.title} ↔ ${targetNode.title} · ${edge.relation_type || 'relación'}${state.graph.typed ? ` · ${edge.kind}` : ''}`;
      button.addEventListener('click', () => void inspect(source.id)); item.append(button); relations.append(item);
    }
    relationList.append(relationSummary, relations); const relationItem = make('li'); relationItem.append(relationList); rootList.append(relationItem);
    const note = make('p', state.graph.typed
      ? 'Árbol agrupado por tipo publicado. Las citas y validaciones se conservan; una relación inferida, una sugerencia y una afirmación revisada no se elevan a hecho confirmado.'
      : 'Jerarquía mostrada: agrupación por metadato de proyecto. No se presupone una arquitectura inexistente; las relaciones listadas provienen únicamente de enlaces del grafo.', 'meta');
    target.append(note, rootList);
  }

  function renderInspectorEmpty() {
    byId('ncInspectorType').textContent = 'Sin selección';
    byId('ncInspectorAnnouncement').textContent = 'No hay documento seleccionado.';
    byId('ncInspectorBody').replaceChildren(make('p', 'Selecciona un nodo, resultado de búsqueda o elemento de una comunidad. Se mostrarán metadatos locales y fragmentos citados.', 'nc-inspector-intro'));
    byId('ncFragments').textContent = 'Aún no hay documento seleccionado.';
    byId('ncNeighbors').replaceChildren(make('span', 'Selecciona una entidad para explorar vecinos.', 'meta'));
    byId('ncOpenOriginal').disabled = true; byId('ncGetContext').disabled = true;
    byId('ncSourceRef').textContent = 'No se expone la ruta absoluta de la fuente.';
    state.selectedDocument = null; resetMarkdownReader();
    updateTypedExpansionControl();
  }

  function dispatchSelection(id, node = null) {
    doc.dispatchEvent(new CustomEvent('rabanito-command-selection', {detail: {id: String(id), node}}));
  }

  async function inspectTypedEntity(node) {
    const generation = inspectGate.begin();
    state.selected = node.id; state.selectedDocument = null;
    updateAccessibleNodeSelection(); updateTypedExpansionControl();
    resetMarkdownReader('Esta entidad no es un documento autorizado para lectura Markdown.');
    byId('ncInspectorType').textContent = entityKindLabel(node.entity_kind);
    byId('ncInspectorAnnouncement').textContent = `Entidad ${entityKindLabel(node.entity_kind)}: ${node.title}.`;
    const body = byId('ncInspectorBody'), fields = [
      ['Tipo', entityKindLabel(node.entity_kind)], ['Procedencia', node.source_kind], ['Categoría', node.category],
      ['Proyecto', node.project_name], ['Actualizado', node.updated],
    ];
    const dataFields = ['validation', 'record_status', 'status', 'scope', 'version', 'ecosystem', 'assessment', 'exploitation', 'priority', 'cvss', 'epss', 'framework', 'release', 'stix_type', 'revoked', 'deprecated'];
    for (const key of dataFields) {
      const value = node.data?.[key];
      if (['string', 'number', 'boolean'].includes(typeof value) && String(value).length <= 250) fields.push([key.replaceAll('_', ' '), String(value)]);
    }
    const metadata = fields.filter(([, value]) => value !== undefined && value !== null && String(value) !== '');
    body.replaceChildren(make('h3', node.title || 'Entidad sin título'));
    for (const [label, value] of metadata) body.append(make('p', `${label} · ${String(value).slice(0, 250)}`, 'nc-inspector-meta'));
    const description = node.data?.description ?? node.data?.summary;
    if (typeof description === 'string' && description.trim()) {
      body.append(make('h4', 'Descripción de la fuente'));
      body.append(make('pre', description.slice(0, 1200), 'nc-fragment'));
    }
    const citation = safeGraphCitation(node.citation);
    byId('ncSourceRef').textContent = citation.display ? `Cita · ${citation.display}` : 'La cita no contiene una referencia relativa segura.';
    byId('ncFragments').replaceChildren(make('span', 'Las propiedades proceden de la proyección tipada local; no equivalen a estado instalado ni a aplicabilidad confirmada.', 'meta'));
    byId('ncOpenOriginal').disabled = true; byId('ncGetContext').disabled = true;
    byId('ncNeighbors').replaceChildren(make('span', 'Consultando relaciones tipadas de un salto…', 'meta'));
    await expandTypedNeighbors(node.id);
    if (inspectGate.current(generation)) renderTypedRelations(node.id, generation);
  }

  function renderTypedRelations(nodeId, generation = inspectGate.begin()) {
    const target = byId('ncNeighbors'), content = doc.createDocumentFragment(), edges = state.graph.edges.filter(edge => edge.source === nodeId || edge.target === nodeId).slice(0, 100);
    for (const edge of edges) {
      const otherId = edge.source === nodeId ? edge.target : edge.source;
      const other = state.graph.nodes.find(item => item.id === otherId); if (!other) continue;
      const item = make('div', undefined, 'nc-typed-relation'), button = make('button', undefined); button.type = 'button';
      const validation = edge.validation && edge.validation !== edge.kind ? ` · ${String(edge.validation).slice(0, 80)}` : '';
      button.append(make('strong', other.title), make('span', `${edge.relation_type || 'relación'} · ${edge.kind}${validation}`, 'nc-inspector-meta'));
      button.addEventListener('click', () => dispatchSelection(other.id, other)); item.append(button);
      const citation = safeGraphCitation(edge.citation);
      if (citation.display) item.append(make('span', `Cita · ${citation.display}`, 'nc-inspector-meta'));
      content.append(item);
    }
    if (!edges.length) content.append(make('span', 'No hay vecinos visibles. Expande la entidad con el control del grafo o revisa el ámbito y filtros.', 'meta'));
    if (inspectGate.current(generation)) target.replaceChildren(content);
  }

  async function inspect(id) {
    const numericCandidate = Number(id);
    const selectedNode = state.graph.nodes.find(node => node.id === String(id) || Number.isSafeInteger(numericCandidate) && node.document_id === numericCandidate);
    const documentId = selectedNode?.document_id ?? Number(id);
    if (!Number.isSafeInteger(documentId) || documentId <= 0) {
      if (state.graph.typed && selectedNode) { await inspectTypedEntity(selectedNode); return; }
      return;
    }
    state.selected = selectedNode?.id ?? String(id);
    updateAccessibleNodeSelection();
    const generation = inspectGate.begin();
    state.selectedDocument = null; resetMarkdownReader('Selecciona un documento para consultar el lector completo.');
    updateTypedExpansionControl();
    byId('ncInspectorType').textContent = state.graph.typed ? `${entityKindLabel(selectedNode?.entity_kind || 'document')} · ${documentId}` : `Documento ${documentId}`;
    byId('ncInspectorAnnouncement').textContent = `Cargando metadatos del documento ${documentId}.`;
    byId('ncInspectorBody').replaceChildren(make('p', 'Leyendo metadatos del índice local…', 'nc-inspector-intro'));
    byId('ncFragments').replaceChildren(make('span', 'Recuperando fragmentos citados…', 'meta'));
    byId('ncNeighbors').replaceChildren(make('span', 'Cargando relaciones disponibles…', 'meta'));
    byId('ncOpenOriginal').disabled = false; byId('ncGetContext').disabled = false;
    try {
      const documentData = await api(`/api/doc/${documentId}`);
      if (!inspectGate.current(generation)) return;
      state.selectedDocument = documentData;
      byId('ncReadMarkdown').disabled = false;
      byId('ncInspectorAnnouncement').textContent = `Metadatos del documento ${documentId} cargados. Los fragmentos citados y relaciones están disponibles en el inspector.`;
      const body = byId('ncInspectorBody'), tags = Array.isArray(documentData.tags) ? documentData.tags : [];
      const title = make('h3', documentData.title || 'Documento sin título');
      const meta = make('p', [documentData.project_name, documentData.category, documentData.source_kind, documentData.mtime_iso].filter(Boolean).join(' · ') || 'Metadatos parciales', 'nc-inspector-meta');
      body.replaceChildren(title, meta);
      const tagList = make('div');
      for (const tag of tags.slice(0, 24)) tagList.append(make('span', `#${String(tag).replace(/^#/, '')}`, 'badge'));
      if (tags.length) body.append(tagList);
      const frontmatter = documentData.frontmatter && typeof documentData.frontmatter === 'object' ? Object.keys(documentData.frontmatter).slice(0, 12) : [];
      if (frontmatter.length) body.append(make('p', `Propiedades YAML: ${frontmatter.join(' · ')}`, 'nc-inspector-meta'));
      body.append(make('p', 'Los fragmentos siguientes proceden de recuperación citada. La lectura completa usa un endpoint ID-only del servidor cuando está disponible; abrir la fuente sigue pasando por la autorización local.', 'nc-inspector-intro'));
      byId('ncSourceRef').textContent = `${documentData.source_kind || 'fuente local'} · ${documentData.relative_path || 'referencia relativa no disponible'}${documentData.mtime_iso ? ` · actualizado ${documentData.mtime_iso}` : ''}`;
      await loadFragments(documentData, generation);
      await renderNeighbors(documentData, generation);
    } catch (error) {
      if (inspectGate.current(generation)) {
        byId('ncInspectorBody').replaceChildren(make('p', `No se pudo cargar el documento: ${String(error.message || 'error de API').slice(0, 180)}`, 'error'));
        byId('ncFragments').textContent = 'No hay fragmentos disponibles.';
        byId('ncNeighbors').textContent = 'No hay relaciones disponibles.';
        byId('ncReadMarkdown').disabled = true;
        byId('ncInspectorAnnouncement').textContent = `No se pudieron cargar los metadatos del documento ${documentId}.`;
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
    if (state.graph.typed) {
      const target = byId('ncNeighbors');
      target.replaceChildren(make('span', 'Expandiendo vecinos autorizados…', 'meta'));
      await expandTypedNeighbors(state.selected);
      if (inspectGate.current(generation)) renderTypedRelations(state.selected, generation);
      return;
    }
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
    const target = legacy?.querySelector(map[name] || '#results');
    const disclosure = target?.closest('details');
    if (disclosure) disclosure.open = true;
    if (name === 'coding' || name === 'security') {
      byId('knowledgeMode').value = name === 'coding' ? 'coding' : 'security';
      byId('knowledgeMode').dispatchEvent(new Event('change', {bubbles: true}));
    }
    const moduleButtons = [...root.querySelectorAll('[data-module]')];
    for (const button of moduleButtons) {
      if (button.dataset.module === name) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    if (!target) return;
    target.scrollIntoView({behavior: state.reducedMotion ? 'auto' : 'smooth', block: 'start'});
    const panel = target.closest('details,section') || target;
    const focusTarget = panel.matches('details') ? panel.querySelector(':scope > summary') : panel.querySelector('h2,h3') || target;
    if (focusTarget) {
      if (!focusTarget.hasAttribute('tabindex')) focusTarget.setAttribute('tabindex', '-1');
      focusTarget.classList.add('module-focus-target');
      focusTarget.focus?.({preventScroll: true});
    }
  }

  function selectOrbitNode(id) {
    const node = state.graph.nodes.find(item => item.id === String(id)); if (!node) return;
    orbitHover = null; state.selected = node.id; updateAccessibleNodeSelection(); updateTypedExpansionControl(); drawOrbit(); setStatus(`Seleccionado: ${node.title}. Pulsa Enter para abrir la ficha.`); dispatchSelection(node.id, node);
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
      if (event.key === 'Escape') { state.selected = null; state.selectedDocument = null; inspectGate.begin(); renderInspectorEmpty(); updateAccessibleNodeSelection(); drawOrbit(); return; }
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
    byId('ncGraphMode').addEventListener('change', event => {
      state.graphMode = event.target.value === 'typed' ? 'typed' : 'documents';
      byId('ncKindFilter').disabled = state.graphMode !== 'typed';
      byId('ncTypedGraphNote').hidden = state.graphMode !== 'typed';
      byId('ncGraphSync').hidden = true;
      state.selected = null; state.selectedDocument = null; inspectGate.begin(); renderInspectorEmpty();
      state.panX = 0; state.panY = 0; state.componentFocus = null; state.groupFocus = null;
      void loadGraph();
    });
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
    for (const id of ['ncProject', 'ncSource', 'ncCategory', 'ncKindFilter']) byId(id).addEventListener('change', () => { void loadGraph(); if (byId('ncQuery').value.trim()) void search(); });
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
    byId('ncCenter').addEventListener('click', () => { state.panX = 0; state.panY = 0; state.zoom = 1; state.componentFocus = null; state.groupFocus = null; byId('ncZoomPref').value = '100'; renderHex(); drawOrbit(); savePreferences(); });
    byId('ncLoadMore').addEventListener('click', () => {
      if (state.graphMode === 'typed') { if (state.typedHasMore) void loadTypedGraph(state.typedPageSize, {append: true}); return; }
      const next = Math.min(1000, state.offset + 120); if (next > state.offset) void loadGraph(next);
    });
    byId('ncExpandNeighbors').addEventListener('click', () => void expandTypedNeighbors());
    const syncDialog = byId('ncGraphSyncDialog');
    syncDialog.addEventListener('close', () => { if (syncDialog.returnValue === 'sync') void syncTypedGraph(); });
    byId('ncGraphSync').addEventListener('click', openTypedGraphSyncConfirmation);
    byId('ncShowLabels').addEventListener('change', event => { state.labels = event.target.checked; drawOrbit(); savePreferences(); });
    byId('ncReducedMotion').addEventListener('change', event => { syncReducedMotion(event.target.checked); savePreferences(); });
    byId('ncLowMotion').addEventListener('click', () => { const toggle = byId('ncReducedMotion'); syncReducedMotion(!toggle.checked); savePreferences(); });
    byId('ncZoomPref').addEventListener('input', event => { state.zoom = Number(event.target.value) / 100; drawOrbit(); savePreferences(); });
    byId('ncResetPrefs').addEventListener('click', () => {
      try { localStorage.removeItem('rabanito.ui.theme'); localStorage.removeItem('rabanito.ui.preferences'); } catch { /* continue with defaults */ }
      root.style.removeProperty('--left-width'); root.style.removeProperty('--right-width');
      byId('ncDensity').value = '180'; byId('ncNodeSize').value = '6'; byId('ncMinDegree').value = '0'; byId('ncZoomPref').value = '100'; byId('ncOpacity').value = '92'; byId('ncLinkBrightness').value = '62'; byId('ncLinkWidth').value = '1'; byId('ncOrbitSpacing').value = '100'; byId('ncRenderQuality').value = '150'; byId('ncFontScale').value = '100'; byId('ncTypography').value = 'system'; byId('ncShowLabels').checked = true; syncReducedMotion(prefersReducedMotion());
      root.style.setProperty('--nc-panel-alpha', '92%'); root.style.fontSize = '100%'; root.style.fontFamily = 'system-ui,Segoe UI,sans-serif';
      state.zoom = 1; state.labels = true; setTheme('raven-neon'); drawOrbit();
    });
    byId('ncOpenOriginal').addEventListener('click', async () => {
      if (!state.selectedDocument) return;
      byId('ncOpenOriginal').disabled = true;
      try { await openAuthorizedSource(state.selectedDocument.document_id ?? state.selected, api, setStatus); }
      finally { byId('ncOpenOriginal').disabled = false; }
    });
    byId('ncGetContext').addEventListener('click', () => void retrieveContext());
    byId('ncReadMarkdown').addEventListener('click', () => void readMarkdown());
    byId('ncMarkdownSearch').addEventListener('submit', event => { event.preventDefault(); searchMarkdown(); });
    byId('ncMarkdownQuery').addEventListener('input', searchMarkdown);
    byId('ncMarkdownPrev').addEventListener('click', () => focusMarkdownMatch(markdownMatchIndex - 1));
    byId('ncMarkdownNext').addEventListener('click', () => focusMarkdownMatch(markdownMatchIndex + 1));
    for (const button of root.querySelectorAll('[data-module]')) button.addEventListener('click', () => openModule(button.dataset.module));
    doc.addEventListener('rabanito-command-selection', event => { const id = event.detail?.id ?? event.detail?.node?.document_id; if (id != null) void inspect(id); });
    bindOrbitCanvas(); bindAccessibleNodeDirectory(); bindPanelResizers();
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
