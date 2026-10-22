import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('../web/knowledge.js', import.meta.url), 'utf8')
  .replace(/^import .* from '\.\/cyber\.js';\s*/m, '')
  .replace(/^export /gm, '');
const stubs = `
const createRequestGate = () => { let n=0; return {begin:()=>++n,current:id=>id===n}; };
const requestJson = async () => ({});
const safeReference = value => { try { const url = new URL(value); return ['https:','http:'].includes(url.protocol) && !url.username && !url.password ? url.href : null; } catch { return null; } };
`;
const ui = await import(`data:text/javascript;base64,${Buffer.from(stubs + source + '\nexport {normalizeCommandGraph, orbitCoordinates, orbitLayoutKey, hitTestOrbitNode, safeRelativePath, safeGraphCitation, mergeBoundedTypedGraph, typedPageContinuation, typedPageLimit, typedPageStopReason, canRequestTypedPage, TYPED_GRAPH_MAX_NODES, TYPED_GRAPH_MAX_EDGES, openAuthorizedSource, groupCommandNodes, explicitAdjacency, detectGraphCommunities, parseSafeMarkdown, validateMarkdownResponse, entityKindLabel};').toString('base64')}`);
const html = fs.readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');

test('normalization keeps only real graph endpoints and preserves suggested relation state', () => {
  const graph = ui.normalizeCommandGraph({nodes: [
    {document_id: 1, title: 'Nota A'}, {document_id: 2, title: 'Nota B'}, {document_id: 3, title: '<script>dato</script>'},
  ], edges: [
    {source: 1, target: 2, kind: 'explicit', relation_type: 'wikilink'},
    {source: 2, target: 3, kind: 'suggested'}, {source: 1, target: 99, kind: 'explicit'}, {source: 1, target: 1, kind: 'explicit'},
  ], total_matches: 3, truncated: false});
  assert.deepEqual(graph.edges.map(edge => edge.kind), ['explicit', 'suggested']);
  assert.equal(graph.edges[0].relation_type, 'wikilink');
  assert.equal(graph.nodes[2].title, '<script>dato</script>');
  assert.equal(graph.totalMatches, 3);
});

test('typed Knowledge Graph retains stable entity IDs, provenance, citation safety and relation classes', () => {
  const graph = ui.normalizeCommandGraph({schema_version: 1, projection_available: true, total_candidates: 4, nodes: [
    {id: 'document:7', kind: 'document', title: 'Nota ñ', source: 'obsidian', citation: 'obsidian:Research/Nota.md', data: {document_id: 7}},
    {id: 'vulnerability:CVE-2026-1234', kind: 'vulnerability', title: 'CVE-2026-1234', source: 'nvd', citation: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234', data: {}},
    {id: 'dependency:8:abc', kind: 'dependency', title: 'parser@1.0', source: 'inventory', citation: 'projects:8:inventory.json', data: {}},
    {id: 'security:control-1', kind: 'control', title: 'Control', source: 'security', citation: 'https://example.com/control', data: {}},
  ], edges: [
    {source: 'document:7', target: 'vulnerability:CVE-2026-1234', kind: 'explicit', validation: 'source_documented', relation_type: 'cites'},
    {source: 'document:7', target: 'dependency:8:abc', kind: 'suggested', validation: 'suggested'},
    {source: 'dependency:8:abc', target: 'security:control-1', kind: 'inferred', validation: 'inferred_from_indexed_metadata'},
  ], has_more: true, next_cursor: 'opaque-cursor'});
  assert.equal(graph.typed, true);
  assert.equal(graph.totalMatches, 4);
  assert.equal(graph.nodes[0].id, 'document:7');
  assert.equal(graph.nodes[0].document_id, 7);
  assert.equal(graph.nodes[0].relative_path, 'Research/Nota.md');
  assert.deepEqual(graph.edges.map(edge => edge.kind), ['explicit', 'suggested', 'inferred']);
  assert.deepEqual([...ui.explicitAdjacency(graph).get('document:7')], ['vulnerability:CVE-2026-1234']);
  assert.equal(graph.nextCursor, 'opaque-cursor');
  assert.equal(graph.truncated, true);
});

test('typed graph citation accepts only relative local references or credential-free HTTPS citations', () => {
  assert.equal(ui.safeGraphCitation('projects:8:src/README.md').relativePath, 'src/README.md');
  assert.equal(ui.safeGraphCitation('obsidian:../private.md').display, '');
  assert.equal(ui.safeGraphCitation('internal:C:\\Users\\private\\note.md').display, '');
  assert.equal(ui.safeGraphCitation('https://user:secret@example.com/private').display, '');
  assert.equal(ui.safeGraphCitation('https://example.com/ref').display, 'https://example.com/ref');
});

test('typed graph filters include backend kinds and the UI localizes their names', () => {
  for (const kind of ['weakness', 'product_condition', 'review', 'security_advisory', 'attack_technique', 'attack_asset', 'attack_collection']) {
    assert.match(html, new RegExp(`option value="${kind}"`));
  }
  assert.equal(ui.entityKindLabel('attack_technique'), 'Técnica ATT&CK');
  assert.equal(ui.entityKindLabel('product_condition'), 'Condición de producto');
  assert.equal(ui.entityKindLabel('future_kind'), 'future kind');
});

test('typed graph client merge caps large server responses and keeps edges inside visible nodes', () => {
  const nodes = Array.from({length: 10_000}, (_, index) => ({id: `dependency:${index}`, kind: 'dependency', title: `Package ${index}`, source: 'inventory'}));
  const edges = Array.from({length: 30_000}, (_, index) => ({source: `dependency:${index % 10_000}`, target: `dependency:${(index + 1) % 10_000}`, kind: index % 5 ? 'inferred' : 'explicit', relation_type: 'linked'}));
  const started = performance.now();
  const graph = ui.mergeBoundedTypedGraph(null, {schema_version: 1, projection_available: true, nodes, edges});
  const positions = ui.orbitCoordinates(graph.nodes, 1920, 1080);
  const elapsed = performance.now() - started;
  const ids = new Set(graph.nodes.map(node => node.id));
  assert.equal(graph.nodes.length, ui.TYPED_GRAPH_MAX_NODES);
  assert.ok(graph.edges.length <= ui.TYPED_GRAPH_MAX_EDGES);
  assert.ok(graph.edges.every(edge => ids.has(edge.source) && ids.has(edge.target)));
  assert.equal(positions.size, graph.nodes.length);
  assert.ok([...positions.values()].every(point => Number.isFinite(point.x) && Number.isFinite(point.y)));
  assert.ok(elapsed < 5000, `10,000-node input should be bounded promptly (observed ${elapsed.toFixed(1)} ms)`);
});

test('neighbor expansion preserves the typed graph page cursor until the next page is loaded', () => {
  const page = {hasMore: true, cursor: 'page-2'};
  const neighborResponse = {truncated: false, nextCursor: null};
  assert.deepEqual(ui.typedPageContinuation(page, neighborResponse, {update: false}), page);
  assert.deepEqual(ui.typedPageContinuation(page, {truncated: true, nextCursor: 'page-3'}), {hasMore: true, cursor: 'page-3'});
  assert.equal(ui.typedPageLimit(180, 200, true), 180);
  assert.equal(ui.typedPageLimit(180, 160, false), 160);
  assert.match(source, /commitTypedPayload\(payload, \{append: true, updatePagination: false\}\)/);
  assert.match(source, /typedGraphRequest\(pageSize, append \? state\.typedCursor : null\)/);
});

test('typed graph stops page requests at visual caps, missing cursors and repeated cursors', () => {
  assert.equal(ui.canRequestTypedPage({append: false}), true);
  assert.equal(ui.canRequestTypedPage({append: true, loadedNodes: 999, hasMore: true, cursor: 'page-2'}), true);
  assert.equal(ui.canRequestTypedPage({append: true, loadedNodes: 1000, hasMore: true, cursor: 'page-2'}), false);
  assert.equal(ui.canRequestTypedPage({append: true, loadedNodes: 2, hasMore: true, cursor: null}), false);
  assert.equal(ui.canRequestTypedPage({append: true, loadedNodes: 2, hasMore: true, cursor: 'page-2', seenCursors: ['page-2']}), false);
  assert.match(source, /canRequestTypedPage\(\{append, loadedNodes: state\.graph\.nodes\.length/);
  assert.match(source, /byId\('ncLoadMore'\)\.hidden = !state\.typedHasMore/);
});

test('typed graph page progress handles exact and exceeded node/relation fixtures without raising caps', () => {
  const pageNodes = (start, count) => Array.from({length: count}, (_, offset) => ({id: `dependency:${start + offset}`, kind: 'dependency', title: `P${start + offset}`}));
  const pageEdges = (nodes, count) => Array.from({length: count}, (_, index) => ({source: nodes[index % nodes.length].id, target: nodes[(index + 1) % nodes.length].id, kind: 'explicit', relation_type: `r${index}`}));
  const exactNodes = ui.mergeBoundedTypedGraph(null, {schema_version: 1, total_candidates: 1000, nodes: pageNodes(0, 1000), edges: []});
  assert.equal(exactNodes.nodes.length, 1000);
  assert.equal(ui.typedPageStopReason({loadedNodes: 1000, addedNodes: 1000, hasMore: true, nextCursor: 'page-2'}), 'node-cap');
  const overNodes = ui.mergeBoundedTypedGraph(exactNodes, {schema_version: 1, total_candidates: 1200, nodes: pageNodes(1000, 200), edges: []});
  assert.equal(overNodes.nodes.length, 1000);
  assert.equal(overNodes.totalMatches, 1200);
  const edgeBaseNodes = pageNodes(0, 1000);
  const exactEdges = ui.mergeBoundedTypedGraph(null, {schema_version: 1, nodes: edgeBaseNodes, edges: pageEdges(edgeBaseNodes, 4000)});
  assert.equal(exactEdges.edges.length, 4000);
  const overEdges = ui.mergeBoundedTypedGraph(exactEdges, {schema_version: 1, nodes: [], edges: [{source: edgeBaseNodes[0].id, target: edgeBaseNodes[2].id, kind: 'explicit', relation_type: 'overflow'}]});
  assert.equal(overEdges.edges.length, 4000);
  assert.equal(ui.typedPageStopReason({loadedNodes: 1000, loadedEdges: 4000, addedNodes: 0, addedEdges: 0, hasMore: true, nextCursor: 'page-2'}), 'node-cap');
  assert.equal(ui.typedPageStopReason({loadedNodes: 10, loadedEdges: 4000, addedNodes: 0, addedEdges: 0, hasMore: true, nextCursor: 'page-2'}), 'edge-cap');
  assert.equal(ui.typedPageStopReason({loadedNodes: 0, loadedEdges: 0, hasMore: true, nextCursor: 'page-2'}), 'no-progress', 'empty pages terminate instead of cycling');
  assert.equal(ui.typedPageStopReason({loadedNodes: 1, loadedEdges: 0, addedNodes: 0, addedEdges: 0, hasMore: true, nextCursor: 'page-2'}), 'no-progress', 'duplicate-only pages terminate');
  assert.equal(ui.typedPageStopReason({loadedNodes: 2, loadedEdges: 1, addedNodes: 1, addedEdges: 1, hasMore: true, nextCursor: 'page-3', requestedCursor: 'page-2'}), null, 'a page that adds a cross-page relation is progress');
  assert.equal(ui.typedPageStopReason({loadedNodes: 2, loadedEdges: 1, addedNodes: 1, addedEdges: 0, hasMore: true, nextCursor: 'page-2', requestedCursor: 'page-2'}), 'repeated-cursor');
  assert.equal(ui.typedPageStopReason({loadedNodes: 2, loadedEdges: 1, addedNodes: 1, addedEdges: 0, hasMore: true, nextCursor: null}), 'missing-cursor');
  assert.equal(ui.TYPED_GRAPH_MAX_NODES, 1000);
  assert.equal(ui.TYPED_GRAPH_MAX_EDGES, 4000);
  const firstPage = ui.mergeBoundedTypedGraph(null, {schema_version: 1, total_candidates: 2, nodes: [{id: 'document:a', kind: 'document'}], edges: [], has_more: true, next_cursor: 'page-2'});
  const secondPage = ui.mergeBoundedTypedGraph(firstPage, {schema_version: 1, total_candidates: 2, nodes: [{id: 'document:b', kind: 'document'}], edges: [{source: 'document:a', target: 'document:b', kind: 'explicit', relation_type: 'cross-page'}]});
  assert.equal(secondPage.edges.length, 1, 'a relation to a previously loaded node is retained on the next page');
  assert.equal(secondPage.edges[0].relation_type, 'cross-page');
  const duplicatePage = ui.mergeBoundedTypedGraph(firstPage, {schema_version: 1, nodes: [{id: 'document:a', kind: 'document'}], edges: []});
  assert.equal(duplicatePage.nodes.length, firstPage.nodes.length, 'duplicate nodes do not inflate the loaded entity count');
  assert.equal(ui.typedPageStopReason({loadedNodes: duplicatePage.nodes.length, loadedEdges: duplicatePage.edges.length,
    addedNodes: duplicatePage.nodes.length - firstPage.nodes.length, addedEdges: 0, hasMore: true, nextCursor: 'page-3'}), 'no-progress');
});

test('late context success and failure cannot overwrite a newer Inspector selection', async () => {
  const start = source.indexOf('  async function retrieveContext() {');
  const end = source.indexOf('\n  function setView(', start);
  assert.notEqual(start, -1); assert.notEqual(end, -1);
  const fnSource = source.slice(start, end).replace(/^  /gm, '');
  const elements = new Map([
    ['ncQuery', {value: ''}], ['ncGetContext', {disabled: false}],
    ['ncFragments', {children: ['B existing fragments'], replaceChildren(...children) { this.children = children; }}],
  ]);
  let generation = 0, selectedId = 'A', calls = 0;
  const contextGate = {begin: () => ++generation, current: id => generation === id};
  const state = {selected: 'A', selectedDocument: {document_id: 1, title: 'A'}};
  const deferred = [];
  const api = () => new Promise((resolve, reject) => deferred.push({resolve, reject}));
  const statuses = [];
  const retrieve = new Function('state', 'contextGate', 'byId', 'api', 'setStatus', 'make', 'doc', 'safeCount',
    `${fnSource}; return retrieveContext;`)(state, contextGate, id => elements.get(id), api,
    (message, tone) => statuses.push([message, tone]), (tag, text) => ({tag, text}),
    {createDocumentFragment: () => ({childNodes: [], append(...items) { this.childNodes.push(...items); }})}, String);
  const first = retrieve(); calls++;
  assert.equal(elements.get('ncGetContext').disabled, true);
  contextGate.begin(); selectedId = 'B'; state.selected = selectedId; state.selectedDocument = {document_id: 2, title: 'B'};
  elements.get('ncFragments').children = ['B fragments']; elements.get('ncGetContext').disabled = false;
  deferred[0].resolve({fragments: [{text: 'stale A fragment', citation: 'A:1'}], characters: 13});
  await first;
  assert.deepEqual(elements.get('ncFragments').children, ['B fragments']);
  assert.equal(elements.get('ncGetContext').disabled, false);
  assert.deepEqual(statuses, []);

  const second = retrieve(); calls++;
  contextGate.begin(); selectedId = 'C'; state.selected = selectedId; state.selectedDocument = {document_id: 3, title: 'C'};
  elements.get('ncFragments').children = ['C fragments']; elements.get('ncGetContext').disabled = false;
  deferred[1].reject(new Error('late A network failure'));
  await second;
  assert.deepEqual(elements.get('ncFragments').children, ['C fragments']);
  assert.equal(elements.get('ncGetContext').disabled, false);
  assert.deepEqual(statuses, []);

  const third = retrieve(); calls++;
  contextGate.begin(); state.selected = null; state.selectedDocument = null;
  elements.get('ncFragments').children = ['cleared selection'];
  deferred[2].reject(new Error('late after reset'));
  await third;
  assert.deepEqual(elements.get('ncFragments').children, ['cleared selection']);
  assert.equal(elements.get('ncGetContext').disabled, true);
  assert.deepEqual(statuses, []);
  assert.equal(calls, 3);
  assert.match(source, /function renderInspectorEmpty\(\)\s*\{\s*inspectGate\.begin\(\); contextGate\.begin\(\)/);
  assert.match(source, /async function inspectTypedEntity\(node\)\s*\{\s*const generation = inspectGate\.begin\(\); contextGate\.begin\(\)/);
  assert.match(source, /async function inspect\(id\)[\s\S]*?const generation = inspectGate\.begin\(\); contextGate\.begin\(\);/);
  assert.match(source, /async function loadFragments\(documentData, generation[\s\S]*?if \(!inspectGate\.current\(generation\)\) return/);
  assert.match(source, /async function renderNeighbors\(documentData, generation[\s\S]*?if \(inspectGate\.current\(generation\)\) target\.replaceChildren\(content\)/);
  assert.match(source, /async function inspect\(id\)[\s\S]*?byId\('ncOpenOriginal'\)\.disabled = true; byId\('ncGetContext'\)\.disabled = true;[\s\S]*?state\.selectedDocument = documentData;[\s\S]*?byId\('ncOpenOriginal'\)\.disabled = false;[\s\S]*?byId\('ncGetContext'\)\.disabled = false;/);
  assert.match(fnSource, /if \(!isCurrent\(\)\) return/);
  assert.match(fnSource, /catch \(error\) \{ if \(isCurrent\(\)\)/);
  assert.match(fnSource, /finally \{ if \(isCurrent\(\)\)/);
});

test('typed graph synchronization uses an accessible app-owned confirmation dialog', () => {
  assert.match(html, /<dialog id="ncGraphSyncDialog"[^>]*aria-labelledby="ncGraphSyncTitle"[^>]*aria-describedby="ncGraphSyncDescription"/);
  assert.match(html, /<form method="dialog" novalidate>[\s\S]*?<button type="submit" value="cancel" autofocus>Cancelar<\/button>[\s\S]*?<button type="submit" value="sync">Actualizar proyección local<\/button>/);
  assert.match(source, /dialog\.showModal\(\)/);
  assert.match(source, /syncDialog\.addEventListener\('close',[\s\S]*syncDialog\.returnValue === 'sync'/);
  assert.doesNotMatch(source, /(?:window\.)?confirm\s*\(/);
});

test('clearing the typed graph selection disables neighbor expansion', () => {
  assert.match(source, /function renderInspectorEmpty\(\)[\s\S]*?state\.selectedDocument = null; resetMarkdownReader\(\);\s*updateTypedExpansionControl\(\);/);
});

test('document graph restores its own pagination label after leaving typed mode', () => {
  assert.match(source, /async function loadGraph\([\s\S]*?if \(state\.graphMode === 'typed'\) return loadTypedGraph\(limit\);\s*byId\('ncLoadMore'\)\.textContent = 'Cargar más nodos';/);
});

test('safe Markdown parser covers common blocks while treating HTML and unsafe paths as text', () => {
  const markdown = '# Architecture\n\nA **bold** note with `inline code`, <img src=x onerror=alert(1)> and [external](https://example.com/source).\n\n- first item\n- second item\n\n| Field | Value |\n| --- | --- |\n| Status | Ready |\n\n```js\nconst answer = 42;\n```\n\n> quoted source\n\n[unsafe](javascript:alert(1)) [unresolved](../../private.md) [[notes/allowed.md|allowed note]]';
  const tree = ui.parseSafeMarkdown(markdown, [{target_document_id: 7102, title: 'Allowed note', target_raw: 'notes/allowed.md', relative_path: 'notes/allowed.md'}]);
  assert.deepEqual(tree.map(block => block.type), ['heading', 'paragraph', 'list', 'table', 'codeBlock', 'blockquote', 'paragraph']);
  const paragraphText = JSON.stringify(tree[1]);
  assert.match(paragraphText, /<img src=x onerror=alert\(1\)>/);
  assert.match(paragraphText, /https:\/\/example\.com\/source/);
  const links = JSON.stringify(tree.at(-1));
  assert.doesNotMatch(links, /javascript:/i);
  assert.doesNotMatch(links, /\.\.\/\.\.\/private\.md/);
  assert.match(links, /"type":"document","documentId":7102/);
  assert.match(JSON.stringify(tree[3]), /"type":"table"/);
  assert.equal(tree[4].text, 'const answer = 42;');
  assert.throws(() => ui.parseSafeMarkdown('x'.repeat(65_537)), /65,536/);
});

test('safe Markdown parser refuses unresolved and invalid document references', () => {
  const blocks = ui.parseSafeMarkdown('[[Private note]] [relative](note.md)', [{target_document_id: -1, title: 'Private note', target_raw: 'Private note'}]);
  const output = JSON.stringify(blocks);
  assert.doesNotMatch(output, /"type":"document"/);
  assert.doesNotMatch(output, /target_document_id/);
});

test('explicit-link communities separate dense clusters, ignore suggestions and stay deterministic', () => {
  const nodes = ['a', 'b', 'c', 'd', 'e', 'f', 'z'].map(id => ({id, title: id}));
  const edges = [
    ['a', 'b'], ['a', 'c'], ['b', 'c'], ['d', 'e'], ['d', 'f'], ['e', 'f'], ['c', 'd'],
  ].map(([source, target]) => ({source, target, kind: 'explicit'}));
  edges.push({source: 'a', target: 'z', kind: 'suggested'});
  const graph = {nodes, edges};
  const communities = ui.detectGraphCommunities(graph);
  assert.equal(communities.get('a'), communities.get('c'));
  assert.equal(communities.get('d'), communities.get('f'));
  assert.notEqual(communities.get('a'), communities.get('d'));
  assert.notEqual(communities.get('a'), communities.get('z'));
  assert.deepEqual(ui.groupCommandNodes(nodes, 'community', graph, communities).map(group => group.count), [3, 3, 1]);
  const numericOrderNodes = ['1', '10', '2'].map(id => ({id}));
  const numericOrderGraph = {nodes: numericOrderNodes, edges: []};
  const numericOrderGroups = new Map([['1', 'Comunidad 1'], ['10', 'Comunidad 10'], ['2', 'Comunidad 2']]);
  assert.deepEqual(ui.groupCommandNodes(numericOrderNodes, 'community', numericOrderGraph, numericOrderGroups).map(group => group.name), ['Comunidad 1', 'Comunidad 2', 'Comunidad 10']);
  assert.deepEqual([...ui.detectGraphCommunities({nodes: [...nodes].reverse(), edges: [...edges].reverse()})], [...communities]);
  const chainNodes = Array.from({length: 60}, (_, index) => ({id: String(index).padStart(3, '0')}));
  const chainEdges = chainNodes.slice(1).map((node, index) => ({source: chainNodes[index].id, target: node.id, kind: 'explicit'}));
  assert.ok(new Set(ui.detectGraphCommunities({nodes: chainNodes, edges: chainEdges}).values()).size < chainNodes.length / 2, 'multi-level aggregation must merge more than adjacent pairs on a sparse chain');
});

test('orbit coordinates are deterministic, bounded and include every node once', () => {
  const nodes = [{id: '2', title: 'B', degree: 4}, {id: '1', title: 'A', degree: 4}, {id: '3', title: 'C', degree: 0}];
  const first = ui.orbitCoordinates(nodes, 900, 600), second = ui.orbitCoordinates(nodes, 900, 600);
  assert.deepEqual([...first], [...second]);
  assert.equal(first.size, 3);
  for (const point of first.values()) { assert.ok(point.x >= 0 && point.x <= 900); assert.ok(point.y >= 0 && point.y <= 600); }
  assert.equal(ui.orbitCoordinates(nodes, 0, 600).size, 0);
});

test('orbit layout keys ignore a global selection but invalidate selection-dependent neighborhoods and filters', () => {
  const base = {width: 900, height: 600, spacing: 100, depth: '0', minimumDegree: '0', selectedId: 'node-a', componentFocus: null, groupBasis: undefined, groupName: undefined};
  assert.equal(ui.orbitLayoutKey(base), ui.orbitLayoutKey({...base, selectedId: 'node-b'}));
  assert.notEqual(ui.orbitLayoutKey({...base, depth: '1'}), ui.orbitLayoutKey({...base, depth: '1', selectedId: 'node-b'}));
  assert.notEqual(ui.orbitLayoutKey({...base, minimumDegree: '2'}), ui.orbitLayoutKey({...base, minimumDegree: '2', selectedId: 'node-b'}));
  assert.notEqual(ui.orbitLayoutKey(base), ui.orbitLayoutKey({...base, spacing: 110}));
  assert.notEqual(ui.orbitLayoutKey(base), ui.orbitLayoutKey({...base, groupBasis: 'category', groupName: 'research'}));
});
test('orbit hit testing chooses the nearest target and rejects invalid or distant coordinates', () => {
  const points = new Map([['far', {x: 0, y: 0, hitRadius: 22}], ['near', {x: 16, y: 5, hitRadius: 28}]]);
  assert.equal(ui.hitTestOrbitNode(points, 15, 5), 'near');
  assert.equal(ui.hitTestOrbitNode(points, 100, 100), null);
  assert.equal(ui.hitTestOrbitNode(points, Number.NaN, 5), null);
});

test('orbit preview displays only bounded relative paths', () => {
  assert.equal(ui.safeRelativePath('Research/Notas.md'), 'Research/Notas.md');
  assert.equal(ui.safeRelativePath('C:\\Users\\hexan\\secret.md'), '');
  assert.equal(ui.safeRelativePath('\\\\server\\private\\note.md'), '');
  assert.equal(ui.safeRelativePath('../outside.md'), '');
  assert.equal(ui.safeRelativePath('file:///private/note.md'), '');
});

test('authorized source opening only announces success when the API confirms opened true', async () => {
  const states = [];
  const request = async (path, body) => { assert.equal(path, '/api/open/42'); assert.deepEqual(body, {}); return {opened: false, fixture: true}; };
  assert.equal(await ui.openAuthorizedSource(42, request, (...state) => states.push(state)), false);
  assert.equal(states.at(-1)[1], 'error');
  assert.match(states.at(-1)[0], /No se pudo confirmar/);
  assert.equal(await ui.openAuthorizedSource(42, async () => ({opened: true}), (...state) => states.push(state)), true);
  assert.match(states.at(-1)[0], /El documento se abrió/);
  assert.equal(states.at(-1)[1], undefined);
  assert.equal(await ui.openAuthorizedSource(42, async () => { throw new Error('private detail'); }, (...state) => states.push(state)), false);
  assert.doesNotMatch(states.at(-1)[0], /private detail/);
});

test('hex groups use verified metadata; connected components use explicit links only', () => {
  const graph = ui.normalizeCommandGraph({nodes: [
    {document_id: 1, title: 'A', category: 'docs', project_name: 'P'},
    {document_id: 2, title: 'B', category: 'docs', project_name: 'P'},
    {document_id: 3, title: 'C', category: '', project_name: 'Q'},
  ], edges: [
    {source: 1, target: 2, kind: 'explicit'}, {source: 2, target: 3, kind: 'suggested'},
  ]});
  assert.deepEqual(ui.groupCommandNodes(graph.nodes, 'project').map(group => [group.name, group.count]), [['P', 2], ['Q', 1]]);
  assert.deepEqual(ui.groupCommandNodes(graph.nodes, 'category').map(group => group.name), ['docs', 'Sin clasificar']);
  assert.deepEqual(ui.groupCommandNodes(graph.nodes, 'component', graph).map(group => group.count), [2, 1]);
  const adjacency = ui.explicitAdjacency(graph);
  assert.deepEqual([...adjacency.get('1')], ['2']);
  assert.deepEqual([...adjacency.get('3')], []);
});

test('neural command center renders imported text through textContent, not HTML execution', () => {
  assert.match(source, /element\.textContent = String\(text\)/);
  assert.doesNotMatch(source, /\.innerHTML\s*=/);
  assert.match(source, /\/api\/context/);
  assert.match(source, /max_chars: 2400/);
});

test('Markdown reader is user-triggered, bounded, stale-safe and announces status without a live full body', () => {
  assert.match(html, /id="ncReadMarkdown" disabled>Leer Markdown/);
  assert.match(html, /id="ncMarkdownSearch" role="search" novalidate/);
  assert.match(source, /byId\('ncReadMarkdown'\)\.addEventListener\('click',\s*\(\) => void readMarkdown\(\)\)/);
  assert.match(source, /api\('\/api\/doc\/content', \{document_id: documentId, max_bytes: MARKDOWN_MAX_CHARACTERS\}\)/);
  assert.match(source, /markdownGate\.current\(gate\)/);
  assert.match(source, /actualBytes !== payload\.bytes_returned/);
  assert.match(source, /reader\.hidden = true; byId\('ncMarkdownContent'\)\.replaceChildren\(\)/);
  assert.match(html, /id="ncInspectorAnnouncement" class="nc-sr-only" role="status" aria-live="polite" aria-atomic="true"/);
  assert.doesNotMatch(html, /<aside class="nc-inspector"[^>]*aria-live=/);
  assert.doesNotMatch(source, /\.innerHTML\s*=/);
});

test('Markdown reader validates the exact backend response and refuses unsafe references', () => {
  const content = '# Nota real de prueba 🥕';
  const payload = {document_id: 17, content_markdown: content, bytes_returned: Buffer.byteLength(content), truncated: false,
    references: [{target_document_id: 18, title: 'Nota relacionada', target_raw: 'carpeta/nota.md', relative_path: 'carpeta/nota.md', status: 'resolved'}]};
  assert.equal(ui.validateMarkdownResponse(payload, 17), content);
  assert.throws(() => ui.validateMarkdownResponse({...payload, absolute_path: 'C:\\private\\note.md'}, 17), /contrato seguro/);
  assert.throws(() => ui.validateMarkdownResponse(payload, 19), /contrato seguro/);
  assert.throws(() => ui.validateMarkdownResponse({...payload, bytes_returned: 1}, 17), /límite/);
  assert.throws(() => ui.validateMarkdownResponse({...payload, references: [{...payload.references[0], relative_path: '../secreto.md'}]}, 17), /referencia/);
  assert.throws(() => ui.validateMarkdownResponse({...payload, references: [{...payload.references[0], target_raw: 'file:///C:/secreto.md'}]}, 17), /referencia/);
});

test('search result cards stack safely and wrap long citations in the narrow explorer', () => {
  assert.match(html, /\.nc-search-results \.nc-hit\s*\{[^}]*flex-direction:\s*column/s);
  assert.match(html, /\.nc-search-results \.nc-hit\s*>\s*\*\s*\{[^}]*overflow-wrap:\s*anywhere/s);
});

test('command-center search leaves empty-query feedback to its inline status owner', () => {
  assert.match(html, /<form[^>]*id="ncGlobalSearch"[^>]*novalidate/);
  assert.match(html, /id="ncSearchStatus"[^>]*role="status"[^>]*aria-live="polite"/);
});

test('legacy search and context announce concise outcomes through atomic live regions', () => {
  assert.match(html, /id="legacySearchStatus"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
  assert.match(html, /id="contextStatus"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
  assert.match(html, /Sin resultados locales para estos filtros/);
  assert.match(html, /No se encontraron fragmentos citados para estos filtros/);
  assert.match(html, /No se pudo recuperar el contexto citado/);
});

test('global search exposes an app-owned reset action and clears its results immediately', () => {
  assert.match(html, /<input[^>]*type="reset"[^>]*id="ncClearSearch"[^>]*aria-label="Limpiar búsqueda"[^>]*aria-controls="ncSearchResults"[^>]*hidden/);
  assert.match(source, /ncGlobalSearch'\)\.addEventListener\('reset'/);
  assert.match(source, /clearTimeout\(searchTimer\)/);
  assert.match(source, /void search\(''\); void loadGraph\(\)/);
  assert.match(source, /input\.focus\(\)/);
});

test('Neural Orbit exposes explicitly labeled topological communities for color, Hex grouping and accessible metadata', () => {
  assert.match(html, /option value="community">Comunidad detectada/);
  assert.match(html, /id="ncCommunityHelp"[^>]*>Las comunidades detectadas se estiman[\s\S]*?no son hechos semánticos/);
  assert.match(html, /Knowledge Graph ofrece entidades y relaciones tipadas en páginas[\s\S]*?no son hechos semánticos/);
  assert.match(source, /function graphCommunities\(\)[\s\S]*?communityCache = detectGraphCommunities\(state\.graph\)/);
  assert.match(source, /colorMode === 'community' \? graphCommunities\(\)/);
  assert.match(source, /basis === 'community' \? graphCommunities\(\)/);
  assert.match(source, /communityCount === 1 \? '1 comunidad detectada'/);
  assert.match(source, /groupFocus\.basis === 'community'[\s\S]*?graphCommunities\(\)\.get\(node\.id\)/);
  assert.match(source, /Comunidad detectada · \$\{graphCommunities\(\)\.get\(node\.id\)/);
});

test('Neural Orbit exposes a keyboard-described metadata tooltip and pointer hit testing', () => {
  assert.match(html, /id="ncOrbitCanvas"[^>]*aria-describedby="ncOrbitTooltip"/);
  assert.match(html, /id="ncOrbitTooltip" role="tooltip" hidden/);
  assert.match(source, /function renderOrbitTooltip\(visibleIds\)/);
  assert.match(source, /hitTestOrbitNode\(orbitPoints, x, y\)/);
  assert.match(source, /safeRelativePath\(node\.relative_path\)/);
  assert.match(source, /function selectOrbitNode\(id\) \{[\s\S]*?orbitHover = null; state\.selected = node\.id/);
});

test('Neural Orbit provides a bounded screen-reader node list with selection and pagination', () => {
  assert.match(html, /<details class="nc-node-directory"><summary>Navegar nodos en lista accesible<\/summary>/);
  assert.match(html, /id="ncNodeDirectoryStatus"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(html, /<ul id="ncAccessibleNodes"[^>]*aria-label="Nodos filtrados del grafo"/);
  assert.match(html, /id="ncNodePagePrev"[^>]*aria-controls="ncAccessibleNodes"/);
  assert.match(html, /id="ncNodePageNext"[^>]*aria-controls="ncAccessibleNodes"/);
  assert.match(source, /const NODE_DIRECTORY_PAGE_SIZE = 25/);
  assert.match(source, /function renderAccessibleNodeList\(\)[\s\S]*?nodes\.slice\(start, end\)[\s\S]*?aria-pressed/);
  assert.match(source, /button\.setAttribute\('aria-label', `\$\{node\.title\}\. \$\{metadata\}`\)/);
  assert.match(source, /function updateAccessibleNodeSelection\(\)[\s\S]*?button\.dataset\.nodeId === state\.selected/);
  assert.match(source, /function bindAccessibleNodeDirectory\(\)[\s\S]*?ncNodePagePrev[\s\S]*?ncNodePageNext/);
});

test('Orbit reuses derived graph data and deterministic layout until graph or view filters change', () => {
  assert.match(source, /function ensureGraphDerivatives\(\) \{[\s\S]*?derivedGraph === state\.graph[\s\S]*?adjacencyCache = null; componentCache = null/);
  assert.match(source, /if \(!adjacencyCache\) adjacencyCache = explicitAdjacency\(state\.graph\)/);
  assert.match(source, /if \(!componentCache\) componentCache = componentsFromAdjacency\(graphAdjacency\(\)\)/);
  assert.match(source, /derivedGraph = state\.graph; adjacencyCache = null; componentCache = null; communityCache = null/);
  assert.match(source, /if \(orbitLayoutCache\.graph !== state\.graph \|\| orbitLayoutCache\.key !== layoutKey\)/);
  assert.match(source, /const layoutKey = orbitLayoutKey\(\{/);
  assert.match(source, /const \{visibleNodes, visibleIds, local\} = orbitLayoutCache\.value/);
});

test('Hex group buttons expose the currently active metadata or explicit-component focus', () => {
  assert.match(source, /const selected = basis === 'component'[\s\S]*?state\.componentFocus === group\.name && !state\.groupFocus[\s\S]*?state\.groupFocus\?\.basis === basis && state\.groupFocus\.name === group\.name/);
  assert.match(source, /button\.setAttribute\('aria-pressed', String\(Boolean\(selected\)\)\)/);
  assert.match(source, /card\.dataset\.selected = String\(Boolean\(selected\)\)/);
  assert.match(html, /\.nc-hex-card:hover,\.nc-hex-card\[data-selected="true"\]/);
  assert.match(source, /byId\('ncCenter'\)\.addEventListener\('click',[\s\S]*?state\.groupFocus = null;[\s\S]*?renderHex\(\); drawOrbit\(\)/);
});

test('reduced-motion preference respects the OS default and keeps checkbox and toggle state synchronized', () => {
  assert.match(source, /function prefersReducedMotion\(\)[\s\S]*?matchMedia\('\(prefers-reduced-motion: reduce\)'\)/);
  assert.match(source, /function syncReducedMotion\(enabled\)[\s\S]*?byId\('ncReducedMotion'\)\.checked = reduced[\s\S]*?byId\('ncLowMotion'\)\.setAttribute\('aria-pressed', String\(reduced\)\)/);
  assert.match(source, /byId\('ncReducedMotion'\)\.addEventListener\('change', event => \{ syncReducedMotion\(event\.target\.checked\); savePreferences\(\); \}\)/);
  assert.equal((source.match(/byId\('ncReducedMotion'\)\.addEventListener\('change'/g) || []).length, 1);
});

test('visual preferences persist transparency and typography without storing knowledge content', () => {
  const start = source.indexOf('function savePreferences() {');
  const end = source.indexOf('\n  async function loadStats()', start);
  const preferenceFields = source.slice(start, end);
  assert.ok(start >= 0 && end > start, 'preference saver is present');
  assert.match(preferenceFields, /localStorage\.setItem\('rabanito\.ui\.preferences'/);
  assert.match(preferenceFields, /opacity: Number\(byId\('ncOpacity'\)\.value\)/);
  assert.match(preferenceFields, /fontScale: Number\(byId\('ncFontScale'\)\.value\), typography: byId\('ncTypography'\)\.value/);
  assert.doesNotMatch(preferenceFields, /\b(query|content|fragment|documentText|results)\b/i);
  assert.match(html, /<span class="nc-label">Transparencia de paneles<\/span><input id="ncOpacity" type="range" min="60" max="100"/);
  assert.match(source, /if \(id === 'ncOpacity'\) root\.style\.setProperty\('--nc-panel-alpha', `\$\{byId\(id\)\.value\}%`\)/);
  assert.match(source, /if \(id === 'ncFontScale'\) root\.style\.fontSize = `\$\{byId\(id\)\.value\}%`/);
});

test('module navigation opens disclosures, announces the active destination and focuses a usable heading', () => {
  assert.match(html, /id="ncToggleExplorer" aria-controls="ncExplorer"/);
  assert.match(html, /id="ncToggleInspector" aria-controls="ncInspector"/);
  assert.match(source, /const disclosure = target\?\.closest\('details'\);\s*if \(disclosure\) disclosure\.open = true/);
  assert.match(source, /button\.dataset\.module === name\) button\.setAttribute\('aria-current', 'page'\)/);
  assert.match(source, /const panel = target\.closest\('details,section'\) \|\| target;[\s\S]*?focusTarget\.setAttribute\('tabindex', '-1'\)[\s\S]*?focusTarget\.focus\?\.\(\{preventScroll: true\}\)/);
  assert.match(html, /\.legacy-workbench \.module-focus-target:focus/);
});

test('panel splitters initialize their accessible values from the responsive CSS widths', () => {
  assert.match(source, /const currentWidth = \(\) => parseInt\(getComputedStyle\(root\)\.getPropertyValue\(property\), 10\) \|\| defaultWidth/);
  assert.match(source, /separator\.setAttribute\('aria-valuenow', String\(currentWidth\(\)\)\)/);
});

test('graph summary distinguishes matching entities and loaded relations from filtered visibility', () => {
  assert.match(source, /entidades encontradas · \$\{safeCount\(state\.graph\.edges\.length\)\} relaciones cargadas/);
  assert.doesNotMatch(source, /state\.graph\.edges\.length\)\} relaciones visibles/);
});
