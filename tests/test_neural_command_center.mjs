import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('../web/knowledge.js', import.meta.url), 'utf8')
  .replace(/^import .* from '\.\/cyber\.js';\s*/m, '')
  .replace(/^export /gm, '');
const stubs = `
const createRequestGate = () => { let n=0; return {begin:()=>++n,current:id=>id===n}; };
const requestJson = async () => ({});
const safeReference = value => value;
`;
const ui = await import(`data:text/javascript;base64,${Buffer.from(stubs + source + '\nexport {normalizeCommandGraph, orbitCoordinates, groupCommandNodes, explicitAdjacency};').toString('base64')}`);
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

test('orbit coordinates are deterministic, bounded and include every node once', () => {
  const nodes = [{id: '2', title: 'B', degree: 4}, {id: '1', title: 'A', degree: 4}, {id: '3', title: 'C', degree: 0}];
  const first = ui.orbitCoordinates(nodes, 900, 600), second = ui.orbitCoordinates(nodes, 900, 600);
  assert.deepEqual([...first], [...second]);
  assert.equal(first.size, 3);
  for (const point of first.values()) { assert.ok(point.x >= 0 && point.x <= 900); assert.ok(point.y >= 0 && point.y <= 600); }
  assert.equal(ui.orbitCoordinates(nodes, 0, 600).size, 0);
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

test('search result cards stack safely and wrap long citations in the narrow explorer', () => {
  assert.match(html, /\.nc-search-results \.nc-hit\s*\{[^}]*flex-direction:\s*column/s);
  assert.match(html, /\.nc-search-results \.nc-hit\s*>\s*\*\s*\{[^}]*overflow-wrap:\s*anywhere/s);
});

test('command-center search leaves empty-query feedback to its inline status owner', () => {
  assert.match(html, /<form[^>]*id="ncGlobalSearch"[^>]*novalidate/);
  assert.match(html, /id="ncSearchStatus"[^>]*role="status"[^>]*aria-live="polite"/);
});
