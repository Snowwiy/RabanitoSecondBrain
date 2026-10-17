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
const ui = await import(`data:text/javascript;base64,${Buffer.from(stubs + source + '\nexport {normalizeCommandGraph, orbitCoordinates, hitTestOrbitNode, safeRelativePath, openAuthorizedSource, groupCommandNodes, explicitAdjacency};').toString('base64')}`);
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
  assert.match(source, /if \(orbitLayoutCache\.graph !== state\.graph \|\| orbitLayoutCache\.key !== layoutKey\)/);
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
