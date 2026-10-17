// Local-only, explicitly synthetic visual QA server; never connects to the Second Brain API or SQLite.
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const web = path.join(root, 'web');
const port = Number(process.argv[2] || 8877);
const fixture = true;
const largeFixture = process.argv.includes('--large');
const project = {project_id: 7001, name: 'Fixture Core', status: 'active', relative_path: 'fixture/core', technologies: ['Python', 'SQLite']};
const fixtureSources = [
  {source_id: 7002, kind: 'obsidian', enabled: true, managed: false, name: 'Fixture Obsidian'},
  {source_id: 7003, kind: 'projects', enabled: true, managed: false, name: 'Fixture Core'},
  {source_id: 7004, kind: 'internal', enabled: true, managed: false, name: 'Fixture Rabanito'},
];
const seedDocuments = [
  {document_id: 7101, title: 'Fixture — Arquitectura de memoria local', source_kind: 'projects', category: 'technical', project_id: 7001, project_name: 'Fixture Core', relative_path: 'README.md', mtime_iso: '2026-10-15T10:00:00Z', degree: 2, tags: ['fixture', 'arquitectura'], frontmatter: {status: 'fixture'}, links: [], incoming_links: []},
  {document_id: 7102, title: 'Fixture — Indexación incremental de notas', source_kind: 'obsidian', category: 'research', project_id: null, project_name: '', relative_path: 'Research/Indexación.md', mtime_iso: '2026-10-14T09:00:00Z', degree: 2, tags: ['fixture', 'obsidian'], frontmatter: {source: 'fixture'}, links: [], incoming_links: []},
  {document_id: 7103, title: 'Fixture — Recuperación con citas verificables', source_kind: 'internal', category: 'coding-memory', project_id: 7001, project_name: 'Fixture Core', relative_path: 'knowledge/coding-memory/demo.md', mtime_iso: '2026-10-13T12:00:00Z', degree: 1, tags: ['fixture', 'retrieval'], frontmatter: {validation: 'fixture'}, links: [], incoming_links: []},
];
const documents = largeFixture ? Array.from({length: 1000}, (_, index) => {
  const seed = seedDocuments[index % seedDocuments.length];
  return {
    ...seed,
    document_id: 7101 + index,
    title: `Fixture ${String(index + 1).padStart(4, '0')} — ${seed.title.split(' — ')[1]}`,
    relative_path: `fixture/batch-${Math.floor(index / 100) + 1}/notes/${String(index + 1).padStart(4, '0')}.md`,
    degree: index === 0 || index === 999 ? 1 : 2,
  };
}) : seedDocuments;
const edges = largeFixture
  ? documents.slice(1).map((document, index) => ({source: documents[index].document_id, target: document.document_id, kind: 'explicit', status: 'resolved', relation_type: 'synthetic-chain'}))
      .concat([{source: documents[0].document_id, target: documents[2].document_id, kind: 'suggested', status: 'suggested', relation_type: 'synthetic-candidate'}])
  : [
      {source: 7101, target: 7102, kind: 'explicit', status: 'resolved', relation_type: 'wikilink'},
      {source: 7101, target: 7103, kind: 'explicit', status: 'resolved', relation_type: 'documented-reference'},
      {source: 7102, target: 7103, kind: 'suggested', status: 'suggested', relation_type: 'similarity-candidate'},
    ];
const graph = {
  nodes: documents.map(({document_id, title, source_kind, category, project_id, project_name, relative_path, mtime_iso, degree}) => ({document_id, title, source_kind, category, project_id, project_name, relative_path, mtime_iso, degree})),
  edges, node_limit: largeFixture ? 1000 : 180, total_matches: documents.length, truncated: false,
};
const stats = {fixture, documents_active: documents.length, relations_resolved: edges.filter(edge => edge.kind === 'explicit').length, relations_suggested: edges.filter(edge => edge.kind === 'suggested').length, links_broken: 0, links_ambiguous: 0, projects: 1, unique_tags: 3, latest_scan: {scan_id: 7001, started_at: '2026-10-15T09:59:00Z', finished_at: '2026-10-15T10:00:00Z', status: 'ok', files_seen: documents.length, added: documents.length, modified: 0, unchanged: 0, removed: 0, skipped: 0, errors: 0, duration_ms: 1000, source_summary: {}}};
const audit = {
  fixture, generated_at: '2026-10-15T10:01:00Z', quality_score: 100, counts: {}, link_classifications: [],
  missing_link_review_counts: {}, missing_link_path_state_counts: {}, missing_link_review: [], other_broken_findings: [],
  index_drift_summary: {active_documents: documents.length, checked_documents: documents.length, bytes_hashed: 0, documents_out_of_sync: 0, documents_skipped_by_budget: 0, coverage_complete: true, findings_truncated: false, by_status: {}, review_only: true},
  index_drift_findings: [], review_only: true,
};
const json = (response, value, status = 200) => { response.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Rabanito-Fixture': 'synthetic'}); response.end(JSON.stringify(value)); };

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || '/', `http://127.0.0.1:${port}`);
  if (request.method === 'GET' && url.pathname === '/') {
    const body = await fs.readFile(path.join(web, 'index.html'));
    response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store'}); response.end(body); return;
  }
  const assets = {'/assets/cyber.js': 'cyber.js', '/assets/knowledge.js': 'knowledge.js'};
  if (request.method === 'GET' && assets[url.pathname]) {
    const body = await fs.readFile(path.join(web, assets[url.pathname]));
    response.writeHead(200, {'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store'}); response.end(body); return;
  }
  if (request.method === 'GET') {
    const routes = {
      '/api/health': {ok: true, host_policy: 'fixture-loopback', fixture}, '/api/stats': stats,
      '/api/projects': {projects: [project]}, '/api/categories': {categories: ['coding-memory', 'research', 'technical']},
      '/api/tags': {tags: [{tag: 'fixture', document_count: documents.length}]}, '/api/sources': {sources: fixtureSources},
      '/api/scans': {scans: []}, '/api/changes': {changes: []}, '/api/cyber/status': {entities: 0, records: 0, kev: 0, periodic_enabled: false, connectors: []},
    };
    if (url.pathname === '/api/audit/latest') return json(response, audit);
    if (url.pathname.startsWith('/api/doc/')) {
      const document = documents.find(item => item.document_id === Number(url.pathname.split('/').pop()));
      if (document) return json(response, document);
    }
    if (Object.hasOwn(routes, url.pathname)) return json(response, routes[url.pathname]);
    if (url.pathname.startsWith('/api/')) return json(response, {error: 'Not available in synthetic fixture'}, 404);
  }
  if (request.method === 'POST' && url.pathname.startsWith('/api/')) {
    let body = '';
    for await (const chunk of request) { body += chunk; if (body.length > 20_000) return json(response, {error: 'Fixture request too large'}, 413); }
    let payload = {}; try { payload = body ? JSON.parse(body) : {}; } catch { return json(response, {error: 'Invalid JSON'}, 400); }
    if (url.pathname === '/api/graph') {
      const requestedLimit = Math.min(1000, Math.max(1, Number(payload.limit) || 180));
      const query = String(payload.q || '').trim().toLocaleLowerCase();
      const category = String(payload.category || '').trim().toLocaleLowerCase();
      const matches = graph.nodes.filter(node =>
        (!payload.source || node.source_kind === String(payload.source)) &&
        (!payload.project_id || String(node.project_id ?? '') === String(payload.project_id)) &&
        (!category || String(node.category || '').toLocaleLowerCase().startsWith(category)) &&
        (!query || `${node.title} ${node.relative_path}`.toLocaleLowerCase().includes(query))
      );
      const nodes = matches.slice(0, requestedLimit), nodeIds = new Set(nodes.map(node => String(node.document_id)));
      const filtered = {...graph, nodes, edges: graph.edges.filter(edge => nodeIds.has(String(edge.source)) && nodeIds.has(String(edge.target))), node_limit: requestedLimit, total_matches: matches.length, truncated: matches.length > requestedLimit, fixture};
      const includeSuggestions = payload.suggestions === true || ['1', 'true', 'yes'].includes(String(payload.suggestions ?? '').toLowerCase());
      if (!includeSuggestions) filtered.edges = filtered.edges.filter(edge => edge.kind !== 'suggested');
      return json(response, filtered);
    }
    if (url.pathname === '/api/search') {
      const q = String(payload.q || '').toLocaleLowerCase();
      const category = String(payload.category || '').trim().toLocaleLowerCase();
      const tag = String(payload.tag || '').trim().replace(/^#/, '').toLocaleLowerCase();
      const results = documents.filter(item =>
        (!q || `${item.title} ${item.category} ${item.relative_path} ${item.tags.join(' ')}`.toLocaleLowerCase().includes(q)) &&
        (!payload.source || item.source_kind === String(payload.source)) &&
        (!payload.project_id || String(item.project_id ?? '') === String(payload.project_id)) &&
        (!category || String(item.category || '').toLocaleLowerCase().startsWith(category)) &&
        (!tag || item.tags.some(value => value.toLocaleLowerCase() === tag))
      );
      const limit = Math.min(20, Math.max(1, Number(payload.limit) || 20));
      return json(response, {results: results.slice(0, limit).map(item => ({...item, snippet: `Fragmento sintético de prueba para ${item.title}.`, query_match: {matched_terms: 1, total_terms: 1, complete: true}}))});
    }
    if (url.pathname === '/api/context') {
      const q = String(payload.q || 'consulta sintética');
      return json(response, {fixture, characters: Math.min(164, Number(payload.max_chars || 2400)), fragments: [{document_id: 7101, title: documents[0].title, text: `FIXTURE — fragmento sintético citado. Consulta: ${q}. No procede de ninguna bóveda ni repositorio real.`, line_start: 1, line_end: 2, source_kind: 'projects', relative_path: 'fixture/core/README.md', citation: 'projects:fixture/core/README.md:1-2'}]});
    }
    if (url.pathname === '/api/source-preview') {
      const requestedPath = String(payload.path || '');
      if (!/^[A-Za-z]:\\fixture(?:\\|$)/i.test(requestedPath)) return json(response, {error: 'Fixture previews accept only a synthetic C:\\fixture path.'}, 400);
      const kind = ['local', 'research', 'reference'].includes(payload.kind) ? payload.kind : 'local';
      return json(response, {fixture, kind, already_configured: false, approval_required: true, sample_entries: ['Fixture research note.md', 'Fixture sources README.md']});
    }
    if (url.pathname === '/api/decisions') return json(response, {records: []});
    if (url.pathname.startsWith('/api/open/')) return json(response, {opened: false, fixture, message: 'Opening is disabled in fixture mode.'});
    return json(response, {error: 'Not available in synthetic fixture'}, 404);
  }
  json(response, {error: 'Not found'}, 404);
});

server.listen(port, '127.0.0.1', () => process.stdout.write(`Synthetic-only Rabanito UI fixture${largeFixture ? ' (1,000 documents)' : ''} at http://127.0.0.1:${server.address().port}/\n`));
server.on('error', error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
process.on('SIGINT', () => server.close(() => process.exit(0)));
