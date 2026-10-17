// Local-only, explicitly synthetic visual QA server; never connects to the Second Brain API or SQLite.
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const web = path.join(root, 'web');
const port = Number(process.argv[2] || 8877);
const fixture = true;
const project = {project_id: 7001, name: 'Fixture Core', status: 'active', relative_path: 'fixture/core', technologies: ['Python', 'SQLite']};
const documents = [
  {document_id: 7101, title: 'Fixture — Arquitectura de memoria local', source_kind: 'projects', category: 'technical', project_name: 'Fixture Core', relative_path: 'README.md', mtime_iso: '2026-10-15T10:00:00Z', degree: 2, tags: ['fixture', 'arquitectura'], frontmatter: {status: 'fixture'}, links: [], incoming_links: []},
  {document_id: 7102, title: 'Fixture — Indexación incremental de notas', source_kind: 'obsidian', category: 'research', project_name: '', relative_path: 'Research/Indexación.md', mtime_iso: '2026-10-14T09:00:00Z', degree: 2, tags: ['fixture', 'obsidian'], frontmatter: {source: 'fixture'}, links: [], incoming_links: []},
  {document_id: 7103, title: 'Fixture — Recuperación con citas verificables', source_kind: 'internal', category: 'coding-memory', project_name: 'Fixture Core', relative_path: 'knowledge/coding-memory/demo.md', mtime_iso: '2026-10-13T12:00:00Z', degree: 1, tags: ['fixture', 'retrieval'], frontmatter: {validation: 'fixture'}, links: [], incoming_links: []},
];
const graph = {
  nodes: documents.map(({document_id, title, source_kind, category, project_name, relative_path, mtime_iso, degree}) => ({document_id, title, source_kind, category, project_name, relative_path, mtime_iso, degree})),
  edges: [
    {source: 7101, target: 7102, kind: 'explicit', status: 'resolved', relation_type: 'wikilink'},
    {source: 7101, target: 7103, kind: 'explicit', status: 'resolved', relation_type: 'documented-reference'},
    {source: 7102, target: 7103, kind: 'suggested', status: 'suggested', relation_type: 'similarity-candidate'},
  ], node_limit: 180, total_matches: documents.length, truncated: false,
};
const stats = {fixture, documents_active: documents.length, relations_resolved: 2, relations_suggested: 1, links_broken: 0, links_ambiguous: 0, projects: 1, unique_tags: 3, latest_scan: {status: 'ok', finished_at: '2026-10-15T10:00:00Z'}};
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
      '/api/tags': {tags: [{tag: 'fixture', document_count: 3}]}, '/api/sources': {sources: []},
      '/api/scans': {scans: []}, '/api/changes': {changes: []}, '/api/cyber/status': {entities: 0, records: 0, kev: 0, periodic_enabled: false, connectors: []},
    };
    if (url.pathname === '/api/doc/7101' || url.pathname === '/api/doc/7102' || url.pathname === '/api/doc/7103') return json(response, documents.find(item => item.document_id === Number(url.pathname.split('/').pop())));
    if (Object.hasOwn(routes, url.pathname)) return json(response, routes[url.pathname]);
    if (url.pathname.startsWith('/api/')) return json(response, {error: 'Not available in synthetic fixture'}, 404);
  }
  if (request.method === 'POST' && url.pathname.startsWith('/api/')) {
    let body = '';
    for await (const chunk of request) { body += chunk; if (body.length > 20_000) return json(response, {error: 'Fixture request too large'}, 413); }
    let payload = {}; try { payload = body ? JSON.parse(body) : {}; } catch { return json(response, {error: 'Invalid JSON'}, 400); }
    if (url.pathname === '/api/graph') {
      const filtered = {...graph, fixture};
      if (!payload.suggestions) filtered.edges = filtered.edges.filter(edge => edge.kind !== 'suggested');
      return json(response, filtered);
    }
    if (url.pathname === '/api/search') {
      const q = String(payload.q || '').toLocaleLowerCase();
      return json(response, {results: documents.filter(item => `${item.title} ${item.category}`.toLocaleLowerCase().includes(q)).map(item => ({...item, snippet: `Fragmento sintético de prueba para ${item.title}.`, query_match: {matched_terms: 1, total_terms: 1, complete: true}}))});
    }
    if (url.pathname === '/api/context') {
      const q = String(payload.q || 'consulta sintética');
      return json(response, {fixture, characters: Math.min(164, Number(payload.max_chars || 2400)), fragments: [{document_id: 7101, title: documents[0].title, text: `FIXTURE — fragmento sintético citado. Consulta: ${q}. No procede de ninguna bóveda ni repositorio real.`, line_start: 1, line_end: 2, source_kind: 'projects', relative_path: 'fixture/core/README.md', citation: 'projects:fixture/core/README.md:1-2'}]});
    }
    if (url.pathname === '/api/decisions') return json(response, {records: []});
    if (url.pathname.startsWith('/api/open/')) return json(response, {opened: false, fixture, message: 'Opening is disabled in fixture mode.'});
    return json(response, {error: 'Not available in synthetic fixture'}, 404);
  }
  json(response, {error: 'Not found'}, 404);
});

server.listen(port, '127.0.0.1', () => process.stdout.write(`Synthetic-only Rabanito UI fixture at http://127.0.0.1:${port}/\n`));
server.on('error', error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
process.on('SIGINT', () => server.close(() => process.exit(0)));
