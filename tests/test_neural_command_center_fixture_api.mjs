import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import net from 'node:net';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtureServer = path.join(root, 'tests', 'neural_command_center_fixture_server.mjs');

async function unusedLoopbackPort() {
  const probe = net.createServer();
  await new Promise((resolve, reject) => probe.once('error', reject).listen(0, '127.0.0.1', resolve));
  const {port} = probe.address();
  await new Promise((resolve, reject) => probe.close(error => error ? reject(error) : resolve()));
  return port;
}

async function postJson(base, endpoint, payload) {
  const response = await fetch(`${base}${endpoint}`, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
  });
  assert.equal(response.status, 200);
  return response.json();
}

test('synthetic fixture API applies the dashboard search and graph filters', {timeout: 15000}, async t => {
  const port = await unusedLoopbackPort();
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, [fixtureServer, String(port)], {cwd: root, stdio: ['ignore', 'pipe', 'pipe']});
  let startupOutput = '', startupError = '';
  child.stdout.setEncoding('utf8').on('data', chunk => { startupOutput += chunk; });
  child.stderr.setEncoding('utf8').on('data', chunk => { startupError += chunk; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    if (child.exitCode === null && child.signalCode === null) await Promise.race([once(child, 'exit'), new Promise(resolve => setTimeout(resolve, 2000))]);
  });

  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    if (child.exitCode !== null) break;
    try {
      const response = await fetch(`${base}/api/health`);
      if (response.ok && (await response.json()).fixture === true) { ready = true; break; }
    } catch { /* The local process may need a short moment to bind its loopback port. */ }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.ok(ready, `fixture server did not start: ${startupOutput} ${startupError}`);

  const sourceResponse = await fetch(`${base}/api/sources`);
  assert.equal(sourceResponse.status, 200);
  const sources = await sourceResponse.json();
  assert.deepEqual(sources.sources.map(source => source.kind).sort(), ['internal', 'obsidian', 'projects']);
  assert.ok(sources.sources.every(source => source.enabled === true && source.managed === false && source.name.startsWith('Fixture')));

  const statsResponse = await fetch(`${base}/api/stats`);
  assert.equal(statsResponse.status, 200);
  const stats = await statsResponse.json();
  assert.equal(stats.fixture, true);
  assert.deepEqual(
    ['files_seen', 'added', 'modified', 'unchanged', 'removed', 'skipped', 'errors'].map(key => stats.latest_scan[key]),
    [3, 3, 0, 0, 0, 0, 0],
  );

  const markdown = await postJson(base, '/api/doc/content', {document_id: 7101, max_bytes: 65_536});
  assert.equal(markdown.fixture, true);
  assert.equal(markdown.document_id, 7101);
  assert.equal(markdown.truncated, false);
  assert.equal(markdown.bytes_returned, Buffer.byteLength(markdown.content_markdown, 'utf8'));
  assert.match(markdown.content_markdown, /<img src=x onerror=/);
  assert.equal(markdown.references[0].target_document_id, 7102);
  assert.equal(Object.hasOwn(markdown, 'absolute_path'), false);

  const rejectedReader = await fetch(`${base}/api/doc/content`, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({document_id: 7101, max_bytes: 99_999}),
  });
  assert.equal(rejectedReader.status, 400);

  const auditResponse = await fetch(`${base}/api/audit/latest`);
  assert.equal(auditResponse.status, 200);
  const audit = await auditResponse.json();
  assert.equal(audit.review_only, true);
  assert.equal(audit.fixture, true);
  assert.equal(audit.index_drift_summary.coverage_complete, true);
  assert.deepEqual(audit.index_drift_findings, []);
  assert.deepEqual(audit.missing_link_review, []);

  const preview = await postJson(base, '/api/source-preview', {path: 'C:\\fixture\\research', kind: 'research', name: 'Fixture research'});
  assert.equal(preview.fixture, true);
  assert.equal(preview.approval_required, true);
  assert.deepEqual(preview.sample_entries, ['Fixture research note.md', 'Fixture sources README.md']);
  assert.equal(Object.hasOwn(preview, 'absolute_path'), false);

  const rejectedPreview = await fetch(`${base}/api/source-preview`, {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: 'C:\\external\\notes', kind: 'local'}),
  });
  assert.equal(rejectedPreview.status, 400);

  const graph = await postJson(base, '/api/graph', {
    domain: 'documents', limit: 1, source: 'projects', project_id: 7001,
    category: 'tech', q: 'README', suggestions: true, min_degree: 0,
  });
  assert.deepEqual(graph.nodes.map(node => node.document_id), [7101]);
  assert.equal(graph.total_matches, 1);
  assert.equal(graph.truncated, false);
  assert.equal(graph.fixture, true);

  const sourceGraph = await postJson(base, '/api/graph', {domain: 'documents', limit: 10, source: 'obsidian'});
  assert.deepEqual(sourceGraph.nodes.map(node => node.document_id), [7102]);

  const projectGraph = await postJson(base, '/api/graph', {domain: 'documents', limit: 10, project_id: 7001});
  assert.deepEqual(projectGraph.nodes.map(node => node.document_id), [7101, 7103]);

  const categoryGraph = await postJson(base, '/api/graph', {domain: 'documents', limit: 10, category: 'tech'});
  assert.deepEqual(categoryGraph.nodes.map(node => node.document_id), [7101]);

  const queryGraph = await postJson(base, '/api/graph', {domain: 'documents', limit: 10, q: 'README'});
  assert.deepEqual(queryGraph.nodes.map(node => node.document_id), [7101]);

  const limitedGraph = await postJson(base, '/api/graph', {domain: 'documents', limit: 1, project_id: 7001});
  assert.equal(limitedGraph.total_matches, 2);
  assert.equal(limitedGraph.nodes.length, 1);
  assert.equal(limitedGraph.truncated, true);

  const search = await postJson(base, '/api/search', {
    q: 'indexación', source: 'obsidian', category: 'research', tag: '#obsidian', limit: 30,
  });
  assert.deepEqual(search.results.map(item => item.document_id), [7102]);

  const sourceSearch = await postJson(base, '/api/search', {source: 'projects'});
  assert.deepEqual(sourceSearch.results.map(item => item.document_id), [7101]);

  const categorySearch = await postJson(base, '/api/search', {category: 'tech'});
  assert.deepEqual(categorySearch.results.map(item => item.document_id), [7101]);

  const tagSearch = await postJson(base, '/api/search', {tag: 'retrieval'});
  assert.deepEqual(tagSearch.results.map(item => item.document_id), [7103]);

  const querySearch = await postJson(base, '/api/search', {q: 'README'});
  assert.deepEqual(querySearch.results.map(item => item.document_id), [7101]);

  const projectSearch = await postJson(base, '/api/search', {
    project_id: 7001, category: 'coding', tag: 'retrieval', limit: 30,
  });
  assert.deepEqual(projectSearch.results.map(item => item.document_id), [7103]);

  const mismatchedSearch = await postJson(base, '/api/search', {source: 'obsidian', project_id: 7001});
  assert.deepEqual(mismatchedSearch.results, []);
});

test('synthetic fixture can reproduce a Markdown transport failure without returning content', {timeout: 15000}, async t => {
  const port = await unusedLoopbackPort();
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, [fixtureServer, String(port), '--markdown-network-error'], {cwd: root, stdio: ['ignore', 'pipe', 'pipe']});
  let startupOutput = '', startupError = '';
  child.stdout.setEncoding('utf8').on('data', chunk => { startupOutput += chunk; });
  child.stderr.setEncoding('utf8').on('data', chunk => { startupError += chunk; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    if (child.exitCode === null && child.signalCode === null) await Promise.race([once(child, 'exit'), new Promise(resolve => setTimeout(resolve, 2000))]);
  });

  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    if (child.exitCode !== null) break;
    try {
      const response = await fetch(`${base}/api/health`);
      if (response.ok && (await response.json()).fixture === true) { ready = true; break; }
    } catch { /* The local process may need a short moment to bind its loopback port. */ }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.ok(ready, `fixture server did not start: ${startupOutput} ${startupError}`);
  await assert.rejects(
    fetch(`${base}/api/doc/content`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({document_id: 7101, max_bytes: 65_536})}),
    error => error instanceof TypeError && /fetch failed/i.test(error.message),
  );
});
