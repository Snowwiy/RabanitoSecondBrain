import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
const cyber = `data:text/javascript;base64,${Buffer.from(fs.readFileSync(new URL('../web/cyber.js', import.meta.url), 'utf8')).toString('base64')}`;
const source = fs.readFileSync(new URL('../web/knowledge.js', import.meta.url), 'utf8').replace("'./cyber.js'", JSON.stringify(cyber));
const {startKnowledge} = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

function fixture() {
  class Element {
    constructor(tag) {this.tag = tag; this.children = []; this.attributes = {}; this.listeners = {}; this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false;}
    append(...children) {this.children.push(...children);}
    replaceChildren(...children) {this.children = children;}
    setAttribute(k, v) {this.attributes[k] = v;}
    addEventListener(k, fn) {this.listeners[k] = fn;}
    focus() {this.focused = true;}
  }
  const elements = new Map();
  const doc = {getElementById(id) {if (!elements.has(id)) elements.set(id, new Element(id)); return elements.get(id);},
    createElement: tag => new Element(tag), createDocumentFragment: () => new Element('fragment')};
  doc.getElementById('knowledgeMode').value = 'security';
  return doc;
}
const response = data => ({ok: true, json: async () => data});
const entry = (id = 'NIST-800-207') => ({id, title: '<img src=x onerror=leak()>', summary: 'Own cited summary', edition_status: 'published', reviewed_on: '2026-10-16'});
function deferred() {let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve};}

test('knowledge panel is lazy and sends filters in a local POST, never in a URL', async () => {
  const doc = fixture(), calls = [];
  const ui = startKnowledge(doc, async (url, options) => {calls.push({url, options}); return response({results: [entry()], total: 1, catalog_version: 'fixture'});});
  assert.equal(calls.length, 0);
  doc.getElementById('knowledgeQuery').value = 'private-query-sentinel'; await ui.search();
  assert.equal(calls[0].url, '/api/security/search'); assert.equal(calls[0].options.method, 'POST');
  assert.equal(JSON.parse(calls[0].options.body).q, 'private-query-sentinel');
  assert.equal(doc.getElementById('knowledgeNext').disabled, true);
  const button = doc.getElementById('knowledgeResults').children[0].children[0].children[0];
  assert.equal(button.textContent, '<img src=x onerror=leak()>');
});

test('latest knowledge request wins and stale responses cannot replace results', async () => {
  const doc = fixture(), old = deferred(), recent = deferred(); let count = 0;
  const ui = startKnowledge(doc, () => ++count === 1 ? old.promise : recent.promise);
  const a = ui.search(), b = ui.search();
  recent.resolve(response({results: [entry('RECENT')], total: 1})); await b;
  old.resolve(response({results: [entry('OLD')], total: 1})); await a;
  const card = doc.getElementById('knowledgeResults').children[0].children[0];
  assert.match(card.children[1].textContent, /RECENT/);
});

test('knowledge list failure preserves previous results and announces staleness', async () => {
  const doc = fixture(); doc.getElementById('knowledgeResults').append('previous');
  const ui = startKnowledge(doc, async () => {throw new Error('offline');}); await ui.search();
  assert.equal(doc.getElementById('knowledgeResults').children[0], 'previous');
  assert.match(doc.getElementById('knowledgeStatus').textContent, /anteriores.*desactualizados.*reintentar/);
  assert.equal(doc.getElementById('knowledgeResults').attributes['aria-busy'], 'false');
});

test('coding mode requires a query or technology and never invents sample experiences', async () => {
  const doc = fixture(); doc.getElementById('knowledgeMode').value = 'coding'; let calls = 0;
  const ui = startKnowledge(doc, async () => {calls++; return response({results: [], coverage: {candidates_examined: 0}});});
  await ui.search(); assert.equal(calls, 0);
  assert.match(doc.getElementById('knowledgeStatus').textContent, /Escribe un problema/);
  doc.getElementById('knowledgeTechnology').value = 'Python'; await ui.search();
  assert.equal(calls, 1);
  const empty = doc.getElementById('knowledgeResults').children[0].children[0];
  assert.match(empty.textContent, /No se han generado datos de ejemplo/);
});

test('reviewed coding fragments and relative citations render only as text', async () => {
  const doc = fixture(); doc.getElementById('knowledgeMode').value = 'coding'; doc.getElementById('knowledgeQuery').value = 'rollback';
  const ui = startKnowledge(doc, async (url, options) => {
    assert.equal(url, '/api/coding/similar'); assert.equal(JSON.parse(options.body).max_chars, 6000);
    return response({results: [{title: 'Reviewed fixture', project: 'Local', recorded_date: '2026-10-16',
      fragments: [{text: '<script>private()</script>', citation: 'internal:decisions/fixture.md:4-5'}], evidence: ['project:README.md']}], coverage: {candidates_examined: 1}});
  });
  await ui.search(); const card = doc.getElementById('knowledgeResults').children[0].children[0];
  assert.equal(card.children[2].textContent, '<script>private()</script>');
  assert.equal(card.children[3].textContent, 'internal:decisions/fixture.md:4-5');
  assert.match(card.children[1].textContent, /no ejecutada de nuevo/);
  assert.equal(doc.getElementById('knowledgeNext').disabled, true);
});

test('patterns are descriptive and omit hidden query and technology filters', async () => {
  const doc = fixture(); doc.getElementById('knowledgeMode').value = 'patterns'; doc.getElementById('knowledgeTechnology').value = 'hidden-private';
  const ui = startKnowledge(doc, async (url, options) => {
    assert.equal(url, '/api/coding/patterns'); assert.deepEqual(JSON.parse(options.body), {project: null, limit: 10});
    return response({patterns: [{technology: 'python', projects: ['Local'], record_count_in_examined_sample: 2, citations: ['internal:a.md']}], coverage: {candidate_limit_reached: true}});
  });
  await ui.search(); const card = doc.getElementById('knowledgeResults').children[0].children[0];
  assert.match(card.children[2].textContent, /no demuestra una causa común/);
  assert.match(doc.getElementById('knowledgeStatus').textContent, /Cobertura parcial/);
});

test('a pending security detail cannot replace the pane after a newer search', async () => {
  const doc = fixture(), pending = deferred();
  const ui = startKnowledge(doc, async url => url.endsWith('/get') ? pending.promise : response({results: [], total: 0}));
  const detail = ui.detail('OLD'); await ui.search();
  pending.resolve(response({...entry(), edition: 'fixture', source_url: 'javascript:leak()'})); await detail;
  assert.match(doc.getElementById('knowledgeDetail').textContent, /Selecciona una ficha/);
  assert.equal(doc.getElementById('knowledgeDetail').attributes['aria-busy'], 'false');
});
