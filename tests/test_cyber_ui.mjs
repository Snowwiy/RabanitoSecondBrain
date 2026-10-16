import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
const source = fs.readFileSync(new URL('../web/cyber.js', import.meta.url), 'utf8');
const {createRequestGate, cyberLabels, safeReference, syncMessage, startCyber} = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

function fixture() {
  class Element {
    constructor(tag) {this.tag = tag; this.children = []; this.attributes = {}; this.listeners = {}; this.value = ''; this.checked = false; this.textContent = ''; this.disabled = false;}
    append(...children) {this.children.push(...children);}
    replaceChildren(...children) {this.children = children;}
    setAttribute(k, v) {this.attributes[k] = v;}
    removeAttribute(k) {delete this.attributes[k];}
    addEventListener(k, fn) {this.listeners[k] = fn;}
    focus() {this.focused = true;}
  }
  const elements = new Map();
  const doc = {getElementById(id) {if (!elements.has(id)) elements.set(id, new Element(id)); return elements.get(id);}, createElement: tag => new Element(tag)};
  doc.getElementById('cyberSort').value = 'risk';
  return {doc, elements};
}
function deferred() {let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve};}
const response = data => ({ok: true, json: async () => data});
const record = id => ({id, title: '<script>untrusted()</script>', sources: ['kev'], exploitation: 'known_exploited'});

test('request generations ignore superseded list and detail responses', () => {
  const gate = createRequestGate(), first = gate.begin(), second = gate.begin();
  assert.equal(gate.current(first), false); assert.equal(gate.current(second), true);
});
test('resumable windows are described as unpublished progress, not a successful full update', () => {
  const text = syncMessage({status: 'partial', scope: {resumable: true, next_offset: 1500, expected_total: 1668}});
  assert.match(text, /sin publicar: 1500 de 1668/);
  assert.match(text, /continuar.*no cambiaron/);
  assert.match(syncMessage({status: 'ok', added: 3, modified: 0, unchanged: 0, scope: {backlog: true}}), /ventanas incrementales pendientes/);
});
test('EPSS and missing CVSS are labelled without inventing exploitation or severity', () => {
  const labels = cyberLabels({epss: {score: .9, date: '2026-10-15'}});
  assert.equal(labels.exploitation, 'No establecida'); assert.equal(labels.cvss, 'Sin puntuación'); assert.match(labels.epss, /90%/);
});
test('reference links reject executable schemes and embedded credentials', () => {
  for (const value of ['javascript:alert(1)', 'data:text/html,x', 'file:///c:/x', 'https://token@evil.test/']) assert.equal(safeReference(value), null);
  assert.equal(safeReference('https://nvd.nist.gov/vuln/detail/CVE-2021-44228'), 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
});
test('connector freshness distinguishes point lookups, incremental coverage and foreground cadence', async () => {
  const {doc} = fixture();
  const ui = startCyber(doc, async () => response({entities: 1, records: 1, kev: 0, periodic_enabled: true,
    connectors: [{source: 'nvd', status: 'ok', stale: true, last_success: '2026-10-16', scope: {type: 'public_identifiers'},
      coverage: {kind: 'incremental_window_checkpoint', covered_until: '2026-10-15T12:00:00Z', backlog: true}}]}));
  await ui.connectors();
  assert.match(doc.getElementById('cyberConnectorStatus').textContent, /requiere un proceso en primer plano/);
  const card = doc.getElementById('cyberConnectors').children[0];
  assert.equal(card.children[1].textContent, 'Consulta completada');
  assert.ok(card.children.some(child => /Ventanas pendientes.*puntual no amplía/.test(child.textContent)));
});
test('out-of-order searches keep latest result and render remote titles as text', async () => {
  const {doc} = fixture(), a = deferred(), b = deferred(); let calls = 0;
  const ui = startCyber(doc, () => ++calls === 1 ? a.promise : b.promise);
  const old = ui.search(true), latest = ui.search(true);
  b.resolve(response({total: 1, results: [record('CVE-2024-54321')]})); await latest;
  a.resolve(response({total: 1, results: [record('CVE-2024-12345')]})); await old;
  const cell = doc.getElementById('cyberResults').children[0].children[0];
  assert.equal(cell.children[0].textContent, 'CVE-2024-54321');
  assert.equal(cell.children[1].textContent, '<script>untrusted()</script>');
  assert.equal(doc.getElementById('cyberResults').attributes['aria-busy'], 'false');
});
test('list failure preserves prior rows and announces stale state with retry', async () => {
  const {doc} = fixture(); doc.getElementById('cyberResults').append('previous-row');
  const ui = startCyber(doc, async () => {throw new Error('offline');}); await ui.search(true);
  assert.equal(doc.getElementById('cyberResults').children[0], 'previous-row');
  assert.match(doc.getElementById('cyberStatus').textContent, /anteriores.*desactualizados.*reintentar/);
});
test('starting a new search invalidates pending detail and its busy state', async () => {
  const {doc} = fixture(), pending = deferred();
  const ui = startCyber(doc, async path => path.endsWith('/get') ? pending.promise : response({total: 0, results: []}));
  const old = ui.detail('CVE-2024-12345'); await ui.search(true);
  pending.resolve(response({...record('CVE-2024-12345'), observations: []})); await old;
  assert.match(doc.getElementById('cyberDetail').children[0].textContent, /Selecciona/);
  assert.equal(doc.getElementById('cyberDetail').attributes['aria-busy'], 'false');
});
