import {createRequestGate, requestJson, safeReference} from './cyber.js';

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

if (typeof document !== 'undefined') startKnowledge(document);
