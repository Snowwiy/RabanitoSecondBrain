// Public-provider text is never evaluated or rendered as HTML.
export function createRequestGate() {
  let generation = 0;
  return {begin: () => ++generation, current: id => id === generation};
}

export function cyberLabels(record) {
  return {
    exploitation: record.exploitation === 'known_exploited' ? 'Explotación reportada' : 'No establecida',
    cvss: record.cvss?.score == null ? 'Sin puntuación' : `${record.cvss.score} · v${record.cvss.version}`,
    epss: record.epss?.score == null ? 'Sin puntuación' : `${(record.epss.score * 100).toLocaleString('es-MX', {maximumFractionDigits: 2})}% · ${record.epss.date}`,
  };
}

export function safeReference(value) {
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

export function syncMessage(data) {
  if (data.status === 'partial' && data.scope?.resumable) return `Ventana guardada sin publicar: ${data.scope.next_offset} de ${data.scope.expected_total} registros. Vuelve a actualizar la misma fuente para continuar; el índice y su cobertura publicados no cambiaron.`;
  if (data.status === 'ok') return `Consulta completada: ${data.added} nuevos, ${data.modified} modificados, ${data.unchanged} sin cambios.${data.scope?.backlog ? ' Quedan ventanas incrementales pendientes.' : ''}`;
  return `La actualización no se completó (${data.status} · ${data.error_code || 'sin identificadores'}). Se conserva el último índice completo; consulta el estado del conector.`;
}

export async function requestJson(path, body, fetcher = fetch) {
  const options = body === undefined ? {cache: 'no-store'} : {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body), cache: 'no-store'};
  const controller = new AbortController();
  options.signal = controller.signal;
  const timeout = setTimeout(() => controller.abort(), path.endsWith('/sync') ? 180000 : 15000);
  try {
    const response = await fetcher(path, options);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timeout); }
}

export function startCyber(doc, fetcher = fetch) {
  const byId = id => doc.getElementById(id);
  if (!byId('cyberPanel')) return;
  const api = (path, body) => requestJson(path, body, fetcher);
  const listGate = createRequestGate(), detailGate = createRequestGate(), statusGate = createRequestGate();
  let offset = 0, total = 0, timer, composing = false, loaded = false, listBusy = false, syncBusy = false;
  const el = (tag, content, className) => {
    const node = doc.createElement(tag);
    if (content !== undefined) node.textContent = String(content);
    if (className) node.className = className;
    return node;
  };
  function paging() {
    byId('cyberPrev').disabled = listBusy || offset === 0;
    byId('cyberNext').disabled = listBusy || offset + 20 >= total;
    byId('cyberCount').textContent = total ? `${offset + 1}–${Math.min(offset + 20, total)} de ${total.toLocaleString('es-MX')}` : '0 resultados';
  }
  async function detail(id) {
    const generation = detailGate.begin(), target = byId('cyberDetail');
    target.setAttribute('aria-busy', 'true');
    target.replaceChildren(el('p', 'Consultando evidencia local…', 'meta'));
    try {
      const record = await api('/api/cyber/get', {id});
      if (!detailGate.current(generation)) return;
      const labels = cyberLabels(record);
      target.replaceChildren(el('h3', `${record.id} · ${record.title}`), el('p', record.description || 'Descripción no disponible.'),
        el('p', `${labels.exploitation} · Estado: ${record.status} · ${labels.cvss} · EPSS ${labels.epss}`, 'meta'),
        el('p', `Publicado: ${record.published || 'No informado'} · Modificado: ${record.modified || 'No informado'} · Consultado: ${record.retrieved_at}`, 'meta'));
      for (const observation of record.observations || []) {
        const section = el('section');
        section.append(el('h3', `${observation.source.toUpperCase()} · ${observation.id}`), el('p', `Consulta: ${observation.retrieved_at}`, 'meta'));
        if (observation.kev) section.append(el('p', `CISA KEV desde ${observation.kev.date_added}. Acción requerida: ${(observation.mitigations || []).join(' ')}`));
        if (observation.epss) section.append(el('p', `EPSS ${observation.epss.date}: ${(observation.epss.score * 100).toLocaleString('es-MX')}%. Predicción, no evidencia de explotación.`));
        if (observation.affected?.length) {
          const details = el('details'), summary = el('summary', `Productos, rangos y versiones declaradas (${observation.affected.length})`);
          details.append(summary, el('pre', JSON.stringify(observation.affected, null, 2))); section.append(details);
        }
        if (observation.fixes?.length) section.append(el('p', `Versiones de corrección declaradas: ${observation.fixes.map(x => `${x.package} ${x.version}`).join('; ')}`));
        const links = el('ul'), seen = new Set();
        for (const item of [{url: observation.source_url}, ...(observation.references || [])].slice(0, 25)) {
          const url = safeReference(item.url);
          if (!url || seen.has(url)) continue;
          seen.add(url); const li = el('li'), anchor = el('a', url);
          anchor.href = url; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; li.append(anchor); links.append(li);
        }
        section.append(links); target.append(section);
      }
      target.focus();
    } catch {
      if (detailGate.current(generation)) target.replaceChildren(el('p', 'No se pudo recuperar el detalle. Selecciona de nuevo el identificador.', 'error'));
    } finally { if (detailGate.current(generation)) target.setAttribute('aria-busy', 'false'); }
  }
  async function search(reset = false) {
    if (reset) offset = 0;
    const generation = listGate.begin(); detailGate.begin();
    byId('cyberDetail').replaceChildren(el('p', 'Selecciona un identificador de los resultados actuales.', 'meta'));
    byId('cyberDetail').setAttribute('aria-busy', 'false');
    listBusy = true; paging(); byId('cyberResults').setAttribute('aria-busy', 'true');
    byId('cyberStatus').textContent = 'Consultando el índice local…';
    try {
      const data = await api('/api/cyber/search', {q: byId('cyberQuery').value.trim(), source: byId('cyberSource').value,
        sort: byId('cyberSort').value, kev: byId('cyberKev').checked, offset, limit: 20});
      if (!listGate.current(generation)) return;
      total = data.total;
      if (offset >= total && offset > 0) { offset = Math.max(0, Math.floor((total - 1) / 20) * 20); await search(); return; }
      byId('cyberResults').replaceChildren();
      for (const record of data.results) {
        const row = el('tr'), cell = el('td'), button = el('button', record.id), labels = cyberLabels(record);
        button.type = 'button'; button.addEventListener('click', () => detail(record.id));
        cell.append(button, el('div', record.title === record.id ? '' : record.title, 'meta')); row.append(cell);
        for (const content of [labels.exploitation, labels.cvss, labels.epss, record.sources.join(', ')]) row.append(el('td', content));
        byId('cyberResults').append(row);
      }
      byId('cyberStatus').textContent = total ? `${total.toLocaleString('es-MX')} coincidencias locales. Consulta el detalle para comprobar alcance y fechas.` : 'Sin coincidencias locales. Limpia los filtros o actualiza una fuente pública.';
    } catch {
      if (listGate.current(generation)) byId('cyberStatus').textContent = 'No se pudo consultar el índice. Los resultados anteriores pueden estar desactualizados; pulsa Buscar para reintentar.';
    } finally {
      if (listGate.current(generation)) { listBusy = false; paging(); byId('cyberResults').setAttribute('aria-busy', 'false'); }
    }
  }
  async function connectors() {
    const generation = statusGate.begin();
    try {
      const data = await api('/api/cyber/status');
      if (!statusGate.current(generation)) return;
      byId('cyberConnectors').replaceChildren();
      const statuses = {ok: 'Consulta completada', error: 'Error de actualización', partial: 'Actualización incompleta', never: 'Sin sincronización', running: 'Actualizando', interrupted: 'Interrumpido', not_configured: 'Sin identificadores configurados'};
      const cadence = data.periodic_enabled ? 'Cadencia habilitada en configuración; requiere un proceso en primer plano.' : 'Cadencia desactivada.';
      byId('cyberConnectorStatus').textContent = `${data.entities.toLocaleString('es-MX')} vulnerabilidades · ${data.records.toLocaleString('es-MX')} aportaciones de proveedores · ${data.kev.toLocaleString('es-MX')} en CISA KEV. ${cadence} No se administra un servicio automático.`;
      for (const source of data.connectors) {
        const card = el('article');
        card.append(el('h3', source.source.toUpperCase()), el('div', statuses[source.status] || source.status),
          el('div', `${source.records || 0} registros · Último éxito: ${source.last_success || 'Nunca'}`, 'meta'),
          el('div', source.stale ? 'Frescura pendiente de actualizar' : 'Consultado en las últimas 24 horas', 'meta'));
        if (source.error_code) card.append(el('div', `Error registrado: ${source.error_code}`, 'error'));
        const pending = (data.pending_windows || []).find(window => window.source === source.source);
        if (pending) card.append(el('div', `Checkpoint no publicado: ${pending.next_offset} de ${pending.expected_total} registros. Actualiza la misma fuente para continuar.`, 'meta'));
        if (source.coverage?.kind === 'incremental_window_checkpoint' || source.source === 'nvd') card.append(el('div',
          `Cobertura incremental hasta: ${source.coverage?.covered_until || 'Sin ventana completada'}${source.coverage?.backlog ? ' · Ventanas pendientes' : ''}. Una consulta puntual no amplía esta cobertura.`, 'meta'));
        if (source.scope?.type) card.append(el('div', `Ámbito: ${source.scope.type}${source.scope.count != null ? ` · ${source.scope.count} identificadores` : ''}`, 'meta'));
        byId('cyberConnectors').append(card);
      }
    } catch { if (statusGate.current(generation)) byId('cyberConnectorStatus').textContent = 'No se pudo consultar el estado. Vuelve a abrir el panel para reintentar.'; }
  }
  byId('cyberSearchForm').addEventListener('submit', event => { event.preventDefault(); if (!composing) { clearTimeout(timer); search(true); } });
  byId('cyberQuery').addEventListener('compositionstart', () => { composing = true; clearTimeout(timer); listGate.begin(); });
  byId('cyberQuery').addEventListener('compositionend', () => { composing = false; clearTimeout(timer); timer = setTimeout(() => search(true), 300); });
  byId('cyberQuery').addEventListener('input', () => {
    byId('cyberClear').hidden = !byId('cyberQuery').value;
    clearTimeout(timer); listGate.begin(); detailGate.begin();
    if (!composing) timer = setTimeout(() => search(true), 300);
  });
  byId('cyberClear').addEventListener('click', () => { clearTimeout(timer); byId('cyberQuery').value = ''; byId('cyberClear').hidden = true; byId('cyberQuery').focus(); search(true); });
  for (const id of ['cyberSource', 'cyberSort', 'cyberKev']) byId(id).addEventListener('change', () => search(true));
  byId('cyberPrev').addEventListener('click', () => { offset = Math.max(0, offset - 20); search(); });
  byId('cyberNext').addEventListener('click', () => { offset += 20; search(); });
  byId('cyberPanel').addEventListener('toggle', () => { if (byId('cyberPanel').open) { connectors(); if (!loaded) { loaded = true; search(); } } });
  doc.addEventListener?.('rabanito-public-selection', event => {
    if (event.detail?.kind !== 'vulnerability') return;
    loaded = true; byId('cyberPanel').open = true;
    detail(event.detail.id);
  });
  byId('cyberSync').addEventListener('click', async () => {
    if (syncBusy) return;
    const source = byId('cyberSyncSource').value, value = byId('cyberSyncId').value.trim();
    if ((value && !/^(CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2})$/i.test(value)) || (source === 'osv' && !value) || (source === 'kev' && value)) {
      byId('cyberSyncStatus').textContent = 'Usa una CVE o un aviso GHSA público válido; OSV requiere identificador y KEV actualiza el catálogo sin identificador.';
      byId('cyberSyncId').setAttribute('aria-invalid', 'true'); byId('cyberSyncId').focus(); return;
    }
    byId('cyberSyncId').removeAttribute('aria-invalid');
    syncBusy = true; byId('cyberSync').disabled = true; byId('cyberSync').setAttribute('aria-busy', 'true');
    byId('cyberSyncStatus').textContent = 'Actualizando la fuente pública seleccionada… Puedes seguir consultando el índice local.';
    try {
      const data = await api('/api/cyber/sync', {source, ids: value ? [value] : undefined, confirm_public_sync: true});
      byId('cyberSyncStatus').textContent = syncMessage(data);
      await connectors(); await search(true);
    } catch { byId('cyberSyncStatus').textContent = 'No se pudo confirmar la actualización. Reabre el panel para comprobar el historial antes de reintentar.'; }
    finally { syncBusy = false; byId('cyberSync').disabled = false; byId('cyberSync').setAttribute('aria-busy', 'false'); }
  });
  return {search, detail, connectors};
}

if (typeof document !== 'undefined') startCyber(document);
