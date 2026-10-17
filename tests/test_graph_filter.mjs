import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(projectRoot, "web", "index.html"), "utf8");
const rootStyle = html.match(/:root\s*\{([^}]*)\}/)?.[1] ?? "";
const theme = Object.fromEntries([...rootStyle.matchAll(/--([a-z-]+)\s*:\s*(#[\da-f]{6})/gi)].map((match) => [match[1], match[2]]));
function contrastRatio(first, second) {
  const luminance = (color) => {
    const channels = [1, 3, 5].map((offset) => Number.parseInt(color.slice(offset, offset + 2), 16) / 255);
    const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
  };
  const values = [luminance(first), luminance(second)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}
const start = html.indexOf("function visibleGraph(){");
const end = html.indexOf("\n    function drawGraph(){", start);
assert.notEqual(start, -1, "visibleGraph() must exist in the dashboard");
assert.notEqual(end, -1, "drawGraph() must follow visibleGraph()");
const visibleGraphSource = html.slice(start, end);
const communityStart = html.indexOf("    function computeCommunities(){");
const communityEnd = html.indexOf("\n    function seedLayout(){", communityStart);
assert.notEqual(communityStart, -1, "computeCommunities() must exist in the dashboard");
assert.notEqual(communityEnd, -1, "seedLayout() must follow computeCommunities()");
const communitySource = html.slice(communityStart, communityEnd);
const labelStart = html.indexOf("    function layoutGraphLabels(");
const labelEnd = html.indexOf("\n    function drawGraph(){", labelStart);
assert.notEqual(labelStart, -1, "layoutGraphLabels() must exist in the dashboard");
assert.notEqual(labelEnd, -1, "drawGraph() must follow layoutGraphLabels()");
const labelSource = html.slice(labelStart, labelEnd);
const graphInfoStart = html.indexOf("    function renderGraphInfo(){");
const graphInfoEnd = html.indexOf("\n    function selectNode(", graphInfoStart);
assert.notEqual(graphInfoStart, -1, "renderGraphInfo() must exist in the dashboard");
assert.notEqual(graphInfoEnd, -1, "selectNode() must follow renderGraphInfo()");
const graphInfoSource = html.slice(graphInfoStart, graphInfoEnd);
const escStart = html.indexOf("    const esc =");
const escEnd = html.indexOf("\n", escStart);
assert.notEqual(escStart, -1, "dashboard HTML escaping helper must exist");
const escapeSource = html.slice(escStart, escEnd);
const auditSummaryStart = html.indexOf("    function auditSummary(data){");
const auditSummaryEnd = html.indexOf("\n    async function runAction(", auditSummaryStart);
assert.notEqual(auditSummaryStart, -1, "auditSummary() must exist in the dashboard");
assert.notEqual(auditSummaryEnd, -1, "runAction() must follow auditSummary()");
const auditSummarySource = html.slice(auditSummaryStart, auditSummaryEnd);
const sourceFiltersStart = html.indexOf("    function renderSourceFilters(sources){");
const sourceFiltersEnd = html.indexOf("\n    async function loadProjectPolicies()", sourceFiltersStart);
assert.notEqual(sourceFiltersStart, -1, "renderSourceFilters() must exist in the dashboard");
assert.notEqual(sourceFiltersEnd, -1, "loadProjectPolicies() must follow renderSourceFilters()");
const sourceFiltersSource = html.slice(sourceFiltersStart, sourceFiltersEnd);
const projectPanelStart = html.indexOf("    function updateProjectPolicyLabel(){");
const projectPanelEnd = html.indexOf("\n    async function postJson(", projectPanelStart);
assert.notEqual(projectPanelStart, -1, "project inventory renderer must exist in the dashboard");
assert.notEqual(projectPanelEnd, -1, "project inventory renderer must precede postJson()");
const projectPanelSource = html.slice(projectPanelStart, projectPanelEnd);
const auditLabelsStart = html.indexOf("    const auditReasonLabels=");
const auditLabelsEnd = html.indexOf("\n    function fillAuditSelect(", auditLabelsStart);
assert.notEqual(auditLabelsStart, -1, "audit classification labels must exist in the dashboard");
assert.notEqual(auditLabelsEnd, -1, "fillAuditSelect() must follow audit label definitions");
const auditLabelsSource = html.slice(auditLabelsStart, auditLabelsEnd);
const driftStart = html.indexOf("    const indexDriftLabels=");
const driftEnd = html.indexOf("\n    function fillAuditSelect(", driftStart);
assert.notEqual(driftStart, -1, "index-drift labels must exist in the dashboard");
assert.notEqual(driftEnd, -1, "fillAuditSelect() must follow index-drift rendering");
const driftSource = html.slice(driftStart, driftEnd);
const searchMatchStart = html.indexOf("    function searchMatchLabel(");
const searchMatchEnd = html.indexOf("\n    async function search()", searchMatchStart);
assert.notEqual(searchMatchStart, -1, "searchMatchLabel() must exist in the dashboard");
assert.notEqual(searchMatchEnd, -1, "search() must follow searchMatchLabel()");
const searchMatchSource = html.slice(searchMatchStart, searchMatchEnd);
const scanHistoryStart = html.indexOf("    function scanMetric(value){");
const scanHistoryEnd = html.indexOf("\n    async function loadScans()", scanHistoryStart);
assert.notEqual(scanHistoryStart, -1, "scan history renderer must exist in the dashboard");
assert.notEqual(scanHistoryEnd, -1, "scan history loader must follow the renderer");
const scanHistorySource = html.slice(scanHistoryStart, scanHistoryEnd);
const sourceFailuresStart = html.indexOf("    function scanSourceFailures(scan){");
const sourceFailuresEnd = html.indexOf("\n    function renderScanHistory", sourceFailuresStart);
assert.notEqual(sourceFailuresStart, -1, "scan source failure formatter must exist in the dashboard");
assert.notEqual(sourceFailuresEnd, -1, "scan history renderer must follow source failure formatting");
const sourceFailuresSource = html.slice(sourceFailuresStart, sourceFailuresEnd);
const statsLoaderStart = html.indexOf("    async function loadStats(){");
const statsLoaderEnd = html.indexOf("\n    function searchParams()", statsLoaderStart);
assert.notEqual(statsLoaderStart, -1, "loadStats() must exist in the dashboard");
assert.notEqual(statsLoaderEnd, -1, "searchParams() must follow loadStats()");
const statsLoaderSource = html.slice(statsLoaderStart, statsLoaderEnd);
const documentChangesStart = html.indexOf("    const documentChangeLabels=");
const documentChangesEnd = html.indexOf("\n    async function loadDocumentChanges()", documentChangesStart);
assert.notEqual(documentChangesStart, -1, "document-change labels and renderer must exist in the dashboard");
assert.notEqual(documentChangesEnd, -1, "document-change loader must follow the renderer");
const documentChangesSource = html.slice(documentChangesStart, documentChangesEnd);
const canvasResizeStart = html.indexOf("    function syncCanvasBackingStore(");
const canvasResizeEnd = html.indexOf("\n    function drawGraph()", canvasResizeStart);
assert.notEqual(canvasResizeStart, -1, "canvas backing-store helper must exist in the dashboard");
assert.notEqual(canvasResizeEnd, -1, "drawGraph() must follow the canvas backing-store helper");
const canvasResizeSource = html.slice(canvasResizeStart, canvasResizeEnd);
const drawGraphEnd = html.indexOf("\n    function renderGraphInfo()", canvasResizeEnd);
assert.notEqual(drawGraphEnd, -1, "renderGraphInfo() must follow drawGraph()");
const drawGraphSource = html.slice(canvasResizeEnd, drawGraphEnd);

function evaluateGraphSearch(query) {
  const controls = {
    graphDepth: { value: "0" },
    graphView: { value: "global" },
    isolateCommunity: { checked: false },
    graphSearch: { value: query },
  };
  const graph = {
    nodes: [
      { document_id: 1, title: "Alpha", relative_path: "alpha.md", community: 1 },
      { document_id: 2, title: "Beta", relative_path: "beta.md", community: 1 },
      { document_id: 3, title: "Gamma", relative_path: "gamma.md", community: 2 },
    ],
    edges: [{ source: 1, target: 2, kind: "explicit" }],
  };
  const run = new Function("$", "graph", "selected", `${visibleGraphSource}; return visibleGraph();`);
  return run((id) => controls[id], graph, null);
}

function evaluateVisibleGraph(graph, selectedId, { depth = "0", view = "global", query = "", isolate = false } = {}) {
  const controls = {
    graphDepth: { value: depth },
    graphView: { value: view },
    isolateCommunity: { checked: isolate },
    graphSearch: { value: query },
  };
  const run = new Function("$", "graph", "selected", `${visibleGraphSource}; return visibleGraph();`);
  return run((id) => controls[id], graph, selectedId);
}

function evaluateGraphKeyboardTarget(graph, selectedId, direction, { depth = "0", view = "global", query = "" } = {}) {
  const controls = {
    graphDepth: { value: depth },
    graphView: { value: view },
    isolateCommunity: { checked: false },
    graphSearch: { value: query },
  };
  const run = new Function("$", "graph", "selected", "direction", `${visibleGraphSource}; return graphKeyboardTarget(direction);`);
  return run((id) => controls[id], graph, selectedId, direction);
}

function renderGraphInfo(graph, selectedId) {
  const side = {
    innerHTML: "",
    querySelector: () => ({ addEventListener() {} }),
    querySelectorAll: () => [],
  };
  const run = new Function(
    "$", "graph", "selected", "side", `${escapeSource}; ${graphInfoSource}; renderGraphInfo(); return side.innerHTML;`,
  );
  return run((id) => id === "graphInfo" ? side : null, graph, selectedId, side);
}

test("non-matching graph search shows no nodes instead of falling back to the full graph", () => {
  const result = evaluateGraphSearch("not-present");
  assert.equal(result.nodes.length, 0);
  assert.equal(result.edges.length, 0);
  assert.equal(result.matches.size, 0);
});

test("complete inline dashboard JavaScript parses without external dependencies", () => {
  const inlineScripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
  assert.ok(inlineScripts.length > 0, "dashboard must include its local application script");
  for (const source of inlineScripts) assert.doesNotThrow(() => new Function(source));
});

test("narrow dashboard layouts stack the command center and reduce graph canvas height", () => {
  const css = html.match(/<style>([\s\S]*?)<\/style>/)?.[1] ?? "";
  assert.match(css, /@media\s*\(max-width:\s*840px\)[^{]*\{[\s\S]*?\.nc-command-center[^{}]*\{\s*grid-template-columns:\s*minmax\(0,1fr\)/);
  const narrow = css.match(/@media\s*\(max-width:\s*600px\)\s*\{([\s\S]*?)\n\s*\}/)?.[1] ?? "";
  assert.notEqual(narrow, "", "dashboard must define a narrow-screen breakpoint");
  assert.match(narrow, /header\s*\{[^}]*flex-direction:\s*column/);
  assert.match(narrow, /#graph\s*\{[^}]*height:\s*min\(62vh,\s*420px\)/);
  assert.match(narrow, /#graph\s*\{[^}]*min-height:\s*280px/);
});

test("graph redraws avoid reallocating an unchanged canvas backing store", () => {
  assert.match(drawGraphSource, /syncCanvasBackingStore\(canvas,rect\.width,rect\.height,dpr\)/);
  assert.doesNotMatch(drawGraphSource, /canvas\.width=Math\.round\(rect\.width\*dpr\)/);
  const run = new Function("canvas", "width", "height", "dpr", `${canvasResizeSource}; return syncCanvasBackingStore(canvas,width,height,dpr);`);
  let width = 300;
  let height = 150;
  let writes = 0;
  const canvas = {
    get width() { return width; },
    set width(value) { writes += 1; width = value; },
    get height() { return height; },
    set height(value) { writes += 1; height = value; },
  };
  assert.equal(run(canvas, 640, 300, 1), true);
  assert.deepEqual([width, height, writes], [640, 300, 2]);
  assert.equal(run(canvas, 640, 300, 1), false);
  assert.equal(writes, 2, "same-size redraw must not reset either canvas dimension");
  assert.equal(run(canvas, 640, 300, 2), true, "DPR changes must refresh the backing store");
  assert.deepEqual([width, height, writes], [1280, 600, 4]);
  assert.equal(run(canvas, 420, 300, 2), true, "CSS size changes must refresh the backing store");
  assert.deepEqual([width, height, writes], [840, 600, 5]);
});

test("dashboard marks partial document-search matches without trusting response markup", () => {
  const label = new Function(`${searchMatchSource}; return searchMatchLabel;`)();
  assert.equal(label({ matched_terms: 4, total_terms: 5, complete: false }), "Coincidencia parcial: 4/5 términos");
  assert.equal(label({ matched_terms: 5, total_terms: 5, complete: true }), "");
  assert.equal(label({ matched_terms: "<img>", total_terms: 5, complete: false }), "");
  assert.match(html, /esc\(searchMatchLabel\(r\.query_match\)\)/);
});

test("dashboard text and interactive boundaries meet WCAG AA contrast targets", () => {
  assert.ok(Object.keys(theme).length >= 8, "theme color tokens must remain parseable");
  const textPairs = [
    ["main text/background", theme.text, theme.bg],
    ["main text/card", theme.text, "#0d141b"],
    ["main text/input", theme.text, "#0d141c"],
    ["main text/button", theme.text, "#173327"],
    ["muted text/background", theme.muted, theme.bg],
    ["muted text/gradient", theme.muted, "#162533"],
    ["muted text/card", theme.muted, "#0d141b"],
    ["accent/results", theme.accent, "#0d141b"],
    ["warning/snippet", theme.warn, "#0d141b"],
    ["error/card", theme.bad, "#0d141b"],
    ["snippet/card", "#cad5df", "#0d141b"],
    ["badge/background", "#a8c7dd", "#203143"],
    ["audit code/card", "#f0d18a", "#0d141b"],
    ["pre/background", "#cfe1ee", theme.bg],
  ];
  for (const [label, foreground, background] of textPairs) {
    assert.ok(contrastRatio(foreground, background) >= 4.5, `${label} must be at least 4.5:1`);
  }
  assert.ok(contrastRatio(theme.line, "#0d141b") >= 3, "result/card boundaries must be at least 3:1");
  assert.ok(contrastRatio(theme.line, "#121d27") >= 3, "graph-neighbor controls must be at least 3:1");
  assert.ok(contrastRatio(theme["control-border"], "#0d141c") >= 3, "form borders must be at least 3:1");
  assert.ok(contrastRatio(theme["button-border"], "#173327") >= 3, "button border must contrast with its fill");
  assert.ok(contrastRatio(theme["button-border"], "#1e4939") >= 3, "button border must remain visible on hover");
  assert.match(html, /input:focus-visible,\s*select:focus-visible,\s*button:focus-visible,\s*\.result\[role="button"\]:focus-visible\s*\{[^}]*outline:\s*2px solid var\(--accent\)/s);
  assert.doesNotMatch(html, /\.source-item\.disabled\s*\{[^}]*opacity\s*:/, "disabled source metadata must not be dimmed below readable contrast");
});

test("dashboard scan history is bounded, refreshable, and renders untrusted fields as text", () => {
  class Element {
    children = [];
    textContent = "";
    className = "";
    attributes = {};
    replaceChildren(...items) { this.children = items; }
    append(...items) { this.children.push(...items); }
    setAttribute(name, value) { this.attributes[name] = value; }
  }
  const elements = new Map([["scanHistory", new Element()], ["scanHistoryStatus", new Element()]]);
  const document = { createElement: () => new Element() };
  const render = new Function("$", "document", `${scanHistorySource}; return renderScanHistory;`)(
    (id) => elements.get(id), document,
  );
  const scans = Array.from({ length: 12 }, (_, index) => ({
    scan_id: index + 1, status: "ok", started_at: `2026-10-13T00:00:${String(index).padStart(2, "0")}+00:00`,
    added: index, modified: 1, unchanged: 20, removed: 0, skipped: 0, errors: 0, duration_ms: 12.4,
    absolute_path: "C:\\PRIVATE_PATH_SENTINEL", error_message: "PRIVATE_ERROR_SENTINEL",
  }));
  scans[1].errors = 2;
  scans[3].status = "partial";
  scans[3].source_summary = { obsidian: { errors: 1 }, "../PRIVATE_PATH_SENTINEL": { errors: 99 } };
  scans[4].source_summary_truncated = true;
  scans[2].status = "<img src=x onerror=alert(1)>";
  render(scans);
  const list = elements.get("scanHistory");
  const text = list.children.flatMap((item) => [item.textContent, ...item.children.map((child) => child.textContent)]).join(" ");
  assert.equal(list.children.length, 10, "the UI must cap rendering even if an endpoint returns more records");
  assert.match(elements.get("scanHistoryStatus").textContent, /10 ejecuciones recientes/);
  assert.match(text, /#1 · Completado/);
  assert.match(text, /#2 · Completado con errores/);
  assert.match(text, /#3 · Estado desconocido/);
  assert.match(text, /#4 · Parcial · revisar fuentes/);
  assert.match(text, /Fuentes con error: obsidian \(1\)/);
  assert.match(text, /Detalle de fuentes truncado/);
  assert.doesNotMatch(text, /PRIVATE_PATH_SENTINEL|PRIVATE_ERROR_SENTINEL|onerror=|\.\.\//);
  assert.doesNotMatch(scanHistorySource, /innerHTML|insertAdjacentHTML/, "untrusted scan values must be assigned with textContent");
  assert.match(html, /id="scanHistoryRefresh"/);
  assert.match(html, /id="scanHistory"[^>]*role="list"[^>]*aria-label="Diez indexaciones más recientes"/);
  assert.match(html, /id="scanHistoryStatus"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(html, /\$\('scanHistoryRefresh'\)\.addEventListener\('click',loadScans\)/);
  assert.match(html, /api\('\/api\/scans'\)/);
  assert.match(html, /async function loadStats\(\).*await loadScans\(\)/);
  assert.match(html, /Último índice: \$\{scanStatusLabel\(s\.latest_scan\)\}/);
  render([]);
  assert.match(elements.get("scanHistoryStatus").textContent, /No hay indexaciones/);
});

test("dashboard stats summary executes and calls out a partial latest scan", async () => {
  const elements = new Map([
    ["stats", { innerHTML: "" }],
    ["scan", { textContent: "" }],
  ]);
  const calls = [];
  const sourceFailures = new Function("scanMetric", `${sourceFailuresSource}; return scanSourceFailures;`)(
    (value) => String(value),
  );
  const run = new Function(
    "$", "api", "loadScans", "loadDocumentChanges", "scanStatusLabel", "scanSourceFailures", "statCard",
    `${statsLoaderSource}; return loadStats;`,
  )(
    (id) => elements.get(id),
    async (route) => {
      calls.push(route);
      return {
        documents_active: 337, relations_resolved: 42, relations_suggested: 3,
        projects: 3, links_broken: 1, links_directories: 0, unique_tags: 8,
        latest_scan: {
          status: "partial", errors: 1, finished_at: "2026-10-13T12:30:00Z",
          added: 0, modified: 0, unchanged: 337,
          source_summary: { obsidian: { errors: 1 }, "<img src=x>": { errors: 7 } },
        },
      };
    },
    async () => calls.push("scans"),
    async () => calls.push("changes"),
    (scan) => scan.status === "partial" ? "Parcial · revisar fuentes" : "Estado desconocido",
    sourceFailures,
    (value, label) => `<span>${value}:${label}</span>`,
  );
  await run();
  assert.match(elements.get("scan").textContent, /^Último índice: Parcial · revisar fuentes · 2026-10-13T12:30:00Z/);
  assert.match(elements.get("scan").textContent, /Fuentes con error: obsidian \(1\)/);
  assert.doesNotMatch(elements.get("scan").textContent, /<img/);
  assert.match(elements.get("scan").textContent, /· =337 · Fuentes con error:/);
  assert.deepEqual(calls, ["/api/stats", "scans", "changes"]);
});

test("dashboard document changes are bounded, source-cited, and rendered only as text", () => {
  class Element {
    constructor(tag = "div") { this.tag = tag; this.children = []; this.textContent = ""; this.className = ""; this.attributes = {}; this.listeners = {}; }
    replaceChildren(...items) { this.children = items; }
    append(...items) { this.children.push(...items); }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(name, listener) { this.listeners[name] = listener; }
  }
  const elements = new Map([["documentChanges", new Element()], ["documentChangesStatus", new Element()]]);
  const created = [];
  const document = { createElement: (tag) => { const element = new Element(tag); created.push(element); return element; } };
  const render = new Function("$", "document", `${documentChangesSource}; return renderDocumentChanges;`)(
    (id) => elements.get(id), document,
  );
  const changes = Array.from({ length: 25 }, (_, index) => ({
    change_id: index + 1, change_type: index === 0 ? "added" : index === 1 ? "modified" : index === 2 ? "toString" : "modified",
    reason: index === 2 ? "constructor" : "content_changed",
    occurred_at: `2026-10-13T00:00:${String(index).padStart(2, "0")}+00:00`, document_id: index + 1,
    title: index === 0 ? "<img src=x onerror=alert(1)>" : `Nota ${index}`, source_kind: "obsidian",
    relative_path: `Notas/${index}.md`, document_status: "active", absolute_path: "C:\\PRIVATE_PATH_SENTINEL",
  }));
  render(changes);
  const list = elements.get("documentChanges"), allText = list.children.flatMap((item) => [item.textContent, ...item.children.map((child) => child.textContent)]).join(" ");
  assert.equal(list.children.length, 20, "UI must cap rendered changes at 20");
  assert.match(elements.get("documentChangesStatus").textContent, /20 cambios recientes/);
  assert.match(allText, /Alta · <img src=x onerror=alert\(1\)>/);
  assert.match(allText, /El contenido cambió/);
  assert.match(allText, /Cambio registrado · Nota 2/);
  assert.match(allText, /Motivo registrado/);
  assert.doesNotMatch(allText, /PRIVATE_PATH_SENTINEL/);
  assert.equal(created.some((element) => element.tag === "img"), false, "untrusted titles must never become DOM markup");
  assert.doesNotMatch(documentChangesSource, /innerHTML|insertAdjacentHTML/);
  assert.match(html, /id="documentChanges"[^>]*role="list"[^>]*aria-label="Veinte cambios de documentos más recientes"/);
  assert.match(html, /id="documentChangesStatus"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(html, /id="documentChangesRefresh"/);
  assert.match(html, /params\.set\('project_id',\$\('documentChangeProject'\)\.value\)/);
  assert.match(html, /api\(`\/api\/changes\?\$\{params\.toString\(\)\}`\)/);
  assert.ok(html.includes("$('documentChangeProject').addEventListener('change',loadDocumentChanges)"));
  assert.match(html, /'documentChangeProject'/, "project selector must be populated from active projects");
  assert.match(html, /\$\('documentChangesRefresh'\)\.addEventListener\('click',loadDocumentChanges\)/);
  render([]);
  assert.match(elements.get("documentChangesStatus").textContent, /No hay cambios de documentos registrados/);
});

test("3D graph node palette remains distinguishable when search dims neighbor nodes", () => {
  assert.match(html, /return `hsl\(\$\{h%360\},64%,66%\)`;/, "graph colors must remain deterministically generated from category/source hues");
  const dimAlphaMatch = html.match(/ctx\.globalAlpha=dim\?\.(\d+):/);
  assert.ok(dimAlphaMatch, "search-neighbor node opacity must be explicit");
  const dimAlpha = Number.parseFloat(`0.${dimAlphaMatch[1]}`);
  assert.ok(dimAlpha < 0.82, "non-matching neighbors must remain visibly dimmer than ordinary nodes");
  const canvasBackgroundMatch = html.match(/ctx\.fillStyle='#([0-9a-fA-F]{6})';ctx\.fillRect\(0,0,w,h\)/);
  assert.ok(canvasBackgroundMatch, "graph renderer must expose its actual solid canvas background to the contrast check");
  const background = Array.from({ length: 3 }, (_, index) => Number.parseInt(canvasBackgroundMatch[1].slice(index * 2, index * 2 + 2), 16));
  const hslColor = (hue) => {
    const saturation = 0.64, lightness = 0.66, a = saturation * Math.min(lightness, 1 - lightness);
    const channel = (offset) => {
      const k = (offset + hue / 30) % 12;
      return Math.round(255 * (lightness - a * Math.max(-1, Math.min(k - 3, 9 - k, 1))));
    };
    return [channel(0), channel(8), channel(4)];
  };
  const contrast = (first, second) => {
    const luminance = (rgb) => {
      const [r, g, b] = rgb.map((value) => {
        const srgb = value / 255;
        return srgb <= 0.04045 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const values = [luminance(first), luminance(second)].sort((a, b) => b - a);
    return (values[0] + 0.05) / (values[1] + 0.05);
  };
  let minimum = Infinity;
  let minimumHue = -1;
  for (let hue = 0; hue < 360; hue += 1) {
    const fill = hslColor(hue);
    const composited = fill.map((channel, index) => Math.round(dimAlpha * channel + (1 - dimAlpha) * background[index]));
    const ratio = contrast(composited, background);
    assert.ok(ratio >= 3, `hue ${hue} falls below 3:1 in the search-neighbor state`);
    if (ratio < minimum) {
      minimum = ratio;
      minimumHue = hue;
    }
  }
  assert.ok(minimum >= 3.05, `minimum palette contrast must retain margin above 3:1 (hue ${minimumHue}: ${minimum.toFixed(2)}:1)`);
});

test("knowledge graph exposes keyboard guidance and live accessible node details", () => {
  const canvas = html.match(/<canvas\b[^>]*\bid="graph"[^>]*>/)?.[0] ?? "";
  assert.match(canvas, /\btabindex="0"/);
  assert.match(canvas, /\brole="group"/);
  assert.match(canvas, /aria-roledescription="visualización interactiva"/);
  assert.match(canvas, /aria-label="[^"]*flechas[^"]*Enter[^"]*Escape[^"]*"/);
  assert.match(canvas, /aria-describedby="graphStatus"/);
  assert.match(html, /id="graphStatus" role="status" aria-live="polite"/);
  assert.match(html, /<aside\b[^>]*\bid="graphInfo"[^>]*aria-live="polite"/);
  assert.match(html, /canvas\.addEventListener\('keydown'/);
  assert.match(html, /data-neighbor=/);
});

test("graph truncation is reported without exposing index paths or content", () => {
  const start = html.indexOf("    function graphTruncationNotice(");
  const end = html.indexOf("\n", start);
  assert.notEqual(start, -1, "graph truncation notice helper must exist");
  const source = html.slice(start, end);
  const notice = new Function(`${source}; return graphTruncationNotice;`)();
  assert.equal(notice({ truncated: false }), "");
  assert.equal(notice({ truncated: true, total_matches: 999, private_path: "C:\\private\\note.md" }), " · límite alcanzado; la vista puede estar incompleta");
  assert.match(html, /scopeNotice=graphTruncationNotice\(graph\)/);
});

test("dashboard graph cap is user-adjustable within the API limit", () => {
  const select = html.match(/<select id="graphLimit">([\s\S]*?)<\/select>/)?.[1] ?? "";
  assert.match(select, /value="100"/);
  assert.match(select, /value="250"/);
  assert.match(select, /value="500" selected/);
  assert.match(select, /value="1000"/);
  const start = html.indexOf("    async function loadGraph(){");
  const end = html.indexOf("\n    function renderSourceFilters(", start);
  assert.notEqual(start, -1, "loadGraph() must exist");
  assert.match(html.slice(start, end), /limit:Number\(\$\('graphLimit'\)\.value\)/);
  assert.match(html, /\$\('graphLimit'\)\.addEventListener\('change',loadGraph\)/);
});

test("only the latest graph request may replace the visible graph", () => {
  const gateStart = html.indexOf("    function createLatestRequestGate(){");
  const gateEnd = html.indexOf("\n", gateStart);
  assert.notEqual(gateStart, -1, "graph request gate must exist");
  const createGate = new Function(`${html.slice(gateStart, gateEnd)}; return createLatestRequestGate;`)();
  const gate = createGate();
  const firstRequest = gate.begin();
  assert.equal(gate.isCurrent(firstRequest), true);
  const secondRequest = gate.begin();
  assert.equal(gate.isCurrent(firstRequest), false);
  assert.equal(gate.isCurrent(secondRequest), true);
  const loadStart = html.indexOf("    async function loadGraph(){");
  const loadEnd = html.indexOf("\n    function renderSourceFilters(", loadStart);
  const loadSource = html.slice(loadStart, loadEnd);
  assert.match(loadSource, /const requestId=graphRequestGate\.begin\(\)/);
  assert.match(loadSource, /const nextGraph=await postJson\('\/api\/graph',p\);if\(!graphRequestGate\.isCurrent\(requestId\)\)return;graph=nextGraph/);
  assert.match(loadSource, /catch\(error\)\{if\(graphRequestGate\.isCurrent\(requestId\)\)/);
  assert.match(loadSource, /documentRequestGate\.begin\(\).*La selección ya no está en la vista actual del grafo/);
});

test("only the latest document detail request may replace the visible document", async () => {
  const gateStart = html.indexOf("    function createLatestRequestGate(){");
  const gateEnd = html.indexOf("\n", gateStart);
  const showStart = html.indexOf("    async function showDoc(id){");
  const showEnd = html.indexOf("\n    function hashColor(", showStart);
  assert.notEqual(gateStart, -1, "latest-request gate must exist");
  assert.notEqual(showStart, -1, "showDoc() must exist");
  const deferred = () => {
    let resolve;
    let reject;
    const promise = new Promise((accept, decline) => { resolve = accept; reject = decline; });
    return { promise, resolve, reject };
  };
  const requests = new Map();
  const detail = { innerHTML: "" };
  const makeApp = () => new Function("api", "$", "esc", "drawGraph", "renderGraphInfo", `
    ${html.slice(gateStart, gateEnd)}
    const documentRequestGate = createLatestRequestGate();
    let selected = null;
    ${html.slice(showStart, showEnd)}
    return { showDoc, selected: () => selected, setSelected: (id) => { selected = id; } };
  `)(
    (url) => {
      const id = Number(url.split("/").at(-1));
      const pending = deferred();
      requests.set(id, pending);
      return pending.promise;
    },
    (selector) => selector === "detail" ? detail : { addEventListener() {} },
    (value) => String(value ?? ""),
    () => {},
    () => {},
  );
  const app = makeApp();
  const first = app.showDoc(1);
  const second = app.showDoc(2);
  requests.get(2).resolve({ title: "Documento reciente", frontmatter: {}, links: [], incoming_links: [] });
  await second;
  assert.match(detail.innerHTML, /Documento reciente/);
  requests.get(1).resolve({ title: "Documento obsoleto", frontmatter: {}, links: [], incoming_links: [] });
  await first;
  assert.match(detail.innerHTML, /Documento reciente/);
  assert.doesNotMatch(detail.innerHTML, /Documento obsoleto/);
  assert.equal(app.selected(), 2);

  const staleFailure = app.showDoc(3);
  const newest = app.showDoc(4);
  requests.get(4).resolve({ title: "Último documento", frontmatter: {}, links: [], incoming_links: [] });
  await newest;
  requests.get(3).reject(new Error("respuesta antigua"));
  await staleFailure;
  assert.match(detail.innerHTML, /Último documento/);
  assert.doesNotMatch(detail.innerHTML, /respuesta antigua/);

  const clearedSelection = app.showDoc(5);
  app.setSelected(null);
  requests.get(5).resolve({ title: "Documento no seleccionado", frontmatter: {}, links: [], incoming_links: [] });
  await clearedSelection;
  assert.match(detail.innerHTML, /La selección cambió mientras se cargaba/);

  const currentFailure = app.showDoc(6);
  requests.get(6).reject(new Error("fallo actual"));
  await currentFailure;
  assert.match(detail.innerHTML, /fallo actual/);
});

test("only the latest search response may replace the search results", async () => {
  const gateStart = html.indexOf("    function createLatestRequestGate(){");
  const gateEnd = html.indexOf("\n", gateStart);
  const searchStart = html.indexOf("    async function search(){");
  const searchEnd = html.indexOf("\n    async function retrieve(", searchStart);
  assert.notEqual(gateStart, -1, "latest-request gate must exist");
  assert.notEqual(searchStart, -1, "search() must exist");
  assert.notEqual(searchEnd, -1, "retrieve() must follow search()");
  const deferred = () => {
    let resolve;
    const promise = new Promise((accept) => { resolve = accept; });
    return { promise, resolve };
  };
  const requests = new Map();
  const results = { innerHTML: "" };
  let query = "viejo";
  const createGate = new Function(`${html.slice(gateStart, gateEnd)}; return createLatestRequestGate;`)();
  const search = new Function("postJson", "$", "document", "esc", "searchMatchLabel", "searchParams", "searchRequestGate", `${html.slice(searchStart, searchEnd)}; return search;`)(
    (_path, payload) => {
      const pending = deferred();
      requests.set(payload.q, pending);
      return pending.promise;
    },
    (id) => id === "results" ? results : { value: query },
    { querySelectorAll: () => [] },
    (value) => String(value ?? ""),
    () => "",
    () => ({ q: query }),
    createGate(),
  );
  const oldRequest = search();
  query = "nuevo";
  const newRequest = search();
  requests.get("nuevo").resolve({ results: [{ document_id: 2, title: "Resultado nuevo", category: "", source_kind: "local", relative_path: "nuevo.md", snippet: "nuevo" }] });
  await newRequest;
  assert.match(results.innerHTML, /Resultado nuevo/);
  requests.get("viejo").resolve({ results: [{ document_id: 1, title: "Resultado viejo", category: "", source_kind: "local", relative_path: "viejo.md", snippet: "viejo" }] });
  await oldRequest;
  assert.match(results.innerHTML, /Resultado nuevo/);
  assert.doesNotMatch(results.innerHTML, /Resultado viejo/);
});

test("only the latest context retrieval may replace the cited context", async () => {
  const gateStart = html.indexOf("    function createLatestRequestGate(){");
  const gateEnd = html.indexOf("\n", gateStart);
  const retrieveStart = html.indexOf("    async function retrieve(){");
  const retrieveEnd = html.indexOf("\n    async function loadDecisions(", retrieveStart);
  assert.notEqual(gateStart, -1, "latest-request gate must exist");
  assert.notEqual(retrieveStart, -1, "retrieve() must exist");
  const deferred = () => {
    let resolve;
    let reject;
    const promise = new Promise((accept, decline) => { resolve = accept; reject = decline; });
    return { promise, resolve, reject };
  };
  const requests = new Map();
  const context = { textContent: "" };
  let query = "viejo";
  const createGate = new Function(`${html.slice(gateStart, gateEnd)}; return createLatestRequestGate;`)();
  const retrieve = new Function("postJson", "$", "searchParams", "contextRequestGate", `${html.slice(retrieveStart, retrieveEnd)}; return retrieve;`)(
    (_path, payload) => {
      const pending = deferred();
      requests.set(payload.q, pending);
      return pending.promise;
    },
    () => context,
    () => ({ q: query }),
    createGate(),
  );
  const oldRequest = retrieve();
  query = "nuevo";
  const newRequest = retrieve();
  requests.get("nuevo").resolve({ fragments: [{ title: "Contexto nuevo", heading: "Diseño", line_start: 3, line_end: 4, text: "evidencia nueva", citation: "project:README.md#L3-L4" }] });
  await newRequest;
  requests.get("viejo").reject(new Error("respuesta antigua"));
  await oldRequest;
  assert.match(context.textContent, /Contexto nuevo/);
  assert.match(context.textContent, /project:README\.md#L3-L4/);
  assert.doesNotMatch(context.textContent, /respuesta antigua|Contexto viejo/);
});

test("only the latest decision query may replace the decision list", async () => {
  const gateStart = html.indexOf("    function createLatestRequestGate(){");
  const gateEnd = html.indexOf("\n", gateStart);
  const decisionsStart = html.indexOf("    async function loadDecisions(){");
  const decisionsEnd = html.indexOf("\n    async function openDoc(", decisionsStart);
  assert.notEqual(gateStart, -1, "latest-request gate must exist");
  assert.notEqual(decisionsStart, -1, "loadDecisions() must exist");
  const deferred = () => {
    let resolve;
    let reject;
    const promise = new Promise((accept, decline) => { resolve = accept; reject = decline; });
    return { promise, resolve, reject };
  };
  const requests = new Map();
  const records = { innerHTML: "" };
  let query = "viejo";
  const createGate = new Function(`${html.slice(gateStart, gateEnd)}; return createLatestRequestGate;`)();
  const loadDecisions = new Function("postJson", "$", "document", "esc", "decisionRequestGate", `${html.slice(decisionsStart, decisionsEnd)}; return loadDecisions;`)(
    (_path, payload) => {
      const pending = deferred();
      requests.set(payload.q, pending);
      return pending.promise;
    },
    (id) => id === "decisionRecords" ? records : { value: id === "decisionQuery" ? query : "" },
    { querySelectorAll: () => [] },
    (value) => String(value ?? ""),
    createGate(),
  );
  const oldRequest = loadDecisions();
  query = "nuevo";
  const newRequest = loadDecisions();
  requests.get("nuevo").resolve({ records: [{ title: "Decisión reciente", project: "Proyecto", record_type: "decision", status: "confirmed", validation: "passed", recorded_date: "2026-10-13", relative_path: "decisions/001.md", evidence: ["project:README.md"], document_id: 2 }] });
  await newRequest;
  requests.get("viejo").reject(new Error("respuesta antigua"));
  await oldRequest;
  assert.match(records.innerHTML, /Decisión reciente/);
  assert.match(records.innerHTML, /project:README\.md/);
  assert.doesNotMatch(records.innerHTML, /respuesta antigua|Decisión vieja/);
});

test("only the latest scan history response may replace the scan list", async () => {
  const gateStart = html.indexOf("    function createLatestRequestGate(){");
  const gateEnd = html.indexOf("\n", gateStart);
  const scansStart = html.indexOf("    async function loadScans(){");
  const scansEnd = html.indexOf("\n    const documentChangeLabels=", scansStart);
  assert.notEqual(scansStart, -1, "loadScans() must exist");
  const deferred = () => {
    let resolve;
    let reject;
    const promise = new Promise((accept, decline) => { resolve = accept; reject = decline; });
    return { promise, resolve, reject };
  };
  const requests = [];
  const rendered = [];
  const elements = { scanHistory: { replaceChildren() {} }, scanHistoryStatus: { textContent: "" } };
  const createGate = new Function(`${html.slice(gateStart, gateEnd)}; return createLatestRequestGate;`)();
  const loadScans = new Function("api", "renderScanHistory", "$", "scanHistoryRequestGate", `${html.slice(scansStart, scansEnd)}; return loadScans;`)(
    () => { const pending = deferred(); requests.push(pending); return pending.promise; },
    (scans) => rendered.push(scans),
    (id) => elements[id],
    createGate(),
  );
  const oldRequest = loadScans();
  const newRequest = loadScans();
  requests[1].resolve({ scans: ["scan-new"] });
  await newRequest;
  requests[0].reject(new Error("stale scan failure"));
  await oldRequest;
  assert.deepEqual(rendered, [["scan-new"]]);
  assert.equal(elements.scanHistoryStatus.textContent, "");
});

test("only the latest project filter may replace the document change list", async () => {
  const gateStart = html.indexOf("    function createLatestRequestGate(){");
  const gateEnd = html.indexOf("\n", gateStart);
  const changesStart = html.indexOf("    async function loadDocumentChanges(){");
  const changesEnd = html.indexOf("\n    async function loadStats(", changesStart);
  assert.notEqual(changesStart, -1, "loadDocumentChanges() must exist");
  const deferred = () => {
    let resolve;
    let reject;
    const promise = new Promise((accept, decline) => { resolve = accept; reject = decline; });
    return { promise, resolve, reject };
  };
  const requests = [];
  const rendered = [];
  const project = { value: "project-old" };
  const elements = { documentChanges: { replaceChildren() {} }, documentChangesStatus: { textContent: "" } };
  const createGate = new Function(`${html.slice(gateStart, gateEnd)}; return createLatestRequestGate;`)();
  const loadChanges = new Function("api", "renderDocumentChanges", "$", "documentChangesRequestGate", `${html.slice(changesStart, changesEnd)}; return loadDocumentChanges;`)(
    (url) => { const pending = deferred(); requests.push({ url, pending }); return pending.promise; },
    (changes) => rendered.push(changes),
    (id) => id === "documentChangeProject" ? project : elements[id],
    createGate(),
  );
  const oldRequest = loadChanges();
  project.value = "project-new";
  const newRequest = loadChanges();
  assert.match(requests[1].url, /project_id=project-new/);
  requests[1].pending.resolve({ changes: ["new-project-change"] });
  await newRequest;
  requests[0].pending.reject(new Error("stale change failure"));
  await oldRequest;
  assert.deepEqual(rendered, [["new-project-change"]]);
  assert.equal(elements.documentChangesStatus.textContent, "");
});

test("graph detail renderer escapes hostile document and neighbor titles", () => {
  const graph = {
    nodes: [
      {
        document_id: 1,
        title: "<img src=x onerror=alert(1)>",
        source_kind: "projects",
        category: "projects/fixture",
        project_name: "fixture",
        relative_path: "README.md",
        mtime_iso: "",
        degree: 1,
        community: 1,
      },
      { document_id: 2, title: '\"><svg/onload=alert(2)>', relative_path: "neighbor.md" },
      { document_id: 3, title: "Suggested <em>node</em>", relative_path: "suggested.md" },
    ],
    edges: [
      { source: 1, target: 2, kind: "explicit" },
      { source: 1, target: 3, kind: "suggested" },
    ],
  };
  const markup = renderGraphInfo(graph, 1);
  assert.doesNotMatch(markup, /<img\b|<svg\b/i);
  assert.match(markup, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(markup, /&quot;&gt;&lt;svg\/onload=alert\(2\)&gt;/);
  assert.match(markup, /<button type="button" data-neighbor="2"/);
  assert.match(markup, /aria-label="Relación explícita: &quot;&gt;&lt;svg\/onload=alert\(2\)&gt;"/);
  assert.match(markup, /aria-label="Relación sugerida \(hipótesis\): Suggested &lt;em&gt;node&lt;\/em&gt;"/);
});

test("matching graph search shows matching nodes and their immediate neighbors", () => {
  const result = evaluateGraphSearch("Alpha");
  assert.deepEqual(result.nodes.map((node) => node.document_id), [1, 2]);
  assert.equal(result.edges.length, 1);
  assert.deepEqual([...result.matches], [1]);
});

test("public graph nodes show cited evidence without offering local file opening", () => {
  const graph = {nodes: [{document_id: -42, entity_id: 'CVE-2024-12345', entity_kind: 'vulnerability',
    title: '<img src=x>', source_kind: 'cyber', category: 'vulnerability', summary: '<script>data</script>',
    reference_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345', degree: 0}], edges: []};
  const markup = renderGraphInfo(graph, -42);
  assert.doesNotMatch(markup, /data-open-selected|<img\b|<script\b/);
  assert.match(markup, /Consultar referencia pública/);
  assert.match(markup, /no demuestran cumplimiento ni aplicabilidad/);
  assert.match(markup, /&lt;script&gt;data&lt;\/script&gt;/);
});

test("selecting a public CVE uses the public detail event, never the local document endpoint", () => {
  const selectSource = html.slice(html.indexOf('    function selectNode(id){')).split('\n')[0];
  const detail = {textContent: ''}, events = [], privateCalls = [];
  class Event {constructor(type, options) {this.type = type; this.detail = options.detail;}}
  const choose = new Function('graph','document','$','CustomEvent','showDoc', `
    let selected=null; const documentRequestGate={begin(){}},drawGraph=()=>{},renderGraphInfo=()=>{};
    ${selectSource}; return {choose:selectNode,current:()=>selected};
  `)({nodes:[{document_id:-42,entity_kind:'vulnerability',entity_id:'CVE-2024-12345',title:'CVE fixture',summary:'Public data'}]},
    {dispatchEvent:event=>events.push(event)},()=>detail,Event,id=>privateCalls.push(id));
  choose.choose(-42);
  assert.equal(choose.current(),-42); assert.equal(privateCalls.length,0);
  assert.equal(events[0].detail.id,'CVE-2024-12345');
});

test("public graph requests do not reuse project filters or private source scope", async () => {
  const loadStart=html.indexOf('    async function loadGraph(){'),loadEnd=html.indexOf('\n    function updateGraphDomain',loadStart);
  const controls={graphLimit:{value:'250'},suggestions:{checked:true},minDegree:{value:'0'},graphDomain:{value:'cyber'},
    graphProvider:{value:'nvd'},graphSearch:{value:'CVE-2024-12345'},graphSource:{value:'projects'},graphProject:{value:'private-project-id'}};
  let payload;
  const load=new Function('$','postJson',`
    let graph={nodes:[],edges:[]},positions=new Map(),selected=null;
    const graphRequestGate={begin:()=>1,isCurrent:()=>true},documentRequestGate={begin(){}},computeCommunities=()=>{},seedLayout=()=>{},drawGraph=()=>{},renderGraphInfo=()=>{};
    ${html.slice(loadStart,loadEnd)};return loadGraph;
  `)(id=>controls[id],async (_url,body)=>{payload=body;return {nodes:[],edges:[]};});
  await load();
  assert.equal(payload.domain,'cyber'); assert.equal(payload.provider,'nvd');
  assert.equal(payload.q,'CVE-2024-12345'); assert.equal(payload.project_id,undefined); assert.equal(payload.source,undefined);
});

test("graph depth shows only one or two explicit neighborhood hops", () => {
  const graph = {
    nodes: [1, 2, 3, 4].map((document_id) => ({ document_id, community: 1 })),
    edges: [
      { source: 1, target: 2, kind: "explicit" },
      { source: 2, target: 3, kind: "explicit" },
      { source: 3, target: 4, kind: "explicit" },
    ],
  };
  const oneHop = evaluateVisibleGraph(graph, 1, { depth: "1" });
  const twoHops = evaluateVisibleGraph(graph, 1, { depth: "2" });
  assert.deepEqual(oneHop.nodes.map((node) => node.document_id), [1, 2]);
  assert.deepEqual(twoHops.nodes.map((node) => node.document_id), [1, 2, 3]);
  assert.deepEqual(twoHops.edges.map((edge) => [edge.source, edge.target]), [[1, 2], [2, 3]]);
});

test("document view defaults to one hop and community isolation intersects the selected neighborhood", () => {
  const graph = {
    nodes: [
      { document_id: 1, community: 7 }, { document_id: 2, community: 7 },
      { document_id: 3, community: 9 }, { document_id: 4, community: 7 },
    ],
    edges: [
      { source: 1, target: 2, kind: "explicit" },
      { source: 2, target: 3, kind: "explicit" },
      { source: 3, target: 4, kind: "explicit" },
    ],
  };
  const documentView = evaluateVisibleGraph(graph, 1, { view: "document" });
  const isolatedTwoHopView = evaluateVisibleGraph(graph, 1, { depth: "2", isolate: true });
  assert.deepEqual(documentView.nodes.map((node) => node.document_id), [1, 2]);
  assert.deepEqual(isolatedTwoHopView.nodes.map((node) => node.document_id), [1, 2]);
  assert.deepEqual(isolatedTwoHopView.edges.map((edge) => [edge.source, edge.target]), [[1, 2]]);
});

test("graph arrow navigation follows visible neighbors in stable title order", () => {
  const graph = {
    nodes: [
      { document_id: 1, title: "Alpha", relative_path: "alpha.md" },
      { document_id: 2, title: "Beta", relative_path: "beta.md" },
      { document_id: 3, title: "Gamma", relative_path: "gamma.md" },
      { document_id: 4, title: "Delta", relative_path: "delta.md" },
    ],
    edges: [
      { source: 1, target: 2, kind: "explicit" },
      { source: 1, target: 3, kind: "suggested" },
      { source: 3, target: 4, kind: "explicit" },
    ],
  };
  assert.equal(evaluateGraphKeyboardTarget(graph, 1, 1), 2);
  assert.equal(evaluateGraphKeyboardTarget(graph, 1, -1), 3);
  assert.equal(evaluateGraphKeyboardTarget(graph, 2, 1), 1);
});

test("graph arrows use the filtered neighborhood, then fall back to visible global order", () => {
  const graph = {
    nodes: [
      { document_id: 1, title: "Alpha", relative_path: "alpha.md" },
      { document_id: 2, title: "Beta", relative_path: "beta.md" },
      { document_id: 3, title: "Delta", relative_path: "delta.md" },
      { document_id: 4, title: "Gamma", relative_path: "gamma.md" },
    ],
    edges: [
      { source: 1, target: 2, kind: "explicit" },
      { source: 1, target: 4, kind: "explicit" },
    ],
  };
  assert.equal(evaluateGraphKeyboardTarget(graph, 1, 1, { query: "Beta" }), 2);
  assert.equal(evaluateGraphKeyboardTarget(graph, 3, 1), 4);
  assert.equal(evaluateGraphKeyboardTarget(graph, 3, -1), 2);
  assert.equal(evaluateGraphKeyboardTarget(graph, null, 1), 1);
  assert.equal(evaluateGraphKeyboardTarget(graph, null, -1), 4);
  assert.equal(evaluateGraphKeyboardTarget(graph, 1, 1, { query: "not-present" }), null);
});

function evaluateCommunities(edges) {
  const graph = {
    nodes: [1, 2, 3, 4, 5, 6].map((document_id) => ({ document_id })),
    edges,
  };
  const run = new Function("graph", `${communitySource}; computeCommunities(); return graph.nodes.map((node) => node.community);`);
  return run(graph);
}

test("community detection groups explicit components and ignores suggested edges", () => {
  const explicit = [
    { source: 1, target: 2, kind: "explicit" },
    { source: 2, target: 3, kind: "explicit" },
    { source: 3, target: 1, kind: "explicit" },
    { source: 4, target: 5, kind: "explicit" },
    { source: 5, target: 6, kind: "explicit" },
    { source: 6, target: 4, kind: "explicit" },
  ];
  const communities = evaluateCommunities(explicit);
  const withSuggestion = evaluateCommunities([...explicit, { source: 3, target: 4, kind: "suggested" }]);
  assert.equal(communities[0], communities[1]);
  assert.equal(communities[1], communities[2]);
  assert.equal(communities[3], communities[4]);
  assert.equal(communities[4], communities[5]);
  assert.notEqual(communities[0], communities[3]);
  assert.deepEqual(withSuggestion, communities);
});

function evaluateLabels(nodes, positions, selectedId, neighbors, matches, width = 500, height = 320) {
  const context = { font: "", measureText: (text) => ({ width: String(text).length * 7 }) };
  const run = new Function("ctx", "nodes", "positions", "selectedId", "neighbors", "matches", "width", "height", `${labelSource}; return layoutGraphLabels(ctx,nodes,positions,selectedId,neighbors,matches,1,width,height);`);
  return run(context, nodes, positions, selectedId, neighbors, matches, width, height);
}

function rectanglesOverlap(a, b, gap = 3) {
  return a.x < b.x + b.width + gap && a.x + a.width + gap > b.x && a.y < b.y + b.height + gap && a.y + a.height + gap > b.y;
}

test("graph labels avoid other label boxes and visible node circles", () => {
  const nodes = [
    { document_id: 1, title: "Selected architecture note", degree: 8 },
    { document_id: 2, title: "Neighbor about persistent memory", degree: 5 },
    { document_id: 3, title: "Another connected record", degree: 3 },
    { document_id: 4, title: "Nearby independent node", degree: 1 },
  ];
  const positions = new Map([
    [1, { x: 200, y: 150, radius: 8 }], [2, { x: 228, y: 150, radius: 8 }],
    [3, { x: 215, y: 184, radius: 6 }], [4, { x: 180, y: 150, radius: 6 }],
  ]);
  const labels = evaluateLabels(nodes, positions, 1, new Set([2, 3]), new Set());
  assert.ok(labels.has(1), "the selected node remains the first label candidate");
  const entries = [...labels.entries()];
  for (let i = 0; i < entries.length; i += 1) {
    const [id, label] = entries[i];
    for (let j = i + 1; j < entries.length; j += 1) assert.equal(rectanglesOverlap(label.box, entries[j][1].box), false);
    for (const other of nodes) {
      if (other.document_id === id) continue;
      const point = positions.get(other.document_id);
      const x = Math.max(label.box.x, Math.min(point.x, label.box.x + label.box.width));
      const y = Math.max(label.box.y, Math.min(point.y, label.box.y + label.box.height));
      const clearance = point.radius + 2;
      assert.ok((point.x - x) ** 2 + (point.y - y) ** 2 >= clearance ** 2, `label for ${id} overlaps node ${other.document_id}`);
    }
  }
});

test("dense graph searches cap label candidates according to available canvas area", () => {
  const nodes = Array.from({ length: 48 }, (_, index) => ({ document_id: index + 1, title: `Node ${index + 1}`, degree: index % 9 }));
  const positions = new Map(nodes.map((node, index) => [node.document_id, { x: 35 + (index % 8) * 108, y: 30 + Math.floor(index / 8) * 58, radius: 4 }]));
  const labels = evaluateLabels(nodes, positions, 40, new Set(), new Set(nodes.map((node) => node.document_id)), 900, 400);
  assert.ok(labels.size <= 15, `expected at most 15 labels on this canvas, got ${labels.size}`);
  assert.ok(labels.has(40), "selected node has priority over search-match labels");
});

test("audit dashboard status distinguishes absent targets from live unindexed targets", () => {
  const run = new Function("data", `${auditSummarySource}; return auditSummary(data);`);
  const summary = run({
    counts: { documents_index_drift: 2, links_broken: 3, links_ambiguous: 1, documents_with_inactive_search_payload: 12, project_dependency_manifest_errors: 4, documents_with_unclosed_sensitive_blocks: 0 },
    missing_link_path_state_counts: { not_present_on_disk: 2, live_markdown_not_indexed: 1, multiple_live_path_candidates: 1 },
    quality_score: 86,
  });
  assert.match(summary, /2 fuentes fuera de sincronía/);
  assert.match(summary, /3 enlaces rotos/);
  assert.match(summary, /2 destinos ausentes/);
  assert.match(summary, /2 existentes sin indexar\/ambiguos/);
  assert.match(summary, /4 manifiestos por revisar/);
  assert.match(summary, /12 documentos inactivos con texto retenido/);
  assert.match(html, /documents_with_inactive_search_payload','Texto en documentos inactivos/);
  assert.match(summary, /0 candidatas de contradicción/);
  const partial = run({
    counts: { contradiction_candidates: 2 },
    contradiction_scan_summary: { coverage_complete: false, findings_truncated: false, documents_skipped_by_document_budget: 1 },
    missing_link_path_state_counts: {}, quality_score: 90,
  });
  assert.match(partial, /contradicciones con cobertura parcial \(1 fuentes omitidas\)/);
  const claimLimited = run({
    counts: { contradiction_candidates: 0 },
    contradiction_scan_summary: { coverage_complete: false, claim_budget_exhausted: true, claim_limit: 400 },
    missing_link_path_state_counts: {}, quality_score: 90,
  });
  assert.match(claimLimited, /contradicciones con cobertura parcial \(límite de 400 afirmaciones únicas\)/);
  const truncated = run({
    counts: { contradiction_candidates: 50 },
    contradiction_scan_summary: { coverage_complete: false, findings_truncated: true },
    missing_link_path_state_counts: {}, quality_score: 90,
  });
  assert.match(truncated, /lista de contradicciones truncada/);
});

test("index-drift dashboard shows bounded metadata only and a coverage status", () => {
  class Element {
    children = [];
    textContent = "";
    className = "";
    handler = null;
    replaceChildren() { this.children = []; }
    append(...items) { this.children.push(...items); }
    addEventListener(_event, handler) { this.handler = handler; }
  }
  const elements = new Map([["auditIndexDrift", new Element()]]);
  const document = { createElement: () => new Element() };
  const render = new Function("$", "document", `${driftSource}; return renderIndexDrift;`)(
    (id) => elements.get(id), document,
  );
  render({
    index_drift_summary: { active_documents: 3, checked_documents: 2, bytes_hashed: 40, documents_skipped_by_budget: 1, coverage_complete: false, findings_truncated: true },
    index_drift_findings: [{ document_id: 7, title: "Nota", source_kind: "obsidian", relative_path: "Árbol/Nota Ñ.md", status: "content_changed_same_metadata" }],
  });
  const text = elements.get("auditIndexDrift").children.flatMap((item) => [item.textContent, ...item.children.map((child) => child.textContent)]).join(" ");
  assert.match(text, /2\/3 documentos comprobados/);
  assert.match(text, /Cobertura parcial/);
  assert.match(text, /Árbol\/Nota Ñ\.md/);
  assert.match(text, /Cambió el contenido aunque tamaño\/fecha coincidan/);
  assert.match(text, /Abrir nota original/);
  assert.match(text, /lista de hallazgos está limitada/);
});

function evaluateSourceFilters(sources, previous) {
  const controls = Object.fromEntries(["source", "graphSource"].map((id) => [id, {
    value: previous,
    options: [],
    replaceChildren() { this.options = []; this.value = ""; },
    append(option) { this.options.push(option); if (this.options.length === 1) this.value = option.value; },
  }]));
  const document = { createElement: () => ({ value: "", textContent: "" }) };
  const run = new Function("$", "document", "sources", `${sourceFiltersSource}; renderSourceFilters(sources); return [$("source"), $("graphSource")];`);
  return run((id) => controls[id], document, sources);
}

test("dashboard source filters include enabled custom roots and preserve valid selection", () => {
  const sources = [
    { kind: "obsidian", name: "Vault", enabled: true },
    { kind: "research", name: "Investigación 1", enabled: true },
    { kind: "research", name: "Investigación 2", enabled: true },
    { kind: "archive", name: "Archivo", enabled: false },
  ];
  const [search, graph] = evaluateSourceFilters(sources, "research");
  for (const select of [search, graph]) {
    assert.equal(select.value, "research");
    assert.deepEqual(select.options.map((option) => option.value), ["", "obsidian", "research"]);
    assert.equal(select.options.at(-1).textContent, "Investigación 1 · 2 carpetas");
  }
  const [afterDisable] = evaluateSourceFilters(sources, "archive");
  assert.equal(afterDisable.value, "");
});

test("active project inventory opens its indexed memory profile and excluded projects expose no action", () => {
  const render = (project) => {
    const created = [];
    const panel = {
      children: [],
      replaceChildren() { this.children = []; },
      append(...items) { this.children.push(...items); },
    };
    const controls = {
      projectPolicy: { value: String(project.project_id) },
      toggleProjectExclusion: {},
      projectInventory: panel,
    };
    const document = {
      createElement(tag) {
        const element = {
          tagName: tag,
          children: [],
          listeners: {},
          append(...items) { this.children.push(...items); },
          setAttribute(name, value) { this[name] = value; },
          addEventListener(name, callback) { this.listeners[name] = callback; },
        };
        created.push(element);
        return element;
      },
    };
    const opened = [];
    new Function("$", "document", "policyProjects", "showDoc", `${projectPanelSource}; updateProjectPolicyLabel();`)(
      (id) => controls[id], document, [project], (id) => opened.push(id),
    );
    return { created, controls, opened };
  };

  const active = render({ project_id: 7, name: "Demo Ñ <b>", status: "active", memory_document_id: 42 });
  const button = active.created.find((item) => item.textContent === "Abrir ficha de memoria");
  assert.ok(button);
  assert.equal(button["aria-label"], "Abrir ficha de memoria de Demo Ñ <b>");
  button.listeners.click();
  assert.deepEqual(active.opened, [42]);

  const excluded = render({ project_id: 7, name: "Demo", status: "excluded", memory_document_id: 42 });
  assert.equal(excluded.created.some((item) => item.textContent === "Abrir ficha de memoria"), false);
  assert.match(excluded.controls.projectInventory.children[1].textContent, /Proyecto excluido/);
});

test("dashboard explains link resolution categories without treating clues as repairs", () => {
  const run = new Function(`${auditLabelsSource}; return [auditClassificationLabel({status:"broken",reason:"invalid_absolute_path"}), auditClassificationLabel({status:"external",reason:"external_reference"}), auditClassificationLabel({status:"ignored",reason:"intentional_placeholder"})];`);
  assert.deepEqual(run(), [
    "Ruta absoluta inválida",
    "Referencia externa",
    "Marcador intencional/incompleto",
  ]);
  assert.match(html, /Solo revisión: no se cambió el enlace/);
});
