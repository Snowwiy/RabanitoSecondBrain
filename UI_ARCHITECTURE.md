# Neural Command Center — UI architecture

## Runtime boundary

The UI remains a static, same-origin client in `web/index.html` and `web/knowledge.js`; there is no new package manager, CDN, telemetry, or external service. Existing dashboard and cybersecurity behavior stays in place. At boot, the command center moves the legacy graph canvas and the rest of the existing dashboard into their respective view/workbench containers rather than duplicating backend functionality.

## Data flow

```text
local dashboard server
  ├─ GET /api/stats, /api/projects, /api/categories
  ├─ POST /api/graph ──> bounded document graph ─────> Orbit / Hex / Tree
  ├─ POST /api/knowledge-graph ─> typed projection ─> Orbit / Hex / Tree
  ├─ POST /api/knowledge-graph/neighbors ──────────> one-hop expansion
  ├─ POST /api/search ─> text-only result rows ─────> selection
  ├─ GET /api/doc/{id} ─> metadata ─────────────────> Inspector
  ├─ POST /api/context ─> capped cited fragments ───> Inspector
  ├─ POST /api/doc/content ─> optional capped body ──> safe Markdown reader
  └─ POST /api/open/{id} ─> server-authorized open ─> original source
```

The UI never accepts an arbitrary filesystem path. Imported titles, excerpts, YAML values and labels are rendered as text. The explicitly confirmed derived-graph refresh uses an app-owned modal dialog; cancel or Escape does not submit the write. Search content is sent in POST bodies and is not persisted in browser storage. Only presentation preferences (theme and graph/layout options) are stored locally.

## Views and truthful grouping

- **Neural Orbit:** deterministic radial Canvas 2D projection of the current API graph; only returned edges are drawn. Explicit and suggested relations remain distinguishable. The view supports pan/zoom, selection, keyboard traversal, search, project/source/category filters, neighborhood depth, degree threshold and a bounded node count. Hover and keyboard selection show the same metadata preview; source references are validated as relative paths before display. Adjacency, components and unchanged coordinate layouts are reused between redraws.
- **Hex Knowledge:** selectable group cards derived from source/project/category metadata. The optional connected-component mode uses explicit graph edges only. This is grouping, not a claim of semantic community detection.
- **Knowledge Galaxy 3D:** reuses and reparents the existing dashboard graph canvas and its controls. It is the legacy Canvas 2D renderer with 3D projection/rotation, not a newly introduced WebGL engine. Its node-ID, node lookup and adjacency index are cached for the currently loaded graph; each redraw still traverses visible nodes and edges.
- **Knowledge Tree:** groups by known project metadata and lists explicit relations; it does not fabricate project architecture levels.
- **Inspector:** reads document metadata and bounded context fragments; original paths are shown only as relative citations. A user-triggered reader calls the integrated `POST /api/doc/content` route with only the selected indexed ID and a 65,536-byte budget. The route rechecks source authorization and freshness, reads through a read-only bounded handle, and never accepts a caller path or triggers reindexing. It was exercised through loopback HTTP against authorized Obsidian, project and internal-memory documents; browser QA rendered real Obsidian Markdown with metadata and 100 recognized references. Errors retain metadata and cited context. The parser constructs a bounded DOM subset without `innerHTML`; raw HTML stays text, unsafe/unknown URLs stay inert, and internal navigation requires a returned authorized reference ID. Search highlighting modifies text nodes in the loaded document and is not persisted.

## Limits and extension seams

`normalizeCommandGraph`, `orbitCoordinates`, `groupCommandNodes`, `explicitAdjacency` and `parseSafeMarkdown` are pure functions for validation and deterministic projections. Document graph requests remain capped at 1,000 records; typed pages are capped at 200 and the accumulated UI graph at 1,000 nodes / 4,000 edges. Typed cursors retain their page size across continuation and are not replaced by one-hop neighbor responses. The authorized Markdown body endpoint and typed cross-entity graph API are integrated; read paths do not synchronize sources.

The panel and splitters support responsive, keyboard and pointer use. Neural Orbit exposes a collapsed native node list with 25 entries per page and keyboard-operable selection. This integration's visual QA was limited to the in-app browser's narrow viewport; earlier 1920×1080 / 2560×1440 captures belong to a prior frontend-only checkpoint and do not certify the combined build. Browser zoom, screen-reader and large real-index browser frame-time/heap certification remain open. A synthetic large-input Node smoke is not a browser paint profile. The master mission and acceptance criteria are recorded in `UI_MASTER_SPEC.md`; capability evidence and remaining work are tracked in `UI_TASK_BACKLOG.md`.
