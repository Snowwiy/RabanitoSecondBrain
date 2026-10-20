# Neural Command Center — UI architecture

## Runtime boundary

The UI remains a static, same-origin client in `web/index.html` and `web/knowledge.js`; there is no new package manager, CDN, telemetry, or external service. Existing dashboard and cybersecurity behavior stays in place. At boot, the command center moves the legacy graph canvas and the rest of the existing dashboard into their respective view/workbench containers rather than duplicating backend functionality.

## Data flow

```text
local dashboard server
  ├─ GET /api/stats, /api/projects, /api/categories
  ├─ POST /api/graph ──> bounded graph projection ──> Orbit / Hex / Tree
  ├─ POST /api/search ─> text-only result rows ─────> selection
  ├─ GET /api/doc/{id} ─> metadata ─────────────────> Inspector
  ├─ POST /api/context ─> capped cited fragments ───> Inspector
  ├─ POST /api/doc/content ─> optional capped body ──> safe Markdown reader
  └─ POST /api/open/{id} ─> server-authorized open ─> original source
```

The UI never accepts an arbitrary filesystem path. Imported titles, excerpts, YAML values and labels are rendered as text. Search content is sent in POST bodies and is not persisted in browser storage. Only presentation preferences (theme and graph/layout options) are stored locally.

## Views and truthful grouping

- **Neural Orbit:** deterministic radial Canvas 2D projection of the current API graph; only returned edges are drawn. Explicit and suggested relations remain distinguishable. The view supports pan/zoom, selection, keyboard traversal, search, project/source/category filters, neighborhood depth, degree threshold and a bounded node count. Hover and keyboard selection show the same metadata preview; source references are validated as relative paths before display. Adjacency, components and unchanged coordinate layouts are reused between redraws.
- **Hex Knowledge:** selectable group cards derived from source/project/category metadata. The optional connected-component mode uses explicit graph edges only. This is grouping, not a claim of semantic community detection.
- **Knowledge Galaxy 3D:** reuses and reparents the existing dashboard graph canvas and its controls. It is the legacy Canvas 2D renderer with 3D projection/rotation, not a newly introduced WebGL engine. Its node-ID, node lookup and adjacency index are cached for the currently loaded graph; each redraw still traverses visible nodes and edges.
- **Knowledge Tree:** groups by known project metadata and lists explicit relations; it does not fabricate project architecture levels.
- **Inspector:** reads document metadata and bounded context fragments; original paths are shown only as relative citations. A user-triggered reader calls the integrated `POST /api/doc/content` route with only the selected indexed ID and a 65,536-byte budget. The route rechecks source authorization and freshness, reads through a read-only bounded handle, and never accepts a caller path or triggers reindexing. It was exercised through loopback HTTP against authorized Obsidian, project and internal-memory documents; browser QA rendered real Obsidian Markdown with metadata and 100 recognized references. Errors retain metadata and cited context. The parser constructs a bounded DOM subset without `innerHTML`; raw HTML stays text, unsafe/unknown URLs stay inert, and internal navigation requires a returned authorized reference ID. Search highlighting modifies text nodes in the loaded document and is not persisted.

## Limits and extension seams

`normalizeCommandGraph`, `orbitCoordinates`, `groupCommandNodes`, `explicitAdjacency` and `parseSafeMarkdown` are pure functions for validation and deterministic projections. The UI caps graph requests at the backend API limit (1000) and reports truncation. The authorized Markdown body endpoint is now integrated and verified against real authorized sources. There is still no typed cross-entity Knowledge Graph API; keep the current document graph and topology-labeled fallback until a typed read contract is reviewed and integrated.

The new panel is responsive and its splitters support keyboard and pointer use. Neural Orbit also exposes a collapsed native node list with 25 entries per page and keyboard-operable selection. Geometry checks at 1920×1080, 2560×1440 and 380×787 found no horizontal overflow; full-width captures are capped at 1280px. Browser zoom, screen-reader and large real-index performance certification remain open. A synthetic 1,000-node render smoke completed, but no frame-time or memory profile was captured. The master mission and acceptance criteria are recorded in `UI_MASTER_SPEC.md`; capability evidence and remaining work are tracked in `UI_TASK_BACKLOG.md`.
