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
  └─ POST /api/open/{id} ─> server-authorized open ─> original source
```

The UI never accepts an arbitrary filesystem path. Imported titles, excerpts, YAML values and labels are rendered as text. Search content is sent in POST bodies and is not persisted in browser storage. Only presentation preferences (theme and graph/layout options) are stored locally.

## Views and truthful grouping

- **Neural Orbit:** deterministic radial Canvas 2D projection of the current API graph; only returned edges are drawn. Explicit and suggested relations remain distinguishable. The view supports pan/zoom, selection, keyboard traversal, search, project/source/category filters, neighborhood depth, degree threshold and a bounded node count. Hover and keyboard selection show the same metadata preview; source references are validated as relative paths before display.
- **Hex Knowledge:** selectable group cards derived from source/project/category metadata. The optional connected-component mode uses explicit graph edges only. This is grouping, not a claim of semantic community detection.
- **Knowledge Galaxy 3D:** reuses and reparents the existing dashboard graph canvas and its controls. It is the legacy implementation, not a newly introduced WebGL engine.
- **Knowledge Tree:** groups by known project metadata and lists explicit relations; it does not fabricate project architecture levels.
- **Inspector:** reads document metadata and bounded context fragments; original paths are shown only as relative citations. Current API does not provide the complete Markdown body, so full in-app document reading remains pending.

## Limits and extension seams

`normalizeCommandGraph`, `orbitCoordinates`, `groupCommandNodes` and `explicitAdjacency` are pure functions for validation and deterministic projections. The UI caps graph requests at the backend API limit (1000) and reports truncation. There is currently no typed cross-entity Knowledge Graph API or authorized full-document-content API on the tested branch. Those contracts are specified in `FRONTEND_BACKEND_CONTRACT.md`; keep the current document graph as fallback until those endpoints exist and are reviewed.

The new panel is responsive and its splitters support keyboard and pointer use. Visual verification so far is at a 1265×715 viewport; exact 1080p/1440p, browser zoom, screen-reader, and large real-index performance certification remain open.
