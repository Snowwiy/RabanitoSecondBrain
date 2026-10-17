# Frontend ↔ backend contract (FrontEnd-Design base)

## Tested boundary

This worktree starts at `4474bfc91bcc8145b1573dfa36831c5626c5fd76`. It does not contain the concurrent, uncommitted changes in the original checkout. Do not copy backend files from that checkout or call indexing/sync operations from UI tests.

All frontend requests use same-origin `127.0.0.1` endpoints exposed by the current server. The server validates Host/Origin and body limits. Private search terms are POST JSON, never query parameters or `localStorage`.

| Operation | Request | Verified response/use |
|---|---|---|
| Health/stats | `GET /api/health`, `GET /api/stats` | Loopback policy and real counts/latest scan; no fixture values in production. |
| Project/category inventory | `GET /api/projects`, `/api/categories`, `/api/tags` | `projects[]` includes numeric `project_id`, `name`, active/excluded `status`, relative path, and bounded safe metadata; category/tag values are local index data. |
| Global search | `POST /api/search` `{q, limit, source?, category?, project_id?, tag?}` | `{results[]}` with document ID, title, source/category/project metadata, relative path, FTS snippet and match coverage. UI uses `textContent`. |
| Cited context | `POST /api/context` `{q, limit, max_chars, source?, category?, project_id?, tag?}` | `{fragments[],characters,limit,max_chars}`. A fragment carries document ID/title/heading/text/line range/source/project/category/relative path/citation. API removes query and absolute paths from its dashboard response. |
| Document metadata | `GET /api/doc/{positive-id}` | Safe document metadata, tags/frontmatter, outgoing/incoming link metadata. Does **not** return Markdown content. |
| Full Markdown reader | `POST /api/doc/content` `{document_id: positive int, max_bytes: <=65536}` | **Not available in the tested production branch.** The UI sends this request only after the user clicks “Leer documento completo”; the synthetic fixture alone provides a clearly labeled sample response. |
| Related docs | `GET /api/related/{positive-id}` | `{results[]}` bounded relation records. |
| Document graph | `POST /api/graph` `{domain:'documents',limit<=1000,q?,source?,project_id?,category?,suggestions,min_degree?}` | `{nodes[],edges[],node_limit,total_matches,truncated}`. Nodes are active visible documents; paths are relative and private absolute roots are stripped. Edges have explicit/suggested `kind`; suggestions are excluded by default. |
| Safe source opening | `POST /api/open/{positive-id}` `{}` | Server resolves the indexed active document and re-validates its authorized root before asking the OS to open it. UI never accepts a filesystem path. |
| Decision/Coding/Security/Cyber panels | Existing POST endpoints in the current dashboard | Continue using `web/knowledge.js`, `web/cyber.js` and legacy handlers; new center opens the existing panels instead of replacing those APIs. |

## Neural Command Center behavior

- Neural Orbit uses only `/api/graph` nodes and edges; coordinates are a deterministic radial projection, not a source of semantic relations.
- Edge type is preserved. Suggested edges are user-enabled, dashed/orange, and never counted as confirmed.
- Hex grouping keys are verified project/category/source metadata. Optional “Componente conectado” is computed from explicit graph edges only and is not described as semantic community detection.
- Tree uses `project_name` as a metadata group and lists explicit graph edges separately. It does not fabricate architecture/component levels.
- `KNOWLEDGE GALAXY 3D` reparents the existing graph controls and canvas in the browser DOM. Its backend/API contract remains the existing `/api/graph` implementation.
- Inspector queries `/api/doc/{id}` and then a capped `/api/context` request, displaying citation path and line range. The optional full Markdown adapter is user-triggered and sends an ID plus byte limit to `/api/doc/content`; a 404 explains that the production backend has not implemented it. The parser builds a bounded DOM from a Markdown subset, treats raw HTML as text, allows only HTTP(S) external links, and resolves internal document links only from returned authorized references. No Markdown body is stored in browser preferences.

## Pending typed Knowledge Graph API

The current frontend branch has no `/api/knowledge-graph` endpoint. The backend work concurrent in the original checkout is not part of this base, so the UI intentionally does not assume its response schema. When that backend is integrated, feature-detect through a read-only GET/POST query endpoint; do not invoke a sync route from view loading.

Recommended read response:

```json
{
  "projection_available": true,
  "nodes": [{"id":"doc:123","entity_kind":"document","title":"…","category":"…","source_kind":"obsidian","project_id":null,"validation":"source-backed","updated_at":"…","citation":{"relative_path":"…","line_start":1,"line_end":3}}],
  "edges": [{"source":"doc:123","target":"project:7","relation_type":"belongs_to","kind":"explicit","validation":"source-backed","citation":"…"}],
  "total_matches": 1,
  "truncated": false
}
```

Requirements: omit absolute roots and credentials; distinguish explicit, derived, and suggested validation; enforce active-project visibility server-side; include bounded metadata/citations; reject oversized filters; return stable typed IDs. The frontend must retain the current `/api/graph` fallback until this endpoint is committed and integration-tested.

## Required authorized document-content API

The branch tested by this worktree has no document-body endpoint. For integration, implement the following read-only endpoint in the backend and review it independently:

`POST /api/doc/content` with `{ "document_id": 123, "max_bytes": 65536 }`.

The server must accept only a positive indexed document ID and a `max_bytes` value in `1..65536`; it must never accept a filesystem path. It must resolve the active, visible document from the index, recheck source/project authorization and root/reparse-point/symlink protections immediately before reading, enforce the byte cap while reading, decode UTF-8 safely, and return no private absolute roots, credentials, or unrestricted filesystem metadata. If content is truncated, the response must cut at a valid UTF-8 boundary.

Required response shape:

```json
{
  "document_id": 123,
  "content_markdown": "# …",
  "bytes_returned": 2048,
  "truncated": false,
  "references": [{
    "target_document_id": 456,
    "title": "…",
    "target_raw": "…",
    "relative_path": "…",
    "status": "resolved"
  }]
}
```

`references` must be bounded and resolved by the backend; relative paths must not contain absolute roots or parent traversal. The browser validates the selected document ID, response fields and UTF-8 byte count. It renders a restricted Markdown subset with DOM APIs only: raw HTML remains text; external links accept HTTP(S) without credentials; internal links navigate only to IDs in the response references. Unknown local links are inert text. The fixture endpoint is test-only, synthetic, loopback-bound and visibly marked; it is not evidence of production backend support.

## Error and degradation behavior

- 404/400/413: show a bounded inline status; never retry writes automatically.
- 409: explain a conflict without treating stale data as refreshed.
- Network/5xx/timeout: retain selection only when still present, show stale/error status, and allow explicit retry.
- Missing typed KG or content endpoints: disclose “pendiente”; do not synthesize nodes, content, or counts.
- Fixture server sets `fixture:true` and `X-Rabanito-Fixture`; UI must show the synthetic-only banner whenever fixture stats or graph data is observed.
