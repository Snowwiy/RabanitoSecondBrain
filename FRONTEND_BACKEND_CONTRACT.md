# Frontend ↔ backend contract (FrontEnd-Design base)

## Tested boundary

This branch preserves the Neural Command Center frontend while selectively integrating the authorized reader from published `origin/main` commit `5109981a794a41bb7b646beca61ad11045f18ea5`. The original worktree and its unrelated local changes remain outside this integration.

All frontend requests use same-origin `127.0.0.1` endpoints exposed by the current server. The server validates Host/Origin and body limits. Private search terms are POST JSON, never query parameters or `localStorage`.

| Operation | Request | Verified response/use |
|---|---|---|
| Health/stats | `GET /api/health`, `GET /api/stats` | Loopback policy and real counts/latest scan; no fixture values in production. |
| Project/category inventory | `GET /api/projects`, `/api/categories`, `/api/tags` | `projects[]` includes numeric `project_id`, `name`, active/excluded `status`, relative path, and bounded safe metadata; category/tag values are local index data. |
| Global search | `POST /api/search` `{q, limit, source?, category?, project_id?, tag?}` | `{results[]}` with document ID, title, source/category/project metadata, relative path, FTS snippet and match coverage. UI uses `textContent`. |
| Cited context | `POST /api/context` `{q, limit, max_chars, source?, category?, project_id?, tag?}` | `{fragments[],characters,limit,max_chars}`. A fragment carries document ID/title/heading/text/line range/source/project/category/relative path/citation. API removes query and absolute paths from its dashboard response. |
| Document metadata | `GET /api/doc/{positive-id}` | Safe document metadata, tags/frontmatter, outgoing/incoming link metadata. Does **not** return Markdown content. |
| Authorized Markdown reader | `POST /api/doc/content` `{document_id: safe positive int, max_bytes: 1..65536}` | Integrated into this branch from `origin/main`; the UI requests a sanitized, read-only view only after “Leer Markdown”. The synthetic fixture is test-only. |
| Related docs | `GET /api/related/{positive-id}` | `{results[]}` bounded relation records. |
| Document graph | `POST /api/graph` `{domain:'documents',limit<=1000,q?,source?,project_id?,category?,suggestions,min_degree?}` | `{nodes[],edges[],node_limit,total_matches,truncated}`. Nodes are active visible documents; paths are relative and private absolute roots are stripped. Edges have explicit/suggested `kind`; suggestions are excluded by default. |
| Typed Knowledge Graph page | `POST /api/knowledge-graph` `{kind,limit<=200,q?,source?,category?,project_id?,cursor?,suggestions?,risk?,since?,until?,include_inactive?}` | Stable typed nodes and classified/cited relations, `coverage`, keyset cursor and `total_candidates`; strict same-origin POST. |
| Typed one-hop neighbors | `POST /api/knowledge-graph/neighbors` with page filters plus selected `id` | Authorized anchor, bounded neighbor nodes/edges and next cursor; client caps accumulated view at 1,000 nodes/4,000 edges. |
| Explicit graph refresh | `POST /api/knowledge-graph/sync` `{confirm_graph_sync:true,max_inputs<=1000,max_bytes<=33554432}` | One user-confirmed projection batch. View loading and page/neighbor reads never trigger synchronization. |
| Safe source opening | `POST /api/open/{positive-id}` `{}` | Server resolves the indexed active document and re-validates its authorized root before asking the OS to open it. UI never accepts a filesystem path. |
| Decision/Coding/Security/Cyber panels | Existing POST endpoints in the current dashboard | Continue using `web/knowledge.js`, `web/cyber.js` and legacy handlers; new center opens the existing panels instead of replacing those APIs. |

## Neural Command Center behavior

- Neural Orbit uses only `/api/graph` nodes and edges; coordinates are a deterministic radial projection, not a source of semantic relations.
- Edge type is preserved. Suggested edges are user-enabled, dashed/orange, and never counted as confirmed.
- Hex grouping keys are verified project/category/source metadata. Optional “Componente conectado” is computed from explicit graph edges only and is not described as semantic community detection.
- In Knowledge Graph mode, Orbit, Hex and Tree preserve stable typed IDs, all 32 current entity kinds, provenance, citations and four distinct relation classes. Type filters are localized; typed Tree groups by the published type and lists classified relationships separately.
- Tree uses `project_name` as a metadata group in document mode and lists explicit graph edges separately. It does not fabricate architecture/component levels.
- `KNOWLEDGE GALAXY 3D` reparents the existing graph controls and canvas in the browser DOM. Its backend/API contract remains the existing `/api/graph` implementation.
- Inspector queries `/api/doc/{id}` and then a capped `/api/context` request, displaying citation path and line range. “Leer Markdown” sends only the selected indexed ID and byte budget to `/api/doc/content`. The response is a bounded, read-only text view that may redact detectable credentials and absolute paths; it is not an exact export or universal secret detector. The parser builds a bounded DOM from a Markdown subset, treats raw HTML as text, allows only HTTP(S) external links, and resolves internal document links only from returned authorized references. No Markdown body is stored in browser preferences.

## Typed Knowledge Graph API — integrated on `Frontend-Design`

The isolated branch selectively includes the typed projection, query and relationship modules from published `origin/main`, plus the strict loopback routes and focused tests. This is a selective dependency closure, not a merge of `main`. `/api/graph` remains the document-graph mode; `/api/knowledge-graph` is the typed cross-entity mode.

### Read and navigation requests

All routes are POST-only same-origin JSON requests bound to the loopback server. Graph URLs reject query strings, duplicate JSON keys, non-object bodies and unknown fields. The body cap is 16,384 bytes for page/neighbor requests and 2,048 bytes for the sync request. A page request accepts the following bounded fields:

```json
{"kind":"all","limit":180,"suggestions":false,"q":"optional","source":"optional","category":"optional","project_id":7,"cursor":"opaque"}
```

`kind` accepts the backend's 32 published entity kinds or `all`; `limit` is at most 200 per request. `project` and `project_id` are mutually exclusive. The cursor is bound to filters, authorization, projection generation and route operation. A response includes `schema_version`, `projection_available`, `nodes[]`, `edges[]`, `next_cursor`, `has_more`, `coverage`, `scope_note` and `source_filter_basis`; page responses also include `total_candidates` and `count_basis`. Node identifiers are stable typed IDs. Metadata and citations are bounded; absolute source roots are not returned.

`POST /api/knowledge-graph/neighbors` accepts the page fields plus the selected typed `id`. It returns `anchor_visible`, `hop_depth: 1`, visible endpoint nodes, classified/cited edges and an optional keyset cursor. The UI loads one hop on selection, caps each request at 200 edges and bounds the accumulated view at 1,000 nodes and 4,000 edges. It does not request or render the full 51,000+ candidate set at once. The first page is ordered by stable node ID; use a kind filter or “Cargar más entidades tipadas” to reach later types/pages.

The frontend exposes all 32 kinds published by `rabanito.knowledge_graph.query.KINDS`, with localized labels including ATT&CK records. Neural Orbit, Hex and Knowledge Tree retain the backend kind and stable ID. Hex and Tree display localized labels while keeping the raw kind as the filter key. Document nodes with an authorized `document_id` can use the existing Inspector reader; public/non-document entities cannot be opened as local files.

### Projection refresh and evidence classes

`POST /api/knowledge-graph/sync` accepts exactly `confirm_graph_sync: true` with optional bounded `max_inputs` and `max_bytes`. The UI only exposes this control when `coverage.requires_sync` is true and after a separate confirmation; it requests one batch of at most 1,000 inputs / 32 MiB and does not loop. Opening or filtering the graph is read-only. Sync writes only the derived Knowledge Graph projection; it never modifies Obsidian or project source files.

Edges retain distinct `explicit`, `suggested`, `inferred` and `reviewed_claim` classes plus validation and citation. Suggested edges are opt-in. Reviewed claims and inferred relationships are not presented as confirmed source facts. Topological communities in Orbit/Hex are computed only from loaded explicit links and remain estimates; the backend does not return semantic community labels. The `source` filter describes assertion origin, not project applicability. Imported records and their text are untrusted data.

Focused tests cover request/response contracts, read-only behavior, origin/field/duplicate-key rejection, authorization and exclusions, stale projection handling, cursors, explicit sync, provenance, relationship classes, large pages, transaction rollback and performance budgets. See `UI_TEST_RESULTS.md` for current run results and the real-index browser QA.

## `POST /api/doc/content` — reconciled and integrated contract

The route and reader implementation come from published `origin/main` commit `5109981a794a41bb7b646beca61ad11045f18ea5`; this branch imports only the document reader module, its route and focused tests. No database migration or schema change is required. The add/add conflict occurred because both branches created this contract independently; this section preserves the endpoint-specific security details while the API table, Neural Command Center behavior and typed-graph fallback above retain the UI branch's contracts.

### Request and transport

The request is exactly `{"document_id":123,"max_bytes":65536}`. Both fields are required; additional or duplicate JSON fields are rejected. `document_id` is an integer in `1..9007199254740991` (safe in JavaScript); `max_bytes` is an integer in `1..65536`. The route never accepts a path or private filter. Query strings, URL parameters, fragments, transfer-encoding/chunked bodies and duplicate framing headers are rejected. The UTF-8 JSON body is limited to 2,048 bytes.

Requests require one loopback `Host`, one `Origin` with matching loopback host and server port, and one `Content-Type: application/json` (optional parameters such as charset are accepted). `GET /api/doc/content` returns 405. Responses use `Cache-Control: no-store`; no CORS is added.

### Response

The response contains exactly these top-level fields. `bytes_returned` equals the UTF-8 byte length of `content_markdown` and does not exceed the request budget.

```json
{
  "document_id": 123,
  "content_markdown": "# …",
  "bytes_returned": 5,
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

### Read, freshness and source protection

- The result is a sanitized, untrusted text view, not an exact source export. Detectable credentials and absolute paths are replaced by visible markers. This is defense in depth, not universal DLP; configured source exclusions remain necessary. No extra `redacted` response field is introduced. The server does not interpret HTML, execute note text or load resources.
- At most `max_bytes` bytes are read from the source, and the returned UTF-8 text also stays within that budget. BOM and line endings are normalized. If the input is truncated, an incomplete last line is omitted so a partially read secret line is not returned. `truncated` reports source/output clipping, not redaction; a very small budget may return empty text.
- Current indexed state, enabled source, exclusion policy, active project visibility and nested-project boundaries are rechecked. The stored ID is resolved server-side; caller paths are never used. Reparse points/symlinks, path traversal, non-regular files and unsafe roots fail closed.
- The file is pinned through a read-only handle and its identity is rechecked around the bounded read. Windows uses `CreateFileW` with `OPEN_EXISTING`, read-only access, no write/delete sharing and final-handle path verification; POSIX opens each path component without following symlinks. No application is opened and no source or index write occurs.
- A full read is checked against the indexed content hash. A truncated prefix can only establish stable identity, size and modification time; it does not claim to hash the whole original. A changed/unavailable source returns 409 and is never reindexed automatically.
- References are capped at 512 explicit, resolved, active and currently authorized Markdown/wiki/embed links. Suggested, ambiguous, external and unsafe links are omitted. Each returned string is capped at 1,000 characters. References do not prove that the target content is fresh. The query selects only bounded authorization/reference fields; it does not materialize target frontmatter, tags or full error metadata.

### Errors and frontend behavior

Errors retain the stable body `{"error":"code"}` and never include input values, absolute roots or OS exception details:

| HTTP | Meaning | Inspector response |
|---|---|---|
| 400 | Invalid request or source encoding | Keep metadata/citations; report a bounded request/encoding error. |
| 403 | Loopback origin or JSON content type denied | Explain that the local same-origin request was rejected. |
| 404 | Missing, inactive or currently unauthorized document | Do not reveal whether a hidden document exists. |
| 409 | Source changed or became unavailable | Mark the view stale; do not treat it as refreshed or reindex automatically. |
| 413 | Configured source-size or read-size limit exceeded | Explain the bounded read limit and retain the rest of the Inspector. |
| 503 | Local index unavailable or authorization bound exceeded | Keep the Inspector usable; do not create or migrate the index. |

The browser accepts only the exact response/reference field sets, the selected safe ID, a matching UTF-8 byte count, and safe resolved relative references. The bounded Markdown parser creates DOM nodes only: raw HTML remains text, external links are HTTP(S) without credentials, and internal navigation targets only IDs from authorized response references. No Markdown body or query is stored in browser preferences. The synthetic endpoint remains fixture-only and never demonstrates real backend support.

### Published backend evidence (historical)

The `origin/main` contract and test record at `5109981a794a41bb7b646beca61ad11045f18ea5` report 35 endpoint regressions (including real Windows junction cases), 694 normal plus 694 optimized Python checks and 52 JavaScript checks. They also record loopback HTTP reads from Obsidian, projects and internal memory, frontend parser compatibility in memory, and source/database integrity checks. Those claims describe validation performed on `main`; the current Frontend-Design integration is separately verified in `UI_TEST_RESULTS.md` and do not imply that `main` was deployed.

## Error and degradation behavior

- 400/403/404/409/413/503: show the route-specific bounded inline state described above; never retry writes or refresh the index automatically.
- 409: explain that the indexed source changed or became unavailable without treating stale data as refreshed.
- Network/5xx/timeout: retain selection only when still present, show stale/error status, and allow explicit retry.
- Fixture server sets `fixture:true` and `X-Rabanito-Fixture`; UI must show the synthetic-only banner whenever fixture stats or graph data is observed.
