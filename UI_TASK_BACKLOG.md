# UI task backlog

## Completed in this branch checkpoint

- [x] Add three-panel Neural Command Center around the existing dashboard.
- [x] Add five themes and locally persisted visual preferences, excluding knowledge queries/content.
- [x] Implement real API-backed Orbit, metadata-grouped Hex, legacy Galaxy reuse, and metadata-grouped Tree.
- [x] Add bounded search, filters, keyboard/pointer navigation, selection, cited Inspector fragments and authorized source-open action.
- [x] Keep suggested relations distinct and avoid invented hierarchy/community claims.
- [x] Add local synthetic fixture server and pure-function/XSS-boundary tests.
- [x] Document current API boundary and integration limitations.
- [x] Run the original 64-test Node baseline and 290 Python tests (1 skipped); the current Node suite now has 66 tests, while Python is unchanged in the two frontend-only phases.
- [x] Capture the user-provided Neural Command Center mission and acceptance criteria in `UI_MASTER_SPEC.md`.
- [x] Bring the synthetic `/api/search` and `/api/graph` fixture into parity for source, project, category-prefix, query and exact-tag filtering; calculate graph totals after filtering.
- [x] Add an isolated API functional test proving each search/graph filter, combined filters and graph truncation; no production server or database is used.
- [x] Browser-verify Orbit source/project/category/query filtering and the dashboard's query/category/exact-tag/project combination against the updated synthetic fixture.
- [x] Run all 65 Node UI tests and `git diff --check`; the Python suite was not rerun because this phase changes only frontend test fixtures and UI continuity documents.
- [x] Add a collapsed, keyboard-operable Neural Orbit node directory capped at 25 buttons per page, with source metadata, selected state, live page count and previous/next navigation.
- [x] Verify the accessible node directory in the browser accessibility tree: selecting one of 3 nodes opens the Inspector; 1,000-node pagination showed entries 1–25 and 26–50, and keyboard Enter selected node 50 without losing focus.
- [x] Run all 66 Node UI tests and inspect the 1,000-node list visually; screen-reader and browser-zoom certification remain open.
- [x] Final synthetic browser smoke pass: search/selection/inspector, four view tabs, legacy graph mount, panel collapse/restore and preference disclosure.
- [x] Fix narrow search-card horizontal overflow and add a regression check.
- [x] Add an accessible clear action to global search; invalidate pending responses, reset the view, and return focus to the query field.
- [x] Add a Neural Orbit node preview using verified metadata and validated relative source references; preserve keyboard selection.
- [x] Browser-check all five themes, narrow keyboard focus traversal, keyboard node selection, and drag-without-selecting using synthetic fixtures.
- [x] Clarify graph summaries under local filters: distinguish matching entities and loaded relations from visible nodes/edges.
- [x] Keep the Hex Knowledge group’s `aria-pressed` state synchronized with the active metadata or explicit-component focus.
- [x] Synchronize the reduced-motion checkbox and header toggle, expose their current pressed state, and default to the operating-system preference unless a local choice exists.
- [x] Cache Orbit’s graph adjacency, connected components, visible-node set and deterministic coordinates between redraws; invalidate them when graph or layout filters change.
- [x] Add regression checks for the accessibility state and Orbit cache invalidation paths.
- [x] Correct panel `aria-controls`; make module navigation open nested disclosures, update the current module and move focus to a visible heading.
- [x] Cache the legacy Galaxy node/adjacency index by graph identity; verify cache reuse and invalidation when a new graph arrives.
- [x] Correct the synthetic fixture's parsing of `"0"`/`"1"` suggestion flags so the default graph excludes suggestions like production.
- [x] Replace the legacy authorized-source `alert()` with persistent live-region feedback for pending, success, HTTP failure and connection failure.
- [x] Require both command-center and legacy source-open actions to receive `opened: true` before announcing success; cover HTTP 200 `opened: false` responses.
- [x] Check responsive geometry at exact 1920×1080, 2560×1440 and 380×787; no horizontal overflow was found.

## Coverage audit and remaining work

The user supplied the Neural Command Center mission and acceptance areas in this conversation. `UI_MASTER_SPEC.md` now records them as the working specification; the original prompt's verbatim wording is not required. Status statements below refer to committed implementation or actual evidence, and list unavailable or unverified behavior as open work.

| Capability | Implemented on `Frontend-Design` | Evidence actually run | Open gap |
|---|---|---|---|
| Neural Orbit | Deterministic Canvas 2D document graph, explicit/suggested edge distinction, search, node selection, pan/zoom, project/source/category, degree/depth, color and progressive node loading capped at 1,000. A collapsed native list presents 25 node buttons per page. | Pure Node coverage; synthetic-browser selection/keyboard/search/filter smoke; browser accessibility tree showed metadata and selected state, pagination from 1–25 to 26–50, and keyboard selection with Enter at 1,000 loaded nodes; visual smoke and cache regression checks. | No production index or measured 1,000-node frame-time/memory profile; screen-reader certification remains unverified. |
| Hex Knowledge | Groups by indexed category/source/project or explicit-edge connected components; group selection focuses Orbit. | Node grouping tests and synthetic-browser group selection; this phase verified the active group is exposed as pressed in the accessibility tree. | Component groups are document-graph connectivity, not typed entities or semantic communities. |
| Knowledge Galaxy 3D | Existing Canvas 2D renderer with 3D projection/rotation and filters is moved into the central tab; graph indexes are cached per loaded graph. | Existing graph interaction tests; at 1,000 synthetic nodes, keyboard selection and community isolation rendered as expected with 999 explicit relations. | The typed cross-entity graph endpoint is absent. Renderer remains Canvas-based; WebGL was not part of the verified repository contract. |
| Knowledge Tree | Lists documents grouped by verified project metadata and separately lists explicit graph relations (bounded to 160 rendered edges). | Grouping tests and synthetic-browser tab smoke. | It is not a source-backed architecture hierarchy; a typed graph endpoint is absent from this branch. |
| Markdown inspector | Shows safe metadata, bounded cited retrieval fragments, explicit neighbors and an authorized source-open action with live pending/success/failure feedback; success requires the API's explicit `opened: true`. | Browser QA confirmed the synthetic `opened: false` response is announced as failure; unit coverage checks `opened: true`, `opened: false`, HTTP failure and connection failure. | Full Markdown body cannot be read until an ID-only, bounded, authorized content endpoint exists and is reviewed. |
| Personalization | Five themes; local layout, typography, density, zoom, color, labels, link appearance and reduced-motion preferences; no knowledge queries persisted. | Theme and preference browser smoke; latest phase checked both reduced-motion controls in the browser accessibility tree. | No screen-reader/forced-colors certification. |
| Filters | Query, project, source and category API filters; Orbit depth, minimum degree, suggestions, density and coloring controls. | All four `/api/graph` filters and source/project/category/query/tag `/api/search` filters now have isolated API functional coverage. Browser QA verified Orbit source, project, category and query; dashboard query + category + exact tag + project returned only the matching synthetic record. | Real-index filter behavior awaits safe integration QA; fixture content remains synthetic. |
| Navigation | Roving tabs, keyboard/pointer node selection, arrows, Escape, search results, inspector neighbors, Tree and Hex actions, module disclosures, current-module state, keyboard and pointer splitters. | Node keyboard tests; synthetic-browser module navigation opened Projects, Coding Memory and Cyber panels and focused their headings/summaries; pointer dragging changed the Explorer's accessible width from 230 to 244. | Screen-reader certification remains open. |
| Performance | Request cap 1,000; Orbit reuses adjacency/components/positions, and Galaxy reuses a node/adjacency index until a new graph arrives. | Node regression suite plus synthetic-browser render/interaction smoke through 1,000 nodes across Orbit, Hex, legacy Galaxy and Tree; responsive geometry checked at exact 1920×1080 and 2560×1440. | No measured 1,000-node/real-index frame-time or memory profile; caches reduce repeated derivation but are not performance certification. |

### Open in priority order

1. Review the remaining premium static audit `actionless-button` findings against delegated handlers and manually exercise safe read-only legacy controls; do not add fake inline handlers or trigger indexing/sync/write actions.
2. Test the bounded Orbit node list with a screen reader and browser zoom if those tools are available; the browser accessibility tree verifies semantics and keyboard selection, not assistive-technology certification.
3. Keep the typed cross-entity graph and full Markdown reader pending until the corresponding authorized backend endpoints are committed and reviewed; do not synthesize entities or content.
4. Capture frame-time/memory measurements for the synthetic 1,000-node graph if the browser exposes profiling. Exact 1920×1080 / 2560×1440 geometry is checked with no horizontal overflow; the 1,000-node render smoke is not production performance certification.
5. After backend changes are independently reviewed, feature-detect the typed graph and authorized Markdown-content APIs, retain current fallbacks, and run UI + Python regression tests without indexing, syncing or writing SQLite.
6. Review shared-file conflicts with the backend author; never overwrite their changes. Any later PR/merge is separate from this branch task.

## Explicitly out of scope here

- Editing backend modules, migrations, or the live SQLite database.
- Installing UI packages, external assets, fonts, telemetry, or CDNs.
- Full Markdown rendering before the backend offers an ID-only, authorized, bounded content endpoint.
- Claiming WebGL, semantic communities, architecture hierarchy, or production performance tests that have not been implemented and verified.
