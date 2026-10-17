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
- [x] Expose three enabled, integrated synthetic source kinds through fixture `/api/sources` so legacy Dashboard and graph source selectors are usable in QA; assert the fixture source inventory.
- [x] Browser-test the legacy Dashboard source selector with the same text/category/tag filters: `Obsidian` returned one matching record, while `Proyectos` returned none.
- [x] Complete synthetic `/api/stats` counters, expose a read-only `/api/audit/latest` report, and add a source-preview fixture endpoint restricted to `C:\fixture`; assert these contracts without touching disk.
- [x] Browser-verify legacy history/change refresh, read-only audit, decisions search, cited context retrieval and source preview. The preview offered its approval step but it was not activated.
- [x] Browser-verify panel transparency and text scale persistence across reload (92→76 and 100→110), then restore defaults.
- [x] Run all 67 Node UI tests and `git diff --check`; no backend code changed, so the Python suite was not rerun.
- [x] Add concise atomic live regions for legacy search and cited-context success, empty and error outcomes; keep full results/fragments outside the announcements.
- [x] Test current vs. stale search/context statuses, empty search, error redaction, and live-region semantics; browser QA confirmed one-result, empty-result and cited-context announcements.
- [x] Run all 68 Node UI tests and `git diff --check`; no backend code changed, so the Python suite was not rerun.
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

- [x] Keep Orbit's deterministic global layout cache stable across node-selection redraws when depth and minimum degree are both zero; invalidate it when selected-node membership can change a depth/min-degree view.
- [x] Add regression coverage for the selection-independent global cache key and selection-dependent neighborhoods/degree filters.
- [x] Map all 32 premium static `actionless-button` findings to real ID-bound or `data-module`/`data-view` event handlers. No unbound button remained; the strict audit still reports these because it only analyzes literal markup, so no fake inline handlers were added.
- [x] Browser-smoke a synthetic 1,000-node Orbit after loading all 999 explicit relations. Five ArrowRight selection action round trips had a median of 29 ms before and 21 ms after the cache-key fix; these timings include browser automation and are not isolated paint measurements.
- [x] Run all 69 Node UI tests and `git diff --check`; the frontend-only phase does not change Python modules.

## Coverage audit and remaining work

The user supplied the Neural Command Center mission and acceptance areas in this conversation. `UI_MASTER_SPEC.md` now records them as the working specification; the original prompt's verbatim wording is not required. Status statements below refer to committed implementation or actual evidence, and list unavailable or unverified behavior as open work.

| Capability | Implemented on `Frontend-Design` | Evidence actually run | Open gap |
|---|---|---|---|
| Neural Orbit | Deterministic Canvas 2D document graph, explicit/suggested edge distinction, search, node selection, pan/zoom, project/source/category, degree/depth, color and progressive node loading capped at 1,000. A collapsed native list presents 25 node buttons per page. | Pure Node coverage; synthetic-browser selection/keyboard/search/filter smoke; browser accessibility tree showed metadata and selected state, pagination from 1–25 to 26–50, and keyboard selection with Enter at 1,000 loaded nodes; visual smoke and cache regression checks. | No production index or measured 1,000-node frame-time/memory profile; screen-reader certification remains unverified. |
| Hex Knowledge | Groups by indexed category/source/project or explicit-edge connected components; group selection focuses Orbit. | Node grouping tests and synthetic-browser group selection; this phase verified the active group is exposed as pressed in the accessibility tree. | Component groups are document-graph connectivity, not typed entities or semantic communities. |
| Knowledge Galaxy 3D | Existing Canvas 2D renderer with 3D projection/rotation and filters is moved into the central tab; graph indexes are cached per loaded graph. | Existing graph interaction tests; at 1,000 synthetic nodes, keyboard selection and community isolation rendered as expected with 999 explicit relations. | The typed cross-entity graph endpoint is absent. Renderer remains Canvas-based; WebGL was not part of the verified repository contract. |
| Knowledge Tree | Lists documents grouped by verified project metadata and separately lists explicit graph relations (bounded to 160 rendered edges). | Grouping tests and synthetic-browser tab smoke. | It is not a source-backed architecture hierarchy; a typed graph endpoint is absent from this branch. |
| Markdown inspector | Shows safe metadata, bounded cited retrieval fragments, explicit neighbors and an authorized source-open action with live pending/success/failure feedback; success requires the API's explicit `opened: true`. | Browser QA confirmed the synthetic `opened: false` response is announced as failure; unit coverage checks `opened: true`, `opened: false`, HTTP failure and connection failure. | Full Markdown body cannot be read until an ID-only, bounded, authorized content endpoint exists and is reviewed. |
| Personalization | Five themes; local layout, typography, density, zoom, transparency, color, labels, link appearance and reduced-motion preferences; no knowledge queries persisted. | Theme and reduced-motion browser smoke; transparency and text-scale values survived reload and were restored to defaults. | No screen-reader/forced-colors certification; browser zoom remains unverified. |
| Filters | Query, project, source and category API filters; Orbit depth, minimum degree, suggestions, density and coloring controls. | Search/graph filter API coverage; browser QA verified Orbit and Dashboard query/source/category/tag/project. Read-only history/change refresh, audit report, decisions search, cited context, source preview and live result announcements were exercised. | Real-index filter behavior awaits safe integration QA; fixture content remains synthetic. |
| Navigation | Roving tabs, keyboard/pointer node selection, arrows, Escape, search results, inspector neighbors, Tree and Hex actions, module disclosures, current-module state, keyboard and pointer splitters. | Node keyboard tests; synthetic-browser module navigation opened Projects, Coding Memory and Cyber panels and focused their headings/summaries; legacy search/context expose concise atomic live statuses; pointer dragging changed the Explorer's accessible width from 230 to 244. | Screen-reader certification remains open. |
| Performance | Request cap 1,000; Orbit reuses adjacency/components/positions, skips global layout recomputation on selection-only redraws, and Galaxy reuses a node/adjacency index until a new graph arrives. | Node regression tests; synthetic-browser smoke through 1,000 nodes/999 explicit edges. Five selection action round trips showed median 29 ms before and 21 ms after the cache-key fix; exact viewport geometry remains checked at 1920×1080 and 2560×1440. | Action timings include browser automation and are not isolated frame/paint data; no heap or real-index profile. |

### Open in priority order

1. Test the bounded Orbit node list with a screen reader and browser zoom if those tools are available; the browser accessibility tree verifies semantics and keyboard selection, not screen-reader certification. Current browser shortcuts did not change zoom.
2. Keep the typed cross-entity graph and full Markdown reader pending until the corresponding authorized backend endpoints are committed and reviewed; do not synthesize entities or content.
3. Use an isolated browser profiler for the 1,000-node frame-time/heap profile if one becomes available. The available browser driver only provided interaction round trips; exact 1920×1080 / 2560×1440 geometry and synthetic render smoke are not production performance certification.
4. After backend changes are independently reviewed, feature-detect the typed graph and authorized Markdown-content APIs, retain current fallbacks, and run UI + Python regression tests without indexing, syncing or writing SQLite.
5. Review shared-file conflicts with the backend author; never overwrite their changes. Any later PR/merge is separate from this branch task.

## Explicitly out of scope here

- Editing backend modules, migrations, or the live SQLite database.
- Installing UI packages, external assets, fonts, telemetry, or CDNs.
- Full Markdown rendering before the backend offers an ID-only, authorized, bounded content endpoint.
- Claiming WebGL, semantic communities, architecture hierarchy, or production performance tests that have not been implemented and verified.
