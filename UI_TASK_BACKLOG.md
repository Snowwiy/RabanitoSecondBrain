# UI task backlog

## Completed in this branch checkpoint

- [x] Add three-panel Neural Command Center around the existing dashboard.
- [x] Add five themes and locally persisted visual preferences, excluding knowledge queries/content.
- [x] Implement real API-backed Orbit, metadata-grouped Hex, legacy Galaxy reuse, and metadata-grouped Tree.
- [x] Add bounded search, filters, keyboard/pointer navigation, selection, cited Inspector fragments and authorized source-open action.
- [x] Keep suggested relations distinct; label topology-derived communities as estimates and do not invent hierarchy or semantic labels.
- [x] Add local synthetic fixture server and pure-function/XSS-boundary tests.
- [x] Document current API boundary and integration limitations.
- [x] Run the original 64-test Node baseline and 290 Python tests (1 skipped); subsequent frontend-only phases expanded the Node UI suite to 75 passing tests without changing Python implementation.
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
- [x] Add deterministic multi-level modularity grouping for Neural Orbit and Hex using explicit edges only; suggested edges and isolated nodes cannot be silently merged into a semantic claim.
- [x] Add community color mode, Hex navigation to the selected Orbit community, explanatory status/disclaimer, accessible group labels, and numeric ordering for double-digit community labels.
- [x] Cover dense-cluster separation, suggested-edge exclusion, order determinism, sparse-chain aggregation, and numeric community ordering in Node tests; visually and accessibly verify the large fixture in the browser.
- [x] Smoke the detector against 1,000 synthetic nodes / 6,955 explicit edges in Node (44 ms on this run); this is algorithm-only synthetic evidence, not browser frame time or production-index profiling.
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
- [x] Add a user-triggered, bounded Markdown reader adapter with a safe DOM-only parser, ID-authorized internal links, HTTP(S)-only external links, raw-HTML-as-text behavior, loading/error/404 states and in-document search.
- [x] Extend the isolated fixture with explicitly synthetic Markdown success, 404 and transport-failure modes; cover bounded API responses, browser-rendered Markdown blocks, source references, internal navigation, search highlights, inert HTML, and visible failure recovery.
- [x] Document the ID-only `POST /api/doc/content` contract, separate production and fixture behavior, and endpoint-to-component/test matrix.
- [x] Resolve the contract-file add/add conflict by preserving both versions' compatible requirements; selectively import the authorized reader module, route and focused tests without merging unrelated backend work.
- [x] Connect the existing Inspector reader to real `POST /api/doc/content`; verify authorized Obsidian, projects and internal-memory reads, bounded responses, error handling, safe DOM output, and read-only source/database behavior.

## Coverage audit and remaining work

The user supplied the Neural Command Center mission and acceptance areas in this conversation. `UI_MASTER_SPEC.md` now records them as the working specification; the original prompt's verbatim wording is not required. Status statements below refer to committed implementation or actual evidence, and list unavailable or unverified behavior as open work.

| Capability | Implemented on `Frontend-Design` | Evidence actually run | Open gap |
|---|---|---|---|
| Neural Orbit | Deterministic Canvas 2D document graph, explicit/suggested edge distinction, search, node selection, pan/zoom, project/source/category, degree/depth, color and progressive node loading capped at 1,000. A collapsed native list presents 25 node buttons per page. Deterministic multi-level modularity groups only explicit edges and is labeled as a topology estimate. | Pure Node coverage; synthetic-browser selection/keyboard/search/filter smoke; browser accessibility tree showed metadata and selected state, pagination from 1–25 to 26–50, and keyboard selection with Enter at 1,000 loaded nodes; community cards verified visually and in AX against 180 loaded nodes/179 edges. A separate 1,000-node/6,955-edge detector smoke took 44 ms in Node. | No production index or measured browser frame-time/memory profile; screen-reader certification remains unverified. |
| Hex Knowledge | Groups by indexed category/source/project, explicit-edge connected components, or detected topological communities; group selection focuses Orbit and communities are numerically ordered. | Node grouping tests; synthetic browser selected a community, returned to Orbit and announced its non-semantic status; visual/AX inspection showed ordered community cards and explicit group labels for the 180-node/179-edge fixture. | Typed entities and semantic community labels are not available from the current backend. |
| Knowledge Galaxy 3D | Existing Canvas 2D renderer with 3D projection/rotation and filters is moved into the central tab; graph indexes are cached per loaded graph. | Existing graph interaction tests; at 1,000 synthetic nodes, keyboard selection and community isolation rendered as expected with 999 explicit relations. | The typed cross-entity graph endpoint is absent. Renderer remains Canvas-based; WebGL was not part of the verified repository contract. |
| Knowledge Tree | Lists documents grouped by verified project metadata and separately lists explicit graph relations (bounded to 160 rendered edges). | Grouping tests and synthetic-browser tab smoke. | It is not a source-backed architecture hierarchy; a typed graph endpoint is absent from this branch. |
| Markdown inspector | Shows safe metadata, bounded cited retrieval fragments, explicit neighbors and authorized source-open action; user-triggered full-body read uses an ID-only authorized endpoint and bounded safe DOM rendering with internal references and local search. | 35 endpoint Python tests; full suite 325 run (1 skipped); 76 Node tests; live HTTP reads from authorized Obsidian/projects/internal memory; browser rendered a real Obsidian note and a second 35,120-byte note, with metadata, 100 recognized references and explicit neighbors. Strict response validation rejects additional fields, mismatched IDs/byte counts and unsafe references. | Continue stale/encoding/size/error regression coverage. Screen-reader certification remains open; the endpoint does not detect every possible secret, so source exclusions remain important. |
| Personalization | Five themes; local layout, typography, density, zoom, transparency, color, labels, link appearance and reduced-motion preferences; no knowledge queries persisted. | Theme and reduced-motion browser smoke; transparency and text-scale values survived reload and were restored to defaults. | No screen-reader/forced-colors certification; browser zoom remains unverified. |
| Filters | Query, project, source and category API filters; Orbit depth, minimum degree, suggestions, density and coloring controls. | Search/graph filter API coverage; synthetic browser QA verified Orbit and Dashboard query/source/category/tag/project. This integration used the real index for statistics and reader selection only; history/change refresh, audit report, decisions search, cited context and source preview were tested against the fixture. | Targeted real-index search/filter and broader legacy-panel QA remain open; fixture content remains synthetic. |
| Navigation | Roving tabs, keyboard/pointer node selection, arrows, Escape, search results, inspector neighbors, Tree and Hex actions, module disclosures, current-module state, keyboard and pointer splitters. | Node keyboard tests; synthetic-browser module navigation opened Projects, Coding Memory and Cyber panels and focused their headings/summaries; legacy search/context expose concise atomic live statuses; pointer dragging changed the Explorer's accessible width from 230 to 244. | Screen-reader certification remains open. |
| Performance | Request cap 1,000; Orbit reuses adjacency/components/positions, skips global layout recomputation on selection-only redraws, Galaxy reuses a node/adjacency index until a new graph arrives, and community detection aggregates multiple levels. | Node regression tests; synthetic-browser smoke through 1,000 nodes/999 explicit edges. Five selection action round trips showed median 29 ms before and 21 ms after the cache-key fix; separate 1,000-node/6,955-edge community detector smoke took 44 ms in Node; exact viewport geometry remains checked at 1920×1080 and 2560×1440. | Action timings include browser automation and are not isolated frame/paint data; no browser heap or real-index profile. |

### Open in priority order

1. Commit and publish the validated reader integration only to `origin/Frontend-Design`; confirm the pushed SHA and keep `main` unchanged.
2. Continue the typed cross-entity graph only when its read-only API contract is independently reviewed; retain the current document graph fallback.
3. Run the Orbit list with a screen reader and verify browser zoom if reliable tools become available; browser AX/keyboard checks do not certify assistive technology.
4. Use an isolated browser profiler for the 1,000-node frame-time/heap profile if available. Current interaction timings include automation overhead and are not frame-time certification.
5. Add targeted real-index search/filter and broader legacy read-only panel QA without indexing, syncing or writing SQLite.

## Explicitly out of scope here

- Editing backend modules, migrations, or the live SQLite database.
- Installing UI packages, external assets, fonts, telemetry, or CDNs.
- Modifying canonical Obsidian/project sources or the original SQLite index; the integrated endpoint is read-only, and fixture responses remain test-only.
- Claiming WebGL, semantic communities, architecture hierarchy, or production performance tests that have not been implemented and verified.
