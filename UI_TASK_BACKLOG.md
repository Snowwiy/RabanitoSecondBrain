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
- [x] Connect the existing Inspector reader to real `POST /api/doc/content`; verify authorized Obsidian, projects and internal-memory reads, bounded responses, error handling, safe DOM output, and read-only source/database behavior. Published as `a5ea26b9f1156fb3fd879283c77f530b5f61949b` on `origin/Frontend-Design`.
- [x] Continue the selective backend integration with typed `POST /api/knowledge-graph`, `/neighbors` and explicitly confirmed `/sync`, preserving the document graph fallback. The read routes do not synchronize implicitly; no sync or index operation was invoked during QA.
- [x] Expose every one of the 32 current backend entity kinds in the Knowledge Graph filter and localize ATT&CK and security entity labels in Hex, Tree, the accessible node list and Inspector.
- [x] Browser-test the real indexed Knowledge Graph through a copied, read-only SQLite snapshot: the 180-node page represented 51,992 candidates, ATT&CK filters returned 706 active candidates, and selecting a technique loaded a cited one-hop relation. No note titles or content were used as test instructions.
- [x] Browser-test the complete 339-document page set, 2,149 loaded relations, four project Hex groups and 30 category groups after progressive loading; typed Hex/Tree navigation returns to Orbit with state and labels intact.
- [x] Read an authorized real Obsidian note through the existing Inspector (`204` bytes, one recognized reference). Before and after the reader request, its indexed SHA-256, source size and modification time matched; no source or database content was written.
- [x] Visual QA at exact 1920×1080 and 2560×1440 included Orbit and Hex screenshots plus DOM geometry. Both sizes had no horizontal overflow. Galaxy retained its 3D Canvas surface at 2560×1440 and the browser logged zero console errors.
- [x] Run all **82 Node tests** and all **359 Python tests** (1 skipped); the focused Knowledge Graph suite passed **34/34**. The large client test capped 10,000 input nodes/30,000 edges at 1,000 nodes/4,000 edges in about 20 ms on this run.

## Coverage audit and remaining work

The user supplied the Neural Command Center mission and acceptance areas in this conversation. `UI_MASTER_SPEC.md` now records them as the working specification; the original prompt's verbatim wording is not required. Status statements below refer to committed implementation or actual evidence, and list unavailable or unverified behavior as open work.

| Capability | Implemented on `Frontend-Design` | Evidence actually run | Open gap |
|---|---|---|---|
| Neural Orbit | Deterministic Canvas 2D document and typed graphs; explicit/suggested/inferred/reviewed relation distinction; search, selection, pan/zoom, filters, keyboard navigation and progressive loading. The typed client caps the visible set at 1,000 nodes/4,000 edges; backend page size is at most 200. Topological groups remain estimates. | 82 Node tests; real-index copied-snapshot browser QA showed 180/51,992 candidates, 706 filtered ATT&CK candidates, a selected entity and a cited neighbor; keyboard arrows/Enter/Escape worked. Exact 1920×1080 and 2560×1440 DOM checks showed no horizontal overflow. Backend 34-test suite covers cursors, permissions, stale inputs and explicit sync. | No screen-reader certification or isolated browser frame-time/heap profile. |
| Hex Knowledge | Groups document mode by category/source/project and typed mode by all 32 published entity kinds; optional connected components/topology estimates; selection returns to Orbit. | Real-index snapshot QA loaded 339 docs/2,149 relations progressively, with four project groups and 30 category cards; typed Hex labels covered ATT&CK and returned focus to Orbit. | Screen-reader certification remains open; semantic communities are not provided. |
| Knowledge Galaxy 3D | Existing Canvas 2D renderer with 3D projection/rotation and filters is reused; graph indexes are cached per loaded graph. | Browser at 2560×1440 mounted the real-index graph surface with zero console errors; full Node suite retained existing Galaxy cache/navigation coverage. | Renderer is Canvas-based; no WebGL, browser frame-time or heap certification. |
| Knowledge Tree | Document mode lists project metadata and explicit graph relations; typed mode groups entities by localized published kind and lists classified relations (bounded to 160 rendered edges). | Real-index snapshot QA showed project groups and typed ATT&CK group/relationship navigation; 82 Node tests passed. | This is metadata navigation, not a source-backed architecture hierarchy; screen-reader certification remains open. |
| Markdown inspector | Shows safe metadata, bounded cited retrieval fragments, explicit neighbors and authorized source-open action; user-triggered full-body read uses an ID-only authorized endpoint and bounded safe DOM rendering with internal references and local search. | 35 endpoint Python tests; full suite 325 run (1 skipped); 76 Node tests; live HTTP reads from authorized Obsidian/projects/internal memory; browser rendered a real Obsidian note and a second 35,120-byte note, with metadata, 100 recognized references and explicit neighbors. Strict response validation rejects additional fields, mismatched IDs/byte counts and unsafe references. | Continue stale/encoding/size/error regression coverage. Screen-reader certification remains open; the endpoint does not detect every possible secret, so source exclusions remain important. |
| Personalization | Five themes; local layout, typography, density, zoom, transparency, color, labels, link appearance and reduced-motion preferences; no knowledge queries persisted. | Theme and reduced-motion browser smoke; transparency and text-scale values survived reload and were restored to defaults. | No screen-reader/forced-colors certification; browser zoom remains unverified. |
| Filters | Query, project, source and category API filters; Orbit depth, minimum degree, suggestions, density and coloring controls. | Search/graph filter API coverage; synthetic browser QA verified Orbit and Dashboard query/source/category/tag/project. This integration used the real index for statistics and reader selection only; history/change refresh, audit report, decisions search, cited context and source preview were tested against the fixture. | Targeted real-index search/filter and broader legacy-panel QA remain open; fixture content remains synthetic. |
| Navigation | Roving tabs, keyboard/pointer node selection, arrows, Escape, search results, inspector neighbors, Tree and Hex actions, module disclosures, current-module state, keyboard and pointer splitters. | Node keyboard tests; synthetic-browser module navigation opened Projects, Coding Memory and Cyber panels and focused their headings/summaries; legacy search/context expose concise atomic live statuses; pointer dragging changed the Explorer's accessible width from 230 to 244. | Screen-reader certification remains open. |
| Performance | Document graph stays capped at 1,000; typed graph pages at 200 and caps at 1,000 nodes/4,000 edges. Orbit/Galaxy reuse derived indexes and cache selection-independent layout. | Actual database page query returned 50/51,992 candidates in about 966 ms read-only; Node test reduced 10k/30k input to caps in about 20 ms. Exact 1920×1080 and 2560×1440 visual/DOM QA showed no horizontal overflow. | No isolated browser frame-time/heap profile or 10k+ rendered production view; query/Node timing is not paint timing. |

### Open in priority order

1. Run Orbit, Hex and Tree with a screen reader and verify browser zoom when reliable tools are available.
2. Use an isolated browser profiler to measure frame time and heap for the 1,000-node view at 1080p/1440p; present timings are query/Node measurements.
3. Continue real-index tests for other entity kinds, stale projection states and paging boundaries without calling sync/index.
4. Complete the non-destructive compatibility report for a future Pull Request; no merge is authorized in this phase.

## Explicitly out of scope here

- Editing backend modules, migrations, or the live SQLite database.
- Installing UI packages, external assets, fonts, telemetry, or CDNs.
- Modifying canonical Obsidian/project sources or the original SQLite index; the integrated endpoint is read-only, and fixture responses remain test-only.
- Claiming WebGL, semantic communities, architecture hierarchy, or production performance tests that have not been implemented and verified.
