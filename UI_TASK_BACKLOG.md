# UI task backlog

## Completed in this branch checkpoint

- [x] Add three-panel Neural Command Center around the existing dashboard.
- [x] Add five themes and locally persisted visual preferences, excluding knowledge queries/content.
- [x] Implement real API-backed Orbit, metadata-grouped Hex, legacy Galaxy reuse, and metadata-grouped Tree.
- [x] Add bounded search, filters, keyboard/pointer navigation, selection, cited Inspector fragments and authorized source-open action.
- [x] Keep suggested relations distinct and avoid invented hierarchy/community claims.
- [x] Add local synthetic fixture server and pure-function/XSS-boundary tests.
- [x] Document current API boundary and integration limitations.
- [x] Run 61 Node UI tests and 290 Python tests (1 skipped); `git diff --check` passes.
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

## Coverage audit and remaining work

The requested original Neural Command Center master prompt is not present in the `Frontend-Design` worktree or the separate main checkout (including hidden/ignored file-name search), and no tracked Git revision contains it. This table therefore compares the implementation against the repository’s available `UX-CONTRACT.md`, `UI_ARCHITECTURE.md`, API contract and tests. It is provisional until the original prompt is supplied; no missing requirements are inferred from its title.

| Capability | Implemented on `Frontend-Design` | Evidence actually run | Open gap |
|---|---|---|---|
| Neural Orbit | Deterministic Canvas 2D document graph, explicit/suggested edge distinction, search, node selection, pan/zoom, project/source/category, degree/depth, color and progressive node loading capped at 1,000. | Pure Node coverage, synthetic-browser selection/keyboard/search/filter smoke, cache regression checks, and 1,000-node visual render smoke. | No production index or measured 1,000-node frame-time/memory profile; hover-only browser gesture and screen-reader certification remain unverified. |
| Hex Knowledge | Groups by indexed category/source/project or explicit-edge connected components; group selection focuses Orbit. | Node grouping tests and synthetic-browser group selection; this phase verified the active group is exposed as pressed in the accessibility tree. | Component groups are document-graph connectivity, not typed entities or semantic communities. |
| Knowledge Galaxy 3D | Existing dashboard graph controls and renderer are moved into the central tab and remain usable. | Existing graph interaction tests and synthetic-browser tab/mount smoke. | This is the legacy Canvas renderer; no new WebGL renderer was built. |
| Knowledge Tree | Lists documents grouped by verified project metadata and separately lists explicit graph relations (bounded to 160 rendered edges). | Grouping tests and synthetic-browser tab smoke. | It is not a source-backed architecture hierarchy; a typed graph endpoint is absent from this branch. |
| Markdown inspector | Shows safe metadata, bounded cited retrieval fragments, explicit neighbors and an authorized source-open action. | Existing API/fixture tests and synthetic-browser inspector smoke. | Full Markdown body cannot be read until an ID-only, bounded, authorized content endpoint exists and is reviewed. |
| Personalization | Five themes; local layout, typography, density, zoom, color, labels, link appearance and reduced-motion preferences; no knowledge queries persisted. | Theme and preference browser smoke; latest phase checked both reduced-motion controls in the browser accessibility tree. | No screen-reader/forced-colors certification. |
| Filters | Query, project, source and category API filters; Orbit depth, minimum degree, suggestions, density and coloring controls. | Existing API/UI regression suites; synthetic-browser search and minimum-degree smoke. | Not every control has a separate end-to-end browser case; real-index filter behavior awaits integration QA. |
| Navigation | Roving tabs, keyboard/pointer node selection, arrows, Escape, search results, inspector neighbors, Tree and Hex actions, module disclosures, current-module state, keyboard and pointer splitters. | Node keyboard tests; synthetic-browser module navigation opened Projects, Coding Memory and Cyber panels and focused their headings/summaries; pointer dragging changed the Explorer's accessible width from 230 to 244. | Screen-reader certification remains open. |
| Performance | Request cap 1,000; repeated Orbit redraws now reuse adjacency/components and cached deterministic positions for unchanged graph/filter geometry. | 61 Node tests plus synthetic-browser visual render smoke through 1,000 nodes across Orbit, Hex, legacy Galaxy and Tree. | No measured 1,000-node/real-index frame-time or memory profile; cached layout reduces repeated work but is not a performance certification. |

### Open in priority order

1. Obtain the original master prompt from its author/path and reconcile this provisional matrix line by line; continue using the repository UX contract until then.
2. Keep the typed cross-entity graph and full Markdown reader pending until the corresponding backend endpoints are committed and reviewed; do not synthesize entities or content.
3. Capture frame-time/memory measurements for the synthetic 1,000-node graph and complete exact 1920×1080 / 2560×1440 checks if the browser exposes profiling and those viewports. The 1,000-node visual render smoke is complete; record timing limits separately and do not claim production performance from synthetic data.
4. Complete screen-reader/zoom checks when the browser exposes reliable inspection. Keyboard and pointer splitter resizing and narrow/desktop layout checks are already covered.
5. Review the premium static audit’s 32 `actionless-button` findings against the delegated handlers and manually test the remaining legacy controls; do not add fake inline handlers.
6. After the backend branch is reviewed, feature-detect the typed graph and authorized Markdown-content APIs, retain current fallbacks, and run UI + Python regression tests without indexing, syncing or writing SQLite.
7. Review shared-file conflicts with the backend author; never overwrite their changes. Any later PR/merge is separate from this branch task.

## Explicitly out of scope here

- Editing backend modules, migrations, or the live SQLite database.
- Installing UI packages, external assets, fonts, telemetry, or CDNs.
- Full Markdown rendering before the backend offers an ID-only, authorized, bounded content endpoint.
- Claiming WebGL, semantic communities, architecture hierarchy, or production performance tests that have not been implemented and verified.
