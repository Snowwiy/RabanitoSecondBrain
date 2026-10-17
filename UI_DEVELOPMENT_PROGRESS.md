# UI development progress

## Current checkpoint

- Last updated: 2026-10-17.
- Worktree: dedicated `Frontend-Design` linked worktree (local path intentionally omitted from published docs).
- Branch: `Frontend-Design`; base audited at `4474bfc91bcc8145b1573dfa36831c5626c5fd76`.
- Frontend-only edits; no source edits in the original Second Brain checkout, Sol’s backend work, the SQLite index, Obsidian, Hermes, or other projects.
- Video reference: inspected representative frames from the user-provided MP4; adapted radial, hexagonal and three-panel composition without third-party assets.

## Implemented in this UI phase

- Three-panel Neural Command Center with collapsible panels and bounded mouse/keyboard splitters.
- Five local themes; preference persistence excludes query/filter/document data.
- Neural Orbit canvas backed by actual `/api/graph` nodes/edges; graph selection, pan/zoom, labels, focus, degree/depth filters, category/source/project/component coloring, optional suggested links, density and progressive load cap.
- Neural Orbit previews the hovered node's title and verified metadata in a bounded text tooltip; keyboard selection shows the same preview and announces the selected title. Only a validated relative source reference is displayed.
- Hex Knowledge cards grouped by actual source/project/category metadata, or by explicit-edge connected components clearly labeled as connectivity.
- Knowledge Tree grouped by project metadata with explicit relation list; no fabricated architecture levels.
- Existing Knowledge Galaxy 3D controls/canvas are moved into the central tab and retained.
- Search uses `/api/search`; Inspector uses `/api/doc/{id}` and capped `/api/context`, includes relative-path citations and links, uses text-only rendering, and opens originals only through `/api/open/{id}`.
- Existing legacy panels remain available in a collapsed workbench.
- Local fixture-only server for browser QA marks synthetic payloads and disables source opening.
- Added and allowlisted architecture, API contract, integration plan, backlog, test record and next-session continuity documents; no personal absolute paths in the published records.
- Visual QA found long search cards overflowing horizontally in the narrow explorer; changed them to stacked, wrapping cards and added a regression test.
- Search explicitly uses `novalidate` because empty-query feedback is owned by its inline live status region.
- The graph summary now says how many entities matched and how many relations were loaded, so local Orbit filters do not leave a false visible-count claim.
- Global search now has an app-owned clear control. It cancels the pending debounce, invalidates older search/graph responses, refreshes the unfiltered view, and returns focus to the query field.

## Verification evidence

- Node UI suites: **57 passed, 0 failed, 0 skipped**. Regression coverage includes search clearing, graph count wording, orbit hit testing and safe relative references.
- Python suite: **290 run, 289 passed, 1 skipped, 0 failed**.
- Premium strict audit (no-write): **32 errors, 0 warnings**. All 32 are static detections of literal buttons without inline action; application behavior is wired from external modules/delegated handlers and representative command-center search, tabs, inspector and panel-collapse actions were confirmed in browser. This audit does not prove every legacy action; remaining audit finding stays documented for review rather than adding fake inline handlers.
- Browser QA against isolated synthetic fixtures: search returned three fixture-only records; selecting one showed metadata, tags, cited bounded fragment and explicit neighbors. Orbit/Hex/Galaxy/Tree switched correctly, legacy graph mounted, panel collapse/restore worked, and preferences disclosed. A fixed card-wrapping regression was confirmed visually. Fixture banner remained visible.
- Latest browser smoke: searching for “Indexación” returned its synthetic record; pressing “Limpiar búsqueda” cleared the result and returned focus to the empty search field.
- Latest Neural Orbit smoke at a narrow viewport: preview showed fixture title, category, source, project, validated relative path and `Grado · 2`; Escape cleared selection, ArrowRight selected and announced a node, and dragging between nodes panned without selecting the release target. All five themes switched successfully and Raven Neon was restored; Tab advanced from panel toggles to global search. Both splitters initialized with responsive accessible widths (230/270) and adjusted/restored by keyboard.
- Visible QA covered desktop-sized 1265×715 and a narrow screenshot around 380×787. The driver exposes no viewport override or hover-only pointer action; pointer-drag splitters, exact 1920×1080/2560×1440, screen-reader certification, live-index QA and real large-graph performance remain unverified. The loopback fixture server is stopped after browser QA.

## Next action

Review the remaining audit findings and complete the supported wide-viewport checks when the browser can expose those dimensions. Keep the frontend on its documented fallback until backend API changes are reviewed and integrated through their own branch. Do not touch `main` or the original worktree.
