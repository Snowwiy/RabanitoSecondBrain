# UI development progress

## Current checkpoint

- Last updated: 2026-10-17.
- Worktree: dedicated `Frontend-Design` linked worktree (local path intentionally omitted from published docs).
- Branch: `Frontend-Design`; base audited at `4474bfc91bcc8145b1573dfa36831c5626c5fd76`.
- Frontend-only edits; no source edits in the original Second Brain checkout, Sol’s backend work, the SQLite index, Obsidian, Hermes, or other projects.
- Video reference: inspected representative frames from the user-provided MP4; adapted radial, hexagonal and three-panel composition without third-party assets.
- The user supplied the Neural Command Center mission and acceptance areas in this conversation. `UI_MASTER_SPEC.md` is now the durable implementation brief; no verbatim prompt artifact is required.

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
- Added and allowlisted the master specification, architecture, API contract, integration plan, backlog, test record and next-session continuity documents; no personal absolute paths in the published records.
- Visual QA found long search cards overflowing horizontally in the narrow explorer; changed them to stacked, wrapping cards and added a regression test.
- Search explicitly uses `novalidate` because empty-query feedback is owned by its inline live status region.
- The graph summary now says how many entities matched and how many relations were loaded, so local Orbit filters do not leave a false visible-count claim.
- Global search now has an app-owned clear control. It cancels the pending debounce, invalidates older search/graph responses, refreshes the unfiltered view, and returns focus to the query field.
- Hex group buttons now reflect the active metadata/component focus with `aria-pressed` and a visible selected-card treatment; “Centrar vista” clears that state in the rendered Hex panel.
- The reduced-motion checkbox and header toggle now stay synchronized, expose the same pressed state, and use the OS preference unless the user has saved a local choice.
- Orbit redraws reuse explicit adjacency, connected-component labels, visible-node IDs and deterministic coordinates until the graph or layout filters change. Drawing still processes visible edges/nodes; this cache is not a real-index performance certification.
- The legacy Galaxy renderer now reuses node IDs, node lookup and adjacency for the current graph instead of rebuilding them on each redraw; community isolation also uses the cached lookup. A new graph response invalidates the cache by object identity.
- The synthetic fixture now interprets boolean and string suggestion flags the same way as the production API, so `suggestions: "0"` excludes suggested edges in visual tests.
- Module navigation now opens a target `<details>`, updates the matching `aria-current`, and focuses its visible summary/heading. The Explorer and Inspector toggles now point `aria-controls` at the panels they actually control.
- Legacy authorized source opening now reports pending, success, HTTP failure and connection failure in the existing live status region; it no longer invokes a blocking browser alert.
- The command-center Inspector now requires `/api/open/{id}` to return `opened: true` before announcing success; HTTP 200 with `opened: false` is announced as a recoverable failure without exposing server details.
- Added a capability-by-capability implementation/evidence/gap matrix in `UI_TASK_BACKLOG.md`, reconciled against the user-provided mission captured in `UI_MASTER_SPEC.md`.
- The synthetic fixture now applies source, project ID, category-prefix and title/path query filters to graph requests, and source/project/category-prefix/query/exact-tag filters to search. Graph `total_matches`, `truncated` and visible-edge endpoints are computed after filtering. Project metadata is carried on synthetic graph nodes.
- The fixture exposes three enabled synthetic built-in sources so the legacy Dashboard's source selector has realistic options; API coverage checks that only fixture sources are reported.
- Completed the fixture's last-scan counters, added a read-only `/api/audit/latest` response and a path-bounded `/api/source-preview` response that never reads disk. The API test verifies metadata, numeric counters and rejects non-fixture paths.
- Browser-verified legacy read-only controls: scan history and document changes refresh, audit reports 3/3 fixture records checked, decisions search renders its empty state, cited context renders its synthetic citation, and source preview exposes fixture-only sample names. The approval action was not activated.
- Browser-verified panel transparency (92→76) and text scale (100→110) persisted after reload; restored both to defaults. The legacy latest-index line now shows `+3 · ~0 · =0`, and browser console logs remained empty.
- Added concise, atomic live regions for legacy search and cited context. Status announces result/fragment counts, empty states and a redacted error without duplicating entire result cards or long cited passages; request gates prevent stale responses from replacing newer announcements.
- Browser-verified the search count, empty-search state and cited-context count in the accessibility tree; the fixture returned no browser console errors.
- Added an API-level fixture test that starts a fresh loopback-only server on a temporary port and proves each filter, combined search filters and graph truncation without contacting the real service or database.
- Browser-verified Orbit source filters (Projects: 1 node; Obsidian with query “Indexación” and category `research`: 1 node), project filter (Fixture Core: 2 nodes/1 explicit edge), and category filter (`technical`: 1 node). Legacy dashboard search with query “Recuperación”, category prefix `coding`, exact tag `#retrieval`, and Fixture Core project returned only the matching synthetic record.
- Added `UI_MASTER_SPEC.md` with mission, acceptance criteria, implementation evidence, ordered open work, and branch/data safeguards.
- Browser-verified the legacy Dashboard source selector with query “Indexación”, category `research` and tag `#obsidian`: Obsidian returned one record; Projects returned none. The fixture remains clearly marked and isolated.
- Added a collapsed screen-reader path for Orbit using a native list and pagination of 25 node buttons per page. Buttons expose title, category, source, project and `aria-pressed` selection state without creating 1,000 simultaneous tab stops or DOM rows.

- Orbit's layout cache key now includes the selected node only when depth or minimum-degree filters make selection change visible membership. A pure regression test covers cache reuse on global selection and invalidation for selected neighborhoods/degree-filtered views.
- Synthetic browser QA loaded all 1,000 Orbit nodes/999 edges. Five ArrowRight selection action round trips measured 26–36 ms before and 19–22 ms after the key change (medians 29/21 ms); this includes automation and is not an isolated frame-time result. The visible 1,000-node render remained functional with selection and Inspector details.

## Verification evidence

- Node UI suites: **71 passed, 0 failed, 0 skipped**. Regression coverage includes bounded accessible Orbit pagination, legacy search/context live announcements, the loopback fixture API filter test, persistent visual preferences without knowledge-content storage, module navigation, active Hex selection state, synchronized reduced-motion controls, Orbit and Galaxy cache invalidation, explicit-edge community detection and source-open feedback that requires explicit server confirmation, alongside prior search, graph-count, hit-testing and safe-reference cases.
- Python suite: **290 run, 289 passed, 1 skipped, 0 failed**.
- Premium strict audit (no-write): **32 errors, 0 warnings**. An audit-equivalent HTML scan matched all 32 findings to real ID-bound or `data-module`/`data-view` JavaScript handlers; strict mode still reports them because it cannot trace handlers. No inert button or need for an inline no-op was found. Safe read-only controls were exercised; mutation controls were not activated.
- Browser QA against isolated synthetic fixtures: search returned three fixture-only records; selecting one showed metadata, tags, cited bounded fragment and explicit neighbors. Orbit/Hex/Galaxy/Tree switched correctly, legacy graph mounted, panel collapse/restore worked, and preferences disclosed. A fixed card-wrapping regression was confirmed visually. Fixture banner remained visible.
- Latest browser smoke: searching for “Indexación” returned its synthetic record; pressing “Limpiar búsqueda” cleared the result and returned focus to the empty search field.
- Latest synthetic-browser accessibility smoke: selecting a Hex group made its control announce `Value: 1` after returning to Hex; “Centrar vista” cleared the selected state. Toggling reduced motion from the header and from the preferences checkbox updated both accessible values in either direction.
- Latest synthetic-browser navigation smoke: the Projects shortcut moved focus to “Memoria de proyectos”; Coding Memory and Cyber opened their nested disclosure and focused its summary. The Cyber fixture does not provide vulnerability results, so this verified navigation only.
- Latest visual smoke at a desktop-sized 1264×715 viewport showed the selected Hex card with an active fill/border. The same screenshot confirms all three groups and dashboard panels remain laid out without horizontal overflow.
- Latest Galaxy browser smoke at 1,000 synthetic nodes showed `1000/1000 nodos visibles · 999 relaciones · 500 comunidades` with suggested edges off. ArrowRight selected the first fixture document; isolating its computed community reduced the graph to 2 nodes and 1 relation. These are interaction/render checks, not timing measurements.
- Exact viewport geometry checks at 1920×1080, 2560×1440 and 380×787 found no horizontal overflow; the three command-center panels measured 343px at 380px. The screenshot provider caps wide captures at 1280px, so 1920/2560 evidence is DOM geometry rather than a full-width screenshot.
- Browser QA exercised the Inspector against the synthetic `opened: false` response; it announced failure and re-enabled the button. Unit coverage verifies `opened: true`, `opened: false`, HTTP failure and network failure.
- Browser accessibility-tree QA exposed the collapsed Orbit list as a disclosure, then showed 3 metadata-labeled nodes and selected state after activation. At 1,000 loaded fixture nodes, the list showed 25 entries per page, advanced from 1–25 to 26–50, and keyboard Shift+Tab/Enter selected node 50 and populated the Inspector. This verifies the browser accessibility tree and keyboard path, not screen-reader certification.
- Latest Neural Orbit smoke at a narrow viewport: preview showed fixture title, category, source, project, validated relative path and `Grado · 2`; Escape cleared selection, ArrowRight selected and announced a node, and dragging between nodes panned without selecting the release target. All five themes switched successfully and Raven Neon was restored; Tab advanced from panel toggles to global search. Both splitters initialized with responsive accessible widths (230/270) and adjusted/restored by keyboard.
- Visible screenshots covered desktop-sized 1264×715 and 380×787. Exact 1920×1080/2560×1440 geometry passed with no horizontal overflow, but the screenshot provider caps wide captures at 1280px. The driver has no isolated hover-only pointer action. Pointer splitter movement was confirmed after targeting the center of its 8px hit area: the Explorer value changed from 230 to 234 and then 244. Screen-reader certification, true browser-zoom verification, live-index QA and real large-graph performance remain unverified. Ctrl+plus/Ctrl+equal had no effect in this browser driver. A separate synthetic 1,000-node visual smoke exercised Orbit, Hex, legacy Galaxy and Tree; no frame-time or memory profile was recorded. The loopback fixture server is stopped after browser QA.

### Neural Orbit and Hex community phase (2026-10-17)

- Community grouping is a deterministic multi-level modularity estimate over loaded explicit edges only. Suggested links are excluded and isolated nodes remain separate. Tests cover two dense triangles with a bridge, suggested-edge exclusion, order determinism, sparse-chain aggregation and numeric group ordering.
- A synthetic 1,000-node/6,955-edge Node smoke returned 4 groups in 44 ms. This measures the pure detector in Node, not browser rendering, frame time, heap or production-index behavior.
- On the browser fixture, 180 of 1,000 matching documents and 179 explicit edges were initially loaded; the UI showed 12 topology estimates. Hex cards appeared in numeric order, exposed group/count/basis names in the accessibility tree, and selection returned to Orbit with a live disclaimer that the group is not semantic. Screenshot review at 1264×715 found the card grid legible.
- All browser data was synthetic. This state is not a complete 1,000-node graph and does not certify assistive technology.

## Next action

Continue through the open priorities in `UI_TASK_BACKLOG.md`; do not treat the passing tests or this checkpoint as completion of the full redesign. Keep the frontend on its documented fallback until backend API changes are reviewed and integrated through their own branch. Do not touch `main` or the original worktree.
