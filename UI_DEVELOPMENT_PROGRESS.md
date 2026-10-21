# UI development progress

## Combined integration checkpoint (2026-10-21)

- Current worktree is the isolated `integration/rabanito-3.0` branch. Its base includes verified backend `origin/main` commit `c1f11ce12240caf2a085cc299ddf243676095da6` and the Neural Command Center from `origin/Frontend-Design` commit `39b572f28dc6f60915d44bc8b6ad790f78d1c386`.
- The seven merge conflicts and file-by-file preservation decisions are recorded in `UI_INTEGRATION_PLAN.md`. Main's CLI/server and source-authorization behavior were retained, while the frontend's typed graph consumers and UI assets remain integrated.
- Corrected typed Knowledge Graph pagination: neighbor responses preserve the page cursor; subsequent pages keep the cursor's original page size. The live copied-index walkthrough advanced from 180 nodes, expanded six neighbors, then loaded the next page to 365 visible nodes without a cursor error. Projection refresh now uses a labeled app-owned modal rather than a browser confirmation; Cancel/Escape do not send the sync request.
- Added a Node regression covering cursor preservation and stable page size. Final combined results: **84 Node tests passed** and **1,029 Python tests ran (1 skipped)**. Original SQLite database/WAL/SHM bytes and the authorized Obsidian note matched baseline hashes; note metadata matched as well. The SHM mtime alone differed after read-only access. Details are in `UI_TEST_RESULTS.md`.
- Visual QA was limited to the in-app browser's approximately 445px viewport. It verified real local graph data, the reader's earlier real authorized Obsidian smoke, and Tree/Hex/3D navigation; true 1080p/1440p screenshots and browser console logs were unavailable in this session.
- No production source bytes, credentials, `main` worktree, or `Frontend-Design` worktree were changed. The original database sidecar filesystem mtime changed during read-only SQLite access while its size/hash remained identical. The only graph projection sync during QA was run on the ignored temporary SQLite snapshot.
- Remaining integration risks: no screen-reader certification, true browser zoom, or browser heap/frame-time profile; the Coding Memory catalog has no reviewed matching records in the verified dataset; public connector freshness may be pending. Re-evaluate these before classifying the PR as ready to merge.

## Current checkpoint

- Last updated: 2026-10-20.
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
- Inspector's user-triggered Markdown reader now connects to the real `POST /api/doc/content` route. It validates the exact response schema, ID/byte fields and references; parses a bounded Markdown subset through safe DOM constructors; treats raw HTML as text; limits external URLs; and resolves internal links only through returned references. Missing, stale, unauthorized and size errors preserve metadata/context without exposing server details.
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

- Node UI suites: **75 passed, 0 failed, 0 skipped**. Coverage includes the bounded safe Markdown parser and synthetic reader route, reference authorization, inert HTML, byte caps, synthetic transport interruption, and the prior graph, navigation, filter and accessibility regressions.
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

## Historical next action — Frontend-Design checkpoint

The paragraph below records the 2026-10-20 state before this controlled integration. The current branch, validation and next step are stated at the top of this document and in `UI_NEXT_SESSION.md`.

## Markdown reader adapter phase (2026-10-17 — synthetic-only before endpoint integration)

- Added a bounded parser for headings, paragraphs, lists, tables, fenced code, block quotes, rules, inline code/emphasis, safe external links and reference-authorized internal links. It caps input at 65,536 characters, 4,096 lines, 2,048 blocks, 200 list/table rows per block and 512 reference records. It creates DOM elements/text nodes only; no `innerHTML` path was added.
- Added the user-triggered `POST /api/doc/content` adapter with strict selected-ID/response validation, UTF-8 byte accounting, stale-request gates, loading, 404/413/contract/network error states, and a responsive in-document search with highlighted matches and previous/next navigation.
- Separated a concise atomic live status from the full reader DOM so loading a long note does not announce the entire body at once. Internal document links dispatch through the existing selection flow; raw HTML and unknown local paths stay inert text.
- At this historical phase checkpoint, the API committed on `Frontend-Design` did not implement `/api/doc/content`; the local visual fixture route was explicitly synthetic and was not production integration. The authorized endpoint was later integrated from published `origin/main` after resolving the contract conflict, as recorded below.
- The synthetic browser rendered headings, list items, table headers/rows, code, a safe external link, internal reference, source citation and inert `<img ... onerror=...>` text. In-document search found three occurrences and navigation advanced from 1/3 to 2/3. Browser DOM checks found zero `<img>`/`<script>` elements and no horizontal overflow at the 694px browser viewport. Missing-endpoint fixture showed the 404 fallback and retained metadata/fragments.
- Final validation: 75 Node tests passed; syntax checks for the UI, fixture server and changed test modules passed; `git diff --check` passed. The premium strict audit returned 32 markup-only `actionless-button` findings (0 warnings), all matched to real ID-bound or delegated JavaScript handlers. Synthetic browser QA at 694px confirmed keyboard reader search, internal selection, raw HTML remaining text, no injected image/script nodes and no horizontal overflow; 404 and transport-failure fixtures retained metadata/context and showed recoverable feedback. Screen-reader certification and true browser zoom remain unverified.

## Backend reader integration preflight (2026-10-18 — resolved in the 2026-10-20 phase below)

- `git fetch origin` confirmed `main` at `5109981a794a41bb7b646beca61ad11045f18ea5` and `Frontend-Design` at `4dd4a23f647a067cff862496a21fcecb502b8717`.
- Read-only inspection confirmed the endpoint implementation in `origin/main`. `git merge-tree --write-tree Frontend-Design origin/main` found an add/add conflict in `FRONTEND_BACKEND_CONTRACT.md`.
- Per the requested conflict stop rule, no merge, cherry-pick, endpoint code copy, real-source read or endpoint test was performed. The UI branch remains unintegrated; the original checkout and its pending work were not modified.
- Resolution at that point: reconcile both contract files, then selectively import the reader module, endpoint-specific route and focused tests. This was completed in the following phase without merging the full backend commit.

## Authorized Markdown endpoint integration (2026-10-20)

- Rechecked the clean `Frontend-Design` starting point and fetched `origin`. `origin/main` remains at `5109981a794a41bb7b646beca61ad11045f18ea5`; the add/add contract conflict was resolved by preserving the UI API/view contract and importing the complete backend request, response, read, freshness, authorization, redaction and error requirements.
- Selectively imported `rabanito/document_content.py`, its focused tests and only the `/api/doc/content` server route/GET 405 behavior. No main merge, migration, unrelated backend module, project source, Obsidian file, or database write was performed.
- Connected the existing inspector button to the production route, added exact JSON/reference validation and local, non-sensitive error copy for 400/403/404/409/413/503. The existing safe Markdown renderer remains the sole renderer; fixtures remain test-only.
- Loopback API verification read one authorized active document from each configured source class (Obsidian, projects, internal memory), accepted the exact contract, and kept byte budgets. Negative checks covered GET 405, an extra caller `path` field 400, wrong Origin 403, missing ID 404 and a 128-byte read budget.
- Browser QA in the visible local dashboard used the actual source DB in read-only mode. It rendered a real Obsidian note with metadata and 100 recognized references, and a second 35,120-byte note with Markdown plus inspector metadata, cited fragments and explicit neighbors. The reader DOM contained semantic Markdown tags and no script/style/iframe/object/embed/img/svg elements; no absolute source root appeared in the page. Browser console log was empty. The screenshot viewport was 487×884; previously recorded 1920×1080 and 2560×1440 checks were geometry checks, not screenshots of this live note.
- Automated validation: focused Python endpoint tests **35 passed**; full Python suite **325 run, 324 passed, 1 skipped**; Node UI suite **76 passed, 0 failed**; syntax/bytecode checks and `git diff --check` passed.
- The temporary UI server exposed only read APIs plus `/api/doc/content`, used the original DB and roots without changing settings, and was stopped after QA. A read-only integrity check returned `ok` with zero foreign-key errors; the isolated listener is closed. Existing pending Sol changes remain in the separate original checkout.
- Still open: assistive-technology certification, browser zoom, real-index search/filter coverage beyond this reader flow, typed Knowledge Graph integration, and measured browser frame-time/heap at large graph sizes.

## Typed Knowledge Graph, Orbit and Hex phase (2026-10-20)

- Selectively brought the typed projection/query dependency closure from the published backend into this isolated branch and added strict loopback routes for `POST /api/knowledge-graph`, `/api/knowledge-graph/neighbors`, and user-confirmed `/api/knowledge-graph/sync`. No merge was performed. Read/page/neighbor requests do not synchronize; refresh is a single bounded batch after explicit confirmation.
- Extended the existing Neural Orbit, Hex Knowledge and Knowledge Tree with all 32 backend entity kinds, stable typed IDs, localized security labels, provenance/citations, explicit/suggested/inferred/reviewed-claim relation classes, cursor paging, and one-hop neighbor expansion. The document graph and existing Galaxy remain intact. The UI caps accumulation at 1,000 nodes and 4,000 edges.
- Real indexed graph QA used a copied SQLite snapshot opened read-only. The first page returned 180 of 51,992 candidates; an ATT&CK kind filter reported 706 candidates; selecting a technique fetched a cited one-hop relation. Hex grouped four real projects and 30 category cards; Tree showed the real project/type grouping. No imported note text was treated as instructions.
- Visual checks at 1920×1080 and 2560×1440 found no horizontal overflow. The Galaxy canvas mounted at 2560×1440 and the browser console had zero errors. Orbit/Hex mode switches, kind filtering, Tree labels, and typed Inspector metadata were visually checked.
- Rechecked the existing Markdown reader against an authorized indexed Obsidian document. The Inspector rendered 204 bytes and one resolved reference; a repeated read left source SHA-256, byte size and modification time equal to indexed metadata. No Obsidian, database, or index writes were made.
- Keyboard QA covered arrow selection, Enter, Escape, accessible node-list selection and reader reset; Escape also disables one-hop expansion. This does not certify behavior with a screen reader.
- A separate isolated fixture accessibility-tree and narrow-layout smoke exposed named roles for core filters, tabs, sliders and Inspector controls. Tab traversal reached theme, panel toggles, search and statistics. At 640×720 CSS pixels the Explorer stacked above the view without visible horizontal overflow. True browser zoom could not be driven reliably by the browser harness and no screen reader was available, so both remain open.
- Automated validation: focused Knowledge Graph suite **34/34 passed**; full Node UI suites **82 passed**; full Python suite **359 run, 358 passed, 1 skipped**. A 10,000-node/30,000-edge client input was capped to 1,000/4,000 with about 20 ms test-side layout time. This does not constitute browser frame-time or heap profiling.
- Future `main` compatibility was evaluated at published frontend head `6a6cd05e1a310a9d609a0015309705f01c37bc50` with merge base `4474bfc91bcc8145b1573dfa36831c5626c5fd76`. The non-worktree `git merge-tree` simulation found six conflicts: `FRONTEND_BACKEND_CONTRACT.md` and `rabanito/knowledge_graph/query.py` (add/add), plus `docs/API_CONTRACT.md`, `rabanito/cli.py`, `rabanito/server.py` and `tests/test_knowledge_graph.py`. CLI/server conflicts overlap with additional published backend work and need manual, file-by-file reconciliation to avoid dropping commands/routes; the query/test differences include the frontend's source-proof optimization and its focused regression. No merge occurred. Rerun against current refs before any future PR review.

### Remaining critical verification

- Screen-reader certification and browser zoom for typed filters, paging, inspector content, and error states.
- Browser-side frame-time and heap profiling on large real graphs; existing bounded-client tests and Python query timing are not browser performance measurements.
- Broader real-index QA across non-ATT&CK entity kinds and stale/unavailable/filter-combination cases, while keeping private document content out of logs and outputs.
