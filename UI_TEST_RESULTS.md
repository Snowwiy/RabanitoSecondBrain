# UI test results

Last verified: 2026-10-17. All browser checks used the loopback-only synthetic fixture server in `tests/neural_command_center_fixture_server.mjs`; the live index, Obsidian vault and operational SQLite database were not queried or modified.

## Automated

- `node --test tests/test_cyber_ui.mjs tests/test_graph_filter.mjs tests/test_neural_command_center.mjs tests/test_neural_command_center_fixture_api.mjs` — **75 passed, 0 failed, 0 skipped**. Coverage includes the bounded safe Markdown parser, reference authorization, raw HTML as inert text, capped fixture response fields, reader response shape, and a synthetic transport interruption, alongside the existing community, navigation, filter and accessibility regressions.
- `python -B -m unittest discover -s tests -q` — **290 run, 289 passed, 1 skipped, 0 failed**.
- `git diff --check` — passed after the final phase edits. Python was last run before both frontend-only phases; it was not rerun because no backend implementation changed.
- Premium UI audit `audit_project.py <worktree> --mode strict --output <temp>` — **32 errors, 0 warnings** (exit 1). Every finding is `affordance.actionless-button`. An audit-equivalent HTML scan matched all 32 flagged buttons to real ID-bound handlers or `data-module`/`data-view` delegated listeners across `web/index.html`, `web/knowledge.js` and `web/cyber.js`; no unbound control remained. Strict mode still exits 1 because the analyzer only inspects literal markup and cannot trace these JavaScript handlers. Safe read-only history/change refresh, audit, decision search, cited context and source preview actions were browser-verified; mutation controls were not activated. No inline no-op handlers were added. The latest JSON report was saved in the OS temp directory, outside the worktree, and was not staged.

## Browser QA

Using the local synthetic fixture server at `127.0.0.1:8877`, the visible browser confirmed:

- Three-panel layout and persistent synthetic-data notice.
- Search result selection, document metadata, tags/YAML keys, bounded cited fragment, relative source reference and explicit outgoing link.
- Orbit, Hex, legacy Galaxy and Tree tab switching.
- Legacy graph canvas mounted in Galaxy without overlapping the hidden Hex view (a CSS `[hidden]` regression was found and fixed).
- Search results wrap within the explorer after a visual overflow issue was found and corrected; explorer collapse/restore and preference disclosure worked.
- Global search for “Indexación” returned one synthetic result. “Limpiar búsqueda” removed the result immediately and restored focus to the empty field.
- Updated fixture filter QA: Orbit returned one node for `Proyectos`, two nodes/one explicit edge for project `Fixture Core`, one node for category `technical`, and one Obsidian node for the combined “Indexación” + `research` filters. The legacy dashboard search combined query “Recuperación”, category prefix `coding`, exact tag `#retrieval`, and project `Fixture Core`; it returned only the synthetic Coding Memory record. The screenshot provider showed the active category/project and single-node Orbit; all values remained marked as synthetic.
- Legacy Dashboard source-filter QA used the fixture's three synthetic built-in sources: query “Indexación” + category `research` + tag `#obsidian` returned one record when source was Obsidian; switching to Proyectos produced “Sin resultados.” Returning to Obsidian restored the one record. The screenshot showed the selected source and remaining filters.
- Safe legacy control QA: history/change refresh showed the expected empty states; the audit control rendered a `3/3` read-only synthetic drift report; decisions search showed its empty state; context retrieval rendered a bounded synthetic citation; source preview returned fixture-only sample names and offered approval without activating it. No index, audit-write, relation-write, exclusion or sync action was invoked.
- Legacy search announced “1 resultado local” for the matching fixture query and “Sin resultados locales para estos filtros” for a miss. Context retrieval announced “1 fragmento citado recuperado” separately from the full cited text. The browser accessibility tree exposed all three statuses; no console errors were logged.
- The dashboard's last-scan line rendered numeric counters (`+3 · ~0 · =0`) from the complete fixture record, without `undefined` values. Fixture audit/source-preview responses did not read host files.
- Panel transparency changed from 92 to 76 and text scale from 100 to 110; both survived reload and were restored to 92/100. The browser console error log was empty.
- Neural Orbit accessibility QA: the collapsed directory exposed three synthetic nodes with category/source/project labels and a selected state after activation. At 1,000 loaded nodes, it rendered only 25 entries at a time; the browser accessibility tree advanced from 1–25 to 26–50. Shift+Tab and Enter selected node 50 while retaining focus and populated the Inspector. A visual capture showed the bounded list below the 1,000-node Orbit. This verifies keyboard and browser accessibility-tree behavior, not screen-reader certification.
- Neural Orbit preview showed the fixture title, category/source/project metadata, validated relative path and `Grado · 2`. Clicking selected the node; Escape cleared selection; ArrowRight selected and announced the title. Dragging between two visible nodes panned the graph without selecting the node under release.
- Tree reports metadata grouping rather than asserting an undocumented architecture.
- Selecting a Hex group made it announce `Value: 1` after returning to Hex and applied the active-card treatment; “Centrar vista” cleared it back to `Value: 0`.
- The header reduced-motion toggle and preferences checkbox stayed synchronized when either control changed; both reported the same value in the accessibility tree.
- Module shortcuts opened nested Coding Memory and Cyber disclosures, moved focus to their summaries, and focused “Memoria de proyectos” from the Projects shortcut. The fixture does not provide Cyber query results; this confirmed navigation only.
- With the large synthetic fixture, the graph loaded progressively from 180 to 1,000 documents. The accessibility summary reached 1,000 entities and 999 loaded relations; Orbit, Hex (one explicit connected component), legacy Galaxy and Tree rendered at that limit. The data is synthetic; no production profiling was performed.
- After the Orbit layout-key optimization, five ArrowRight selection action round trips at 1,000 nodes measured 19–22 ms (median 21 ms), compared with 26–36 ms (median 29 ms) before the change. These include browser-driver overhead and are not isolated paint timings. Seven progressive load clicks measured 262–277 ms each including local fixture requests and automation overhead.
- Pointer-dragging from the center of the 8px Explorer splitter changed its accessible width from 230 to 234 and then 244; keyboard resizing had already been verified.
- Galaxy 3D at 1,000 synthetic nodes reported 1,000/1,000 visible nodes and 999 relations with suggestions unchecked. ArrowRight selected the first node; “aislar comunidad” showed its 2-node, 1-relation cluster. The Galaxy graph index was reused on redraws and invalidated by a new graph in the Node regression test.
- The large fixture previously treated the string `"0"` as enabled because JavaScript strings are truthy; it now follows the production API's accepted `1`/`true`/`yes` values. Browser verification confirmed the default excludes the single synthetic suggested edge.
- Authorized source opening now announces pending, success, HTTP failure and connection failure in the existing `operationStatus` live region. The test uses a response stub; no local document was opened during this phase.
- The command-center Inspector was exercised against the fixture's HTTP 200 `opened: false` response; it announced failure and restored the button. Unit coverage verifies `opened: true` is required for success.
- Exact viewport geometry at 1920×1080, 2560×1440 and 380×787 showed no horizontal overflow. At 380px, Explorer, Orbit and Inspector each measured 343px. The screenshot provider caps wide captures at 1280px; only the 380px and existing 1264px viewports were captured as full-width visual evidence.
- The browser console returned no errors during the final synthetic Inspector and responsive-geometry checks. This is limited to that fixture session.

Visible QA covered desktop-sized 1264×715 and 380×787 screenshots. In the narrow view, all five themes were selectable and Raven Neon was restored; Tab advanced from panel controls to global search; the explorer, graph and inspector stacked vertically. In the desktop-sized view, both splitters initialized their accessible widths from responsive CSS (230/270) and moved/restored with Left/Right. Setting minimum degree to 2 showed the summary as matching entities and loaded relations, without claiming every returned relation was visible. No live index, real Obsidian note, endpoint write, or real local document opening was used; the synthetic open request returned `opened: false`. Exact 1920×1080/2560×1440 geometry passed without horizontal overflow, but full-width screenshots are limited by the provider's 1280px capture width. The current browser driver has no hover-only pointer action, so the hover-only tooltip path is covered by hit-test tests and code review, not an isolated browser gesture. Pointer dragging worked after targeting the center of the splitter's 8px hit area; its accessible width changed from 230 to 244. Screen-reader testing remains unverified; Ctrl+plus/Ctrl+equal did not change browser zoom in this driver, so true browser-zoom behavior remains open. The final synthetic browser session returned no console errors; this is not a certification of all environments.

## Neural Orbit and Hex community phase (2026-10-17)

- `node --check web/knowledge.js`, `node --check tests/neural_command_center_fixture_server.mjs`, `node --check tests/test_neural_command_center.mjs`, and `git diff --check` passed.
- Community mode on the synthetic fixture showed 12 groups from the 180 graph nodes/179 explicit edges loaded in the initial view (the fixture contains 1,000 matching docs, but graph loading is progressive). Hex rendered cards in numeric order (`Comunidad 1` through `Comunidad 12`), exposed group names/counts/basis in the accessibility tree, and selecting a card switched to Orbit with the estimate disclaimer in live status. Screenshot review at 1264×715 found the grid and existing three-panel layout legible. All data was synthetic.
- Algorithm-only Node smoke on a separate deterministic synthetic graph of 1,000 nodes and 6,955 explicit edges returned 4 groups in 44 ms on this run. This is not a browser frame-time/heap profile or a production-data benchmark.

## Markdown reader adapter phase (2026-10-17)

- The parser and bounded synthetic API route pass tests; browser QA at 694px showed headings, lists, tables, code, an authorized internal navigation button, a safe HTTPS link and inert raw-HTML text. Search found 3 matches and keyboard navigation advanced to match 2.
- DOM inspection found no injected `img` or `script` elements, and the rendered article had no horizontal overflow at that viewport. The `--no-markdown` fixture returned 404 and retained the existing metadata/context view.
- A loopback fixture that reset the content request produced the visible status “No se pudo leer el Markdown: Failed to fetch”; the selected document metadata remained available, the read button was re-enabled, and the empty reader stayed hidden.
- The browser driver did not provide a screen-reader certification or reliable browser-zoom control. Production body-reading remains unverified because the tested backend has no `/api/doc/content` route; fixture content is synthetic only.

## Still unverified

- Full-width screenshots at 1920×1080 / 2560×1440; geometry was checked without horizontal overflow, but the screenshot provider caps captures at 1280px.
- Browser zoom and screen-reader testing.
- Large real index / 10k+ graph performance. Current cap and synthetic fixture do not prove production-scale performance.
- Orbit and Galaxy now reuse derived graph data when their graph/layout inputs are unchanged. The synthetic 1,000-node render and interaction smoke passed, but no frame-time/memory profile or real-index benchmark has been recorded.
- Production full-body Markdown reading remains blocked: the current production API returns metadata plus bounded context and has no `POST /api/doc/content`. The UI adapter passed synthetic-fixture browser/API checks; a separate 404 fixture confirmed the unavailable state preserves metadata and cited fragments.
- New typed cross-entity graph API; it is absent from this branch baseline.
