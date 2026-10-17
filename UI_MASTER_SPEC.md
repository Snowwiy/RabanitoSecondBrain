# Neural Command Center — master specification

## Mission

Develop the Neural Command Center for Rabanito Second Brain, inspired by the user's original video reference. Continue the existing `Frontend-Design` implementation in its isolated worktree. Preserve completed functionality, use real local API data in production, and do not rebuild working views or introduce simulated production data.

This document records the master mission supplied directly by the user on 2026-10-17. Its source is the conversation that originally delivered the video and master prompt; a verbatim prompt file is not required.

## Acceptance criteria and current state

| Area | Acceptance criteria | Current implementation and evidence | Remaining work |
|---|---|---|---|
| Neural Orbit | Radial interactive graph; real indexed nodes and relations; communities, zoom, connection visibility and navigation; meaningful empty/loading/error states. | Canvas graph uses `/api/graph`, supports selection, keyboard navigation, zoom/pan, filters, explicit vs. suggested edges and cached layout data. A collapsed native node list exposes 25 entries per page with metadata, selected state, and previous/next controls. Browser accessibility-tree QA confirmed keyboard selection and pagination across a 1,000-node fixture. | Screen-reader certification remains open. |
| Hex Knowledge | Navigate graph records by indexed category and project, keep selection/focus state visible and operable by keyboard. | Groups use source/project/category metadata or explicitly labeled connected components; group selection focuses Orbit and exposes `aria-pressed`. The filtered API fixture and browser smoke verified the category/project filters. | Retain the distinction between graph connectivity and semantic communities; typed entities await a reviewed backend endpoint. |
| Knowledge Galaxy 3D | Preserve the existing view and its controls, filtering and navigation while improving safe redraw performance. | Existing Canvas renderer with 3D projection/rotation is retained; graph lookup/adjacency are cached. Synthetic visual smoke covered 1,000 nodes. | Do not claim WebGL. Measure frame time and memory if reliable browser profiling becomes available. |
| Knowledge Tree | Provide a navigable hierarchy using real source metadata and explicit relations; do not invent parent/child structure. | Project-grouped records and a bounded explicit-relation list are implemented and covered by grouping/browser smoke. | Continue only when real indexed hierarchy data or an authorized typed graph endpoint is available. |
| Markdown Inspector | Show real document metadata and references; read Markdown through an authorized bounded endpoint; open the original only through the authorized API and report confirmed outcomes. | `/api/doc/{id}` metadata, cited `/api/context` fragments, explicit neighbors and `/api/open/{id}` are used. Success requires `opened: true`; imported text is rendered as text. | Full Markdown body requires an authorized bounded content endpoint; do not read source files directly or fabricate content. |
| Dashboard | Show real index statistics; search and filter by query, source, project, category and tag; navigate to results and related views. | Dashboard consumes local API endpoints. Neural Command Center search supports query, source, project and category; legacy search also sends exact tag. Isolated fixture tests cover filters, complete scan counters, read-only audit metadata and a source-preview response restricted to `C:\fixture`. Browser QA exercised history/change refresh, audit, decision search, cited context and source preview; no write action was activated. | Run production-index QA only after safe integration is available; fixture content remains synthetic. |
| Personalization | Provide themes, transparency, typography, animation controls and persistent user preferences without persisting knowledge queries/content. | Five themes and local preferences for layout, typography, density, zoom, transparency, graph colors/labels, link style and reduced motion. Browser QA changed panel transparency 92→76 and text scale 100→110; both survived reload and were reset to defaults. | Continue accessibility checks for forced colors, browser zoom and screen readers where reliable tools are available. |
| Performance | Keep graph work bounded, avoid repeated derivation, and remain usable at 1080p and 1440p. | Graph requests cap at 1,000 nodes; Orbit and Galaxy reuse derived indexes. Geometry checks at 1920×1080, 2560×1440 and 380×787 passed without horizontal overflow. | Synthetic large-graph frame-time and memory measurements remain open; geometry/render smoke is not production performance certification. |
| Accessibility | Support keyboard operation, visible focus, live feedback, semantic controls and useful status announcements; verify with assistive technology when possible. | Keyboard navigation, splitters, reduced motion, status announcements, `aria-pressed`, `aria-current`, disclosure navigation and a paginated accessible Orbit node list have regression/browser coverage. Safe legacy read-only actions were manually exercised. | Screen-reader certification, true browser-zoom verification and remaining static audit review remain open. |

## Prioritized remaining work

1. Finish mapping remaining static `actionless-button` findings to delegated handlers. The safe read-only subset exercised this phase is documented in `UI_TEST_RESULTS.md`; do not activate index, sync, relation-write or approval actions during that review.
2. Run the Orbit list through a screen reader and verify browser zoom when those tools are available. This browser driver did not apply zoom keyboard shortcuts; the accessibility tree and keyboard checks are not assistive-technology certification.
3. Run visual and keyboard checks at desktop and narrow sizes. Capture reliable frame-time/memory data for the synthetic 1,000-node case if browser profiling is available; report limitations plainly.
4. After backend APIs are independently reviewed and present, feature-detect the authorized Markdown body and typed cross-entity graph endpoints while preserving current fallbacks. Do not modify Sol's backend work from this worktree.
5. Keep screen-reader certification, live-index QA and any unavailable profiling open until evidence exists.

## Workflow and publication constraints

- Work only in the isolated worktree on `Frontend-Design`.
- Do not modify `main`, the original checkout, backend/Sol work, or live SQLite/Obsidian data.
- Never use simulated fixture content as production content.
- Run relevant tests and record actual results in `UI_TEST_RESULTS.md`, `UI_TASK_BACKLOG.md`, `UI_DEVELOPMENT_PROGRESS.md` and `UI_NEXT_SESSION.md`.
- Commit and push each validated phase only to `origin/Frontend-Design`; no merge or force-push.
