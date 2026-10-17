# Neural Command Center — master specification

## Mission

Develop the Neural Command Center for Rabanito Second Brain, inspired by the user's original video reference. Continue the existing `Frontend-Design` implementation in its isolated worktree. Preserve completed functionality, use real local API data in production, and do not rebuild working views or introduce simulated production data.

This document records the master mission supplied directly by the user on 2026-10-17. Its source is the conversation that originally delivered the video and master prompt; a verbatim prompt file is not required.

## Acceptance criteria and current state

| Area | Acceptance criteria | Current implementation and evidence | Remaining work |
|---|---|---|---|
| Neural Orbit | Radial interactive graph; real indexed nodes and relations; communities, zoom, connection visibility and navigation; meaningful empty/loading/error states. | Canvas graph uses `/api/graph`, supports selection, keyboard navigation, zoom/pan, filters, explicit vs. suggested edges and cached layout data. Node and synthetic browser checks cover core interactions and 1,000-node rendering. | Finish end-to-end source/project/category/query filter QA after fixture parity is corrected. Screen-reader access to graph structure remains open. |
| Hex Knowledge | Navigate graph records by indexed category and project, keep selection/focus state visible and operable by keyboard. | Groups use source/project/category metadata or explicitly labeled connected components; group selection focuses Orbit and exposes `aria-pressed`. | Confirm category/project behavior against the filtered API fixture and retain the distinction between connectivity and semantic communities. |
| Knowledge Galaxy 3D | Preserve the existing view and its controls, filtering and navigation while improving safe redraw performance. | Existing Canvas renderer with 3D projection/rotation is retained; graph lookup/adjacency are cached. Synthetic visual smoke covered 1,000 nodes. | Do not claim WebGL. Measure frame time and memory if reliable browser profiling becomes available. |
| Knowledge Tree | Provide a navigable hierarchy using real source metadata and explicit relations; do not invent parent/child structure. | Project-grouped records and a bounded explicit-relation list are implemented and covered by grouping/browser smoke. | Continue only when real indexed hierarchy data or an authorized typed graph endpoint is available. |
| Markdown Inspector | Show real document metadata and references; read Markdown through an authorized bounded endpoint; open the original only through the authorized API and report confirmed outcomes. | `/api/doc/{id}` metadata, cited `/api/context` fragments, explicit neighbors and `/api/open/{id}` are used. Success requires `opened: true`; imported text is rendered as text. | Full Markdown body requires an authorized bounded content endpoint; do not read source files directly or fabricate content. |
| Dashboard | Show real index statistics; search and filter by query, source, project, category and tag; navigate to results and related views. | Dashboard consumes local API endpoints. Neural Command Center search supports query, source, project and category; legacy search also sends exact tag. A synthetic fixture is used only for tests. | Validate all filter combinations through an API-level fixture test and browser smoke; run production-index QA only after safe integration is available. |
| Personalization | Provide themes, transparency, typography, animation controls and persistent user preferences without persisting knowledge queries/content. | Five themes and local preferences for layout, typography, density, zoom, graph colors/labels/link style and reduced motion. Tests/browser smoke cover theme and preference synchronization. | Continue accessibility checks for forced colors, zoom and screen readers where browser tooling supports reliable inspection. |
| Performance | Keep graph work bounded, avoid repeated derivation, and remain usable at 1080p and 1440p. | Graph requests cap at 1,000 nodes; Orbit and Galaxy reuse derived indexes. Geometry checks at 1920×1080, 2560×1440 and 380×787 passed without horizontal overflow. | Synthetic large-graph frame-time and memory measurements remain open; geometry/render smoke is not production performance certification. |
| Accessibility | Support keyboard operation, visible focus, live feedback, semantic controls and useful status announcements; verify with assistive technology when possible. | Keyboard navigation, splitters, reduced motion, status announcements, `aria-pressed`, `aria-current`, disclosure navigation and narrow layouts have regression/browser coverage. | Screen-reader certification and complete manual review of the legacy static audit findings remain open. |

## Prioritized remaining work

1. Complete filter parity in the local synthetic API fixture and cover `/api/search` and `/api/graph` source, project, category, query and tag behavior with functional tests. Then verify representative filters in the browser. The fixture must remain clearly synthetic and isolated from production data.
2. Review remaining legacy control/static accessibility findings against actual delegated event handlers and manually exercise safe read-only actions. Never activate mutation controls against a real index during this QA.
3. Run visual and keyboard checks at desktop and narrow sizes. Capture reliable frame-time/memory data for the synthetic 1,000-node case if browser profiling is available; report limitations plainly.
4. After backend APIs are independently reviewed and present, feature-detect the authorized Markdown body and typed cross-entity graph endpoints while preserving current fallbacks. Do not modify Sol's backend work from this worktree.
5. Keep screen-reader certification, live-index QA and any unavailable profiling open until evidence exists.

## Workflow and publication constraints

- Work only in the isolated worktree on `Frontend-Design`.
- Do not modify `main`, the original checkout, backend/Sol work, or live SQLite/Obsidian data.
- Never use simulated fixture content as production content.
- Run relevant tests and record actual results in `UI_TEST_RESULTS.md`, `UI_TASK_BACKLOG.md`, `UI_DEVELOPMENT_PROGRESS.md` and `UI_NEXT_SESSION.md`.
- Commit and push each validated phase only to `origin/Frontend-Design`; no merge or force-push.
