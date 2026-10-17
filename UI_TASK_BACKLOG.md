# UI task backlog

## Completed in this branch checkpoint

- [x] Add three-panel Neural Command Center around the existing dashboard.
- [x] Add five themes and locally persisted visual preferences, excluding knowledge queries/content.
- [x] Implement real API-backed Orbit, metadata-grouped Hex, legacy Galaxy reuse, and metadata-grouped Tree.
- [x] Add bounded search, filters, keyboard/pointer navigation, selection, cited Inspector fragments and authorized source-open action.
- [x] Keep suggested relations distinct and avoid invented hierarchy/community claims.
- [x] Add local synthetic fixture server and pure-function/XSS-boundary tests.
- [x] Document current API boundary and integration limitations.
- [x] Run 51 Node UI tests and 290 Python tests (1 skipped); `git diff --check` passes.
- [x] Final synthetic browser smoke pass: search/selection/inspector, four view tabs, legacy graph mount, panel collapse/restore and preference disclosure.
- [x] Fix narrow search-card horizontal overflow and add a regression check.

## Remaining before merge to `main`

1. Review the premium static audit's 32 `actionless-button` findings against delegated event handlers; do not add fake inline handlers. Manually test remaining legacy controls when integration QA is scheduled.
2. Complete browser coverage for theme switching, splitters, keyboard focus traversal, narrow responsive behavior, and exact 1920×1080 / 2560×1440 viewports when supported.
3. Add test coverage for graph filters / bounded payload handling if any uncovered bug is found; do not expand scope cosmetically.
4. Verify the exact viewport breakpoints and visual QA at 1920×1080 and 2560×1440 when the browser can expose those viewports.
5. Integrate only after the backend branch is reviewed: feature-detect the typed graph API and authorized Markdown-content endpoint, or retain the documented fallback/pending states.
6. Run UI + Python regression tests against the integrated tree without invoking index, sync, or SQLite writes.
7. Review conflicts in `web/index.html` and `web/knowledge.js` with the backend author; do not overwrite concurrent backend changes.
8. Create a reviewed PR to `main` after integration validation; do not merge automatically.

## Explicitly out of scope here

- Editing backend modules, migrations, or the live SQLite database.
- Installing UI packages, external assets, fonts, telemetry, or CDNs.
- Full Markdown rendering before the backend offers an ID-only, authorized, bounded content endpoint.
- Claiming WebGL, semantic communities, architecture hierarchy, or production performance tests that have not been implemented and verified.
