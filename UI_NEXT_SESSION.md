# UI next session checkpoint

## Starting state

- Continue in the dedicated linked worktree on branch `Frontend-Design` (not the original checkout).
- Initial audited base was `4474bfc91bcc8145b1573dfa36831c5626c5fd76`; confirm branch and remote before any publication.
- Do not merge/rebase `main`, modify the original checkout, or touch the backend agent's work.
- `origin` was verified as `https://github.com/Snowwiy/RabanitoSecondBrain.git`; publish only to `origin/Frontend-Design` and never force-push.

## Implemented checkpoint

See `UI_MASTER_SPEC.md`, `UI_DEVELOPMENT_PROGRESS.md`, `UI_ARCHITECTURE.md`, `UI_TEST_RESULTS.md`, `FRONTEND_BACKEND_CONTRACT.md`, and the capability matrix in `UI_TASK_BACKLOG.md`. Current UI verification is 69 passing Node tests. The last full Python run was 290 tests (1 skipped); Python is not rerun in frontend-only fixture/accessibility phases because no backend code changed. The latest phases add synthetic stats/audit/source-preview coverage, atomic search/context announcements, all-32-button handler mapping for the static audit heuristic, and an Orbit cache-key optimization measured against the 1,000-node fixture.

## Immediate safe next steps

1. Test the bounded Orbit list with a screen reader and verify browser zoom only if reliable tools become available; browser AX/keyboard checks do not certify assistive technology, and Ctrl+plus/Ctrl+equal had no effect.
2. Keep the authorized Markdown-body reader and typed cross-entity graph pending until reviewed backend endpoints exist. Preserve current fallbacks; do not read files directly or synthesize content/entities.
3. If an isolated browser profiler becomes available, measure 1,000-node frame time and heap. Current ArrowRight timings are browser-driver round trips (26–36 ms before, 19–22 ms after) and do not represent paint time; geometry at 1920×1080 and 2560×1440 remains overflow-free.
4. Before the next publication, fetch and compare `origin/Frontend-Design`, stage only intended source/docs/tests, and verify the pushed SHA with `git ls-remote`. Never force-push or touch `main`.

## Known product limitations

- Complete Markdown reader and typed cross-entity Knowledge Graph depend on backend endpoints not present in the tested base; see `FRONTEND_BACKEND_CONTRACT.md`.
- The current Galaxy is the existing Canvas-based graph, not a newly implemented WebGL renderer.
- Visible browser QA covered desktop-sized 1264×715 and 380×787, using synthetic data only. Exact 1920×1080 and 2560×1440 geometry also passed without horizontal overflow, though wide captures are capped at 1280px. Production-data QA remains pending.
- `UI_MASTER_SPEC.md` records the master mission and acceptance criteria supplied directly in the conversation; line-by-line implementation status and remaining gaps are maintained in `UI_TASK_BACKLOG.md`.
- Keyboard and pointer-drag splitter adjustment are verified; the pointer handle must be targeted within its narrow 8px hit area. Screen-reader certification remains open.
- Source-open UI reports success only when the server response contains `opened: true`; synthetic `opened: false` was browser-verified as an error announcement.
- UI/backend shared files may conflict when the backend branch is integrated. Coordinate review; never replace concurrent changes wholesale.
