# UI next session checkpoint

## Starting state

- Continue in the dedicated linked worktree on branch `Frontend-Design` (not the original checkout).
- Initial audited base was `4474bfc91bcc8145b1573dfa36831c5626c5fd76`; confirm branch and remote before any publication.
- Do not merge/rebase `main`, modify the original checkout, or touch the backend agent's work.
- `origin` was verified as `https://github.com/Snowwiy/RabanitoSecondBrain.git`; publish only to `origin/Frontend-Design` and never force-push.

## Implemented checkpoint

See `UI_MASTER_SPEC.md`, `UI_DEVELOPMENT_PROGRESS.md`, `UI_ARCHITECTURE.md`, `UI_TEST_RESULTS.md`, `FRONTEND_BACKEND_CONTRACT.md`, and the capability matrix in `UI_TASK_BACKLOG.md`. Current UI verification is 66 passing Node tests. The last full Python run was 290 tests (1 skipped); Python was not rerun in the frontend-only fixture/accessibility phases because no backend code changed.

## Immediate safe next steps

1. Review the remaining premium static audit `actionless-button` findings against delegated handlers and manually exercise safe read-only legacy controls. Do not trigger indexing, source sync, relation writes or cyber sync during QA.
2. Test the bounded Orbit node list with a screen reader and browser zoom if those tools become available; the current accessibility tree and keyboard checks do not certify assistive technology.
3. Measure frame-time and memory for the synthetic 1,000-node graph only if the browser exposes reliable profiling. Exact 1920×1080 and 2560×1440 geometry passes without horizontal overflow; wide screenshots are capped at 1280px. Do not report synthetic performance as production certification.
4. Before publication, fetch and compare `origin/Frontend-Design`, stage only intended source/docs/tests, and verify the pushed SHA with `git ls-remote`. Never force-push or touch `main`.

## Known product limitations

- Complete Markdown reader and typed cross-entity Knowledge Graph depend on backend endpoints not present in the tested base; see `FRONTEND_BACKEND_CONTRACT.md`.
- The current Galaxy is the existing Canvas-based graph, not a newly implemented WebGL renderer.
- Visible browser QA covered desktop-sized 1264×715 and 380×787, using synthetic data only. Exact 1920×1080 and 2560×1440 geometry also passed without horizontal overflow, though wide captures are capped at 1280px. Production-data QA remains pending.
- `UI_MASTER_SPEC.md` records the master mission and acceptance criteria supplied directly in the conversation; line-by-line implementation status and remaining gaps are maintained in `UI_TASK_BACKLOG.md`.
- Keyboard and pointer-drag splitter adjustment are verified; the pointer handle must be targeted within its narrow 8px hit area. Screen-reader certification remains open.
- Source-open UI reports success only when the server response contains `opened: true`; synthetic `opened: false` was browser-verified as an error announcement.
- UI/backend shared files may conflict when the backend branch is integrated. Coordinate review; never replace concurrent changes wholesale.
