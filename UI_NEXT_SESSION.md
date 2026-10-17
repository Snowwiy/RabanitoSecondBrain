# UI next session checkpoint

## Starting state

- Continue in the dedicated linked worktree on branch `Frontend-Design` (not the original checkout).
- Initial audited base was `4474bfc91bcc8145b1573dfa36831c5626c5fd76`; confirm branch and remote before any publication.
- Do not merge/rebase `main`, modify the original checkout, or touch the backend agent's work.
- `origin` was verified as `https://github.com/Snowwiy/RabanitoSecondBrain.git`; publish only to `origin/Frontend-Design` and never force-push.

## Implemented checkpoint

See `UI_MASTER_SPEC.md`, `UI_DEVELOPMENT_PROGRESS.md`, `UI_ARCHITECTURE.md`, `UI_TEST_RESULTS.md`, `FRONTEND_BACKEND_CONTRACT.md`, and the capability matrix in `UI_TASK_BACKLOG.md`. The Markdown-reader phase now has 75 passing Node tests; browser QA covered the synthetic reader, keyboard search navigation, inert HTML, unavailable-endpoint fallback and transport-error feedback. The last full Python run was 290 tests (1 skipped); Python was not rerun because this phase changes only frontend code and synthetic fixtures. The graph phase adds deterministic multi-level topology estimates for explicit-link communities, Hex navigation/color support and numeric ordering; a separate 1,000-node/6,955-edge Node smoke took 44 ms, not a browser frame-time measurement.

## Immediate safe next steps

1. Backend work needed: implement and independently review ID-only `POST /api/doc/content` with the response contract in `FRONTEND_BACKEND_CONTRACT.md`; verify the current UI adapter against that real authorized route while preserving the visible 404 fallback. Do not read files directly.
2. Keep the typed cross-entity graph behind a reviewed read-only API and retain the existing graph fallback.
3. Test the bounded Orbit list with a screen reader and verify browser zoom only if reliable tools become available; browser AX/keyboard checks do not certify assistive technology, and Ctrl+plus/Ctrl+equal had no effect.
4. If an isolated browser profiler becomes available, measure 1,000-node frame time and heap. Current ArrowRight timings are browser-driver round trips (26–36 ms before, 19–22 ms after) and do not represent paint time; the 44 ms community result is Node-only. Geometry at 1920×1080 and 2560×1440 remains overflow-free.
5. Before publication, fetch and compare `origin/Frontend-Design`, stage only intended source/docs/tests, and verify the pushed SHA with `git ls-remote`. Never force-push or touch `main`.

## Known product limitations

- The Markdown reader adapter is implemented and tested against a synthetic fixture, but production full-body reading depends on the backend endpoint not present in the tested base. Typed cross-entity Knowledge Graph also depends on a reviewed backend API; see `FRONTEND_BACKEND_CONTRACT.md`.
- The current Galaxy is the existing Canvas-based graph, not a newly implemented WebGL renderer.
- Visible browser QA covered desktop-sized 1264×715 and 380×787, using synthetic data only. Exact 1920×1080 and 2560×1440 geometry also passed without horizontal overflow, though wide captures are capped at 1280px. Production-data QA remains pending.
- `UI_MASTER_SPEC.md` records the master mission and acceptance criteria supplied directly in the conversation; line-by-line implementation status and remaining gaps are maintained in `UI_TASK_BACKLOG.md`.
- Orbit and Hex communities are deterministic topology estimates derived only from loaded explicit edges. They are not backend-typed or semantic communities; fixture QA saw 180 loaded nodes/179 relations out of 1,000 matching docs.
- Keyboard and pointer-drag splitter adjustment are verified; the pointer handle must be targeted within its narrow 8px hit area. Screen-reader certification remains open.
- Source-open UI reports success only when the server response contains `opened: true`; synthetic `opened: false` was browser-verified as an error announcement.
- UI/backend shared files may conflict when the backend branch is integrated. Coordinate review; never replace concurrent changes wholesale.
