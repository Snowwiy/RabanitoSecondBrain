# UI next session checkpoint

## Current state — 2026-10-20

- Work exclusively in the isolated linked worktree on `Frontend-Design`; never edit `main` or the original backend worktree.
- The latest fetched refs before this phase were `origin/main` = `5109981a794a41bb7b646beca61ad11045f18ea5` and `origin/Frontend-Design` = `1eaf2c1c3814bb7bb5680ca619a89b17e78aec99`. The integration edits are validated locally and must be committed/pushed only to `origin/Frontend-Design`.
- The sole add/add conflict (`FRONTEND_BACKEND_CONTRACT.md`) has been reconciled by preserving both the UI and backend contract requirements. No merge of the backend commit was performed.
- `POST /api/doc/content` and the minimal dependency closure are now available in this frontend worktree. The existing Inspector requests the selected indexed ID with a 65,536-byte budget, validates exact response fields/references and renders with the existing safe Markdown DOM parser.
- Read-only loopback API checks succeeded for authorized Obsidian, project and internal-memory documents. Visible browser QA rendered real Obsidian Markdown, metadata, explicit neighbors and 100 recognized references. Stale, size, invalid ID, wrong origin and extra-path failures are covered by backend/frontend checks.
- Validation: **35 focused Python tests passed; full Python suite 325 run (324 passed, 1 skipped); 76 Node tests passed; syntax/bytecode checks and `git diff --check` passed.** Read-only SQLite integrity check returned `ok` and zero FK errors. Temporary server stopped; listener closed. No source/index write or index/sync operation was enabled or invoked.
- See `UI_MASTER_SPEC.md`, `UI_DEVELOPMENT_PROGRESS.md`, `UI_ARCHITECTURE.md`, `UI_TEST_RESULTS.md`, `FRONTEND_BACKEND_CONTRACT.md` and the capability matrix in `UI_TASK_BACKLOG.md` for the reconciled state.

## Immediate next steps

1. Review the final diff and commit the validated phase. Push only `HEAD:Frontend-Design`; never force-push, merge into `main`, or touch the original checkout. Verify the resulting remote SHA and clean branch status.
2. Continue remaining work by priority: typed cross-entity Knowledge Graph only after its read-only contract is reviewed; targeted real-index search/filter and legacy read-only panel QA; screen-reader and browser-zoom checks; isolated large-graph frame-time/heap measurement.
3. Keep the current document-graph fallback and topology disclaimer. Do not call topology groups semantic communities or claim WebGL/browser performance measurements without evidence.

## Reader contract and safeguards

- The endpoint accepts exactly `document_id` and `max_bytes`; never pass caller paths or private filters. GET returns 405, request framing/origin/body are bounded, and the response uses no-store.
- Current authorization, active source/project visibility, exclusions, nested-project boundaries and file identity/freshness are rechecked at read time. A stale/unavailable source returns 409; do not reindex automatically.
- The bounded read uses a read-only handle and may redact detectable credentials/absolute paths. This is defense in depth, not universal DLP; configured source exclusions remain necessary.
- The synthetic fixture reader remains test-only. Do not use fixture content as real data or perform `index`, `sync`, source approval, source opening or mutation actions during read-only verification.

## Known remaining gaps

- No typed cross-entity Knowledge Graph endpoint is integrated; the document graph is the current verified fallback.
- Browser AX and keyboard checks do not certify screen-reader behavior; browser zoom was not verifiable with the current driver.
- Geometry checks at 1920×1080, 2560×1440 and 380×787 remain layout checks. No isolated canvas frame-time/heap profile or 10k+ production graph benchmark exists.
- Real-index validation in this phase covered read-only stats, three document source kinds and the Inspector, not the full search/filter and legacy-panel surface.
