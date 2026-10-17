# UI test results

Last verified: 2026-10-17. All browser checks used the loopback-only synthetic fixture server in `tests/neural_command_center_fixture_server.mjs`; the live index, Obsidian vault and operational SQLite database were not queried or modified.

## Automated

- `node --test tests/test_cyber_ui.mjs tests/test_graph_filter.mjs tests/test_neural_command_center.mjs` — **52 passed, 0 failed, 0 skipped**.
- `python -B -m unittest discover -s tests -q` — **290 run, 289 passed, 1 skipped, 0 failed**.
- `git diff --check` — passed after the final phase edits.
- Premium UI audit `audit_project.py <worktree> --mode strict --no-write` — **32 errors, 0 warnings**. Every finding is `affordance.actionless-button`: the static audit cannot discover buttons wired by the existing `web/knowledge.js` module/delegated handlers. Representative new actions were browser-verified; not every legacy dashboard action received a manual click-through. No audit writes were requested.

## Browser QA

Using the local synthetic fixture server at `127.0.0.1:8877`, the visible browser confirmed:

- Three-panel layout and persistent synthetic-data notice.
- Search result selection, document metadata, tags/YAML keys, bounded cited fragment, relative source reference and explicit outgoing link.
- Orbit, Hex, legacy Galaxy and Tree tab switching.
- Legacy graph canvas mounted in Galaxy without overlapping the hidden Hex view (a CSS `[hidden]` regression was found and fixed).
- Search results wrap within the explorer after a visual overflow issue was found and corrected; explorer collapse/restore and preference disclosure worked.
- Global search for “Indexación” returned one synthetic result. “Limpiar búsqueda” removed the result immediately and restored focus to the empty field.
- Tree reports metadata grouping rather than asserting an undocumented architecture.

Observed browser viewport was approximately 1265×715. No live index, real Obsidian note, endpoint write, or source opening was used. The fixture server was shut down after QA. Browser console-log collection was unavailable in the current driver, so this is not a console-clean certification.

## Still unverified

- Exact 1920×1080 and 2560×1440 viewport QA, browser zoom and screen-reader testing.
- Exact 1920×1080 and 2560×1440 viewport QA, browser zoom and screen-reader testing.
- Large real index / 10k+ graph performance. Current cap and synthetic fixture do not prove production-scale performance.
- Full Markdown reading; current tested API returns metadata plus bounded context, not the complete body.
- New typed cross-entity graph API; it is absent from this branch baseline.
