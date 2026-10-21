# UI integration plan

## Combined integration checkpoint (2026-10-21)

- Integration worktree: dedicated branch `integration/rabanito-3.0`; `origin/main` backend base `c1f11ce12240caf2a085cc299ddf243676095da6`; `origin/Frontend-Design` source `39b572f28dc6f60915d44bc8b6ad790f78d1c386`. This section is authoritative for the combined integration; historical Frontend-Design preflights below describe earlier phases.
- `integration/rabanito-3.0` was fast-forwarded from its prior remote commit `5109981a794a41bb7b646beca61ad11045f18ea5` to `origin/main`, then merged with `origin/Frontend-Design` locally. No changes were made to either source branch. Full Python/Node suites and live pagination QA now pass; the worktree is ready for commit and publication to this integration branch only.
- Seven textual conflicts were resolved individually:

| File | Resolution retained from Sol/backend | Resolution retained from Luna/frontend | Validation or reason |
|---|---|---|---|
| `FRONTEND_BACKEND_CONTRACT.md` | Reader endpoint authorization, freshness, byte limits, errors and safe-path details | UI adapter, graph views, bounded typed graph behavior and error states | Combined contract; reader and graph suites plus live loopback QA |
| `docs/API_CONTRACT.md` | Current routes, security controls, CLI/backend feature contracts | Neural Command Center consumers and UI limits | Backend API inventory retained; additive consumer section |
| `rabanito/cli.py` | Entire current `main` CLI including Cyber, ATT&CK, Zero Trust, Coding Memory and dependency-analysis commands | No frontend CLI implementation required | Backend file retained whole; frontend is served through existing dashboard |
| `rabanito/knowledge_graph/query.py` | Current authorization, source eligibility, budgets, stale-input checks and typed query implementation | Persisted proof fast path and fallback when the proof is absent/invalid | 43 focused KG/query tests; full Python suite |
| `rabanito/knowledge_graph/store.py` | Current input eligibility, project/source authorization and path exclusions | Compatible graph projection inputs required by the UI | Backend implementation retained; graph and API regressions passed |
| `rabanito/server.py` | Current backend routes, request validation, duplicate-key rejection and safe reader/API behavior | Typed graph routes plus strict Knowledge Graph URL guard | Full Python suite; same-origin route/API tests |
| `tests/test_knowledge_graph.py` | Backend authorization, staleness, and graph behavior tests | Persisted-proof reuse and fallback coverage | Combined tests retained; 43 focused graph tests passed |

- `rabanito/cli.py` and `server.py` resolve to `main` as the implementation base; the frontend adds no CLI behavior and contributes only bounded UI consumers and the explicit typed graph route guard. No user source, SQLite database, key, or note was staged.
- A live typed-graph walkthrough found two pagination defects and both are fixed: neighbor expansion no longer replaces the main page cursor, and page continuation reuses the page size because the backend cursor binds it to query scope. The 180-node first page plus six one-hop neighbors continued successfully to 365 visible nodes from 51,988 candidates.
- Test and visual evidence, including viewport and tooling limitations, is recorded in `UI_TEST_RESULTS.md`. This checkpoint does not authorize merging the future PR to `main`.

## Isolation facts

- Branch: `Frontend-Design`, dedicated linked worktree (local path intentionally omitted from published docs).
- Worktree base: `4474bfc91bcc8145b1573dfa36831c5626c5fd76` on the initial audit. Verify `origin/Frontend-Design` before publishing each phase.
- Main checkout remains on its original branch and contains concurrent backend work. Do not change it or cherry-pick its uncommitted files.
- UI work is confined to this linked worktree. Do not use the shared SQLite or execute `index`, `sync`, audit-write, project exclusion, or source mutation operations during UI verification.

## Reader and typed Knowledge Graph integration status (2026-10-20)

The authorized Markdown reader and typed Knowledge Graph are integrated in this isolated branch. The reader's add/add contract requirements were reconciled in the frontend branch by retaining both the UI/API requirements and backend security contract. Backend code was selectively copied from published `origin/main` with its focused dependency closures; no backend-wide merge or schema migration was performed. The typed graph phase is published as `6a6cd05e1a310a9d609a0015309705f01c37bc50` on `origin/Frontend-Design`.

1. The reader integration remains published as `a5ea26b9f1156fb3fd879283c77f530b5f61949b`; the previous checkpoint is `515cc257906dbd9bc67bfbab81541b6e966542a0`; the typed graph phase is `6a6cd05e1a310a9d609a0015309705f01c37bc50`. `origin/main` remains `5109981a794a41bb7b646beca61ad11045f18ea5`.
2. Typed routes now use the backend's strict contract. Page and one-hop reads are read-only, and refresh is separately confirmed and bounded. The document graph remains available as fallback.
3. Current phase QA is recorded in `UI_TEST_RESULTS.md`: 82 Node tests, 359 Python tests (1 skipped), real indexed graph checks, read-only Obsidian reader recheck, and 1920×1080 / 2560×1440 visual geometry.
4. Remaining critical work is browser-side frame-time/heap profiling, screen-reader/browser-zoom verification, and broader non-ATT&CK and stale/error real-index coverage.
5. Any future `Frontend-Design` → `main` integration remains a separately reviewed PR operation. Do not merge it automatically.

## Future PR compatibility assessment (read-only, 2026-10-20)

- Audited refs: merge base `4474bfc91bcc8145b1573dfa36831c5626c5fd76`, `origin/main` `5109981a794a41bb7b646beca61ad11045f18ea5`, functional `Frontend-Design` phase `6a6cd05e1a310a9d609a0015309705f01c37bc50`; the same simulation was repeated after docs checkpoint `6c5972b6b63cbcee449a076fb9fce12a591f4485`.
- `git merge-tree --write-tree origin/main origin/Frontend-Design` reported six conflict paths without modifying the worktree: `FRONTEND_BACKEND_CONTRACT.md` (add/add), `docs/API_CONTRACT.md` (content), `rabanito/cli.py` (content), `rabanito/knowledge_graph/query.py` (add/add), `rabanito/server.py` (content), and `tests/test_knowledge_graph.py` (add/add). Other paths auto-merged in the simulation.
- The CLI overlap is substantial: the main-side file contains many backend commands/features absent from this branch, so retaining the entire frontend side risks deleting them. The server must preserve the main backend routes/security changes and the reader plus typed graph routes. The query and graph-test conflicts are narrower, reflecting the frontend proof optimization and its test updates. Reconcile both contracts and each file deliberately; do not resolve by choosing an entire side.
- This is a compatibility assessment only. Re-run against current refs before future PR preparation. It does not authorize opening a PR or performing a merge.

## Frontend/backend integration matrix

| Endpoint / data contract | Availability on tested branch | Frontend consumer | Verified format and tests | Integration state / blocker |
|---|---|---|---|---|
| `GET /api/health`, `/api/stats`, `/api/projects`, `/api/categories`, `/api/tags`, `/api/sources` | Present in the committed dashboard API; synthetic fixture covers these shapes. | Header, Dashboard, filter options, project list. | Counts, latest scan, inventory and synthetic sources; fixture API tests. | Integrated on the documented base; repeat read-only verification after backend merge. |
| `POST /api/search`, `POST /api/context` | Present. | Global and legacy search, Inspector fragments, retrieved context. | Query/filter results and cited fragment shape; isolated API test plus browser smoke. | Integrated; fixture content must never be treated as production. |
| `POST /api/graph` | Present. The typed graph is exposed separately. | Document-graph fallback for Neural Orbit, Hex, Tree and Galaxy. | Nodes/edges, filtering, relation kinds and truncation; fixture API + browser smoke through 1,000 synthetic records. | Integrated fallback; deterministic layout/topological groups are not semantic claims. |
| `POST /api/knowledge-graph`, `/neighbors`, `/sync` | Selectively integrated from published backend dependency closure on `Frontend-Design`; `/sync` remains explicitly confirmed. | Typed Neural Orbit, Hex Knowledge and Knowledge Tree; Inspector uses authorized Markdown only for document nodes. | 34 focused Python tests; 82 Node tests; full suite 359 Python tests (1 skipped); real indexed 180/51,992 page, ATT&CK filter and cited neighbor; visual checks at 1920×1080 and 2560×1440. | Read/page/neighbor requests are read-only; 1,000-node/4,000-edge UI accumulation cap. Screen-reader/zoom and browser heap/frame profiling remain open. |
| `GET /api/doc/{id}`, `GET /api/related/{id}`, `POST /api/open/{id}` | Present in the documented base. | Inspector metadata/neighbors and authorized source opening. | Metadata, related records and open confirmation (`opened: true`); safe-open response behavior tested. | Integrated; do not pass caller-supplied paths. |
| `POST /api/doc/content` `{document_id,max_bytes}` | Integrated into `Frontend-Design` from published `origin/main` commit `5109981a794a41bb7b646beca61ad11045f18ea5`; exact ID-only, read-only contract documented. | User-triggered safe Markdown reader, authorized inline references and in-document search. | 35 focused Python endpoint tests; full 325-test Python suite (1 skipped); 76 Node tests; real loopback reads from authorized Obsidian, projects and internal memory; browser-rendered real Obsidian Markdown with metadata, references and explicit neighbors. Negative HTTP checks include 405/400/403/404 and bounded reads. Recheck this phase confirmed Obsidian source identity metadata stayed equal to the indexed values. | Integrated and already published at `a5ea26b9` on `origin/Frontend-Design`; no full main merge, reindex or source write. |
| `POST /api/cyber/status`, `/api/cyber/search`, `/api/cyber/get`, `/api/cyber/sync` | Existing dashboard connector routes are consumed by the Cyber panel. Fixture exposes status/navigation only and has no vulnerability results. | CVE/CISA KEV/CVSS/EPSS panel and explicitly user-triggered public-data refresh. | UI adapter and response normalization in `web/cyber.js`; synthetic browser verified navigation only. | UI is wired; production coverage/provenance freshness must be verified against reviewed backend responses after integration. Never treat fixture counts as real. |
| `POST /api/security/search`, `/api/security/get` | Existing dashboard routes consumed by the local standards/Zero Trust panel. | Standards and controls library. | Safe reference linking and selected-record rendering in `web/knowledge.js`; fixture has no real catalog records. | UI is wired; verify real edition/source metadata and bounded relations after integration. |
| `POST /api/coding/patterns`, `/api/coding/similar`, `POST /api/decisions` | Existing dashboard routes. | Coding Memory and architecture decisions. | Existing legacy consumers retained; fixture verifies decisions empty state and panel navigation. | UI is preserved; verify real reviewed-record and source-citation semantics after integration. |
| Preferences/local graph controls | Browser-only; no backend route. | Theme, typography, transparency, movement, graph labels/density, layout and resizable panels. | Five themes, reduced-motion synchronization, local persistence and reload smoke. | Integrated; queries and Markdown body are not written to local storage. |

## Safe preview

For visual QA only, run `node tests/neural_command_center_fixture_server.mjs 8877` from this worktree and browse `http://127.0.0.1:8877/`. It serves only the three local web assets and synthetic API payloads, binds to loopback, disables source opening, and visibly labels all displayed values as fixtures. Stop the process after verification. Do not point it at the live Second Brain API or the fixture data at production.

## Scope boundaries

- No database migration or unrelated backend subsystem import. This UI branch selectively contains endpoint-specific reader and typed graph code with their dependency closures; the fixture route remains synthetic and test-only.
- No Obsidian, Hermes, Jev, project repository, or profile modification.
- No integration of uncommitted concurrent files.
- No deployment to a public host or third-party service.
