# UI integration plan

## Isolation facts

- Branch: `Frontend-Design`, dedicated linked worktree (local path intentionally omitted from published docs).
- Worktree base: `4474bfc91bcc8145b1573dfa36831c5626c5fd76` on the initial audit. Verify `origin/Frontend-Design` before publishing each phase.
- Main checkout remains on its original branch and contains concurrent backend work. Do not change it or cherry-pick its uncommitted files.
- UI work is confined to this linked worktree. Do not use the shared SQLite or execute `index`, `sync`, audit-write, project exclusion, or source mutation operations during UI verification.

## Reader and typed Knowledge Graph integration status (2026-10-20)

The authorized Markdown reader and typed Knowledge Graph are integrated in this isolated branch. The reader's add/add contract requirements were reconciled in the frontend branch by retaining both the UI/API requirements and backend security contract. Backend code was selectively copied from published `origin/main` with its focused dependency closures; no backend-wide merge or schema migration was performed. This phase's typed graph changes are currently local and must be committed/pushed to `Frontend-Design` before the compatibility assessment is considered current.

1. The reader integration remains published as `a5ea26b9f1156fb3fd879283c77f530b5f61949b`; the previous checkpoint is `515cc257906dbd9bc67bfbab81541b6e966542a0`. `origin/main` remains `5109981a794a41bb7b646beca61ad11045f18ea5`.
2. Typed routes now use the backend's strict contract. Page and one-hop reads are read-only, and refresh is separately confirmed and bounded. The document graph remains available as fallback.
3. Current phase QA is recorded in `UI_TEST_RESULTS.md`: 82 Node tests, 359 Python tests (1 skipped), real indexed graph checks, read-only Obsidian reader recheck, and 1920×1080 / 2560×1440 visual geometry.
4. Remaining critical work is browser-side frame-time/heap profiling, screen-reader/browser-zoom verification, and broader non-ATT&CK and stale/error real-index coverage.
5. Any future `Frontend-Design` → `main` integration remains a separately reviewed PR operation. Do not merge it automatically.

## Future PR compatibility assessment (read-only, 2026-10-20)

- Audited refs before this phase's pending commit: merge base `4474bfc91bcc8145b1573dfa36831c5626c5fd76`, `origin/main` `5109981a794a41bb7b646beca61ad11045f18ea5`, `Frontend-Design` `515cc257906dbd9bc67bfbab81541b6e966542a0`.
- `git merge-tree --write-tree origin/main HEAD` reported three conflict paths and no worktree merge: `FRONTEND_BACKEND_CONTRACT.md` (add/add), `docs/API_CONTRACT.md` (content), and `rabanito/server.py` (content). Other paths were auto-merged in the simulation.
- The existing reader route and typed graph routes both need to survive server reconciliation; the contracts should combine UI behavior, endpoint shapes, validation, authorization, bounds, stale behavior, and error requirements. Do not resolve by choosing an entire side.
- Re-run the simulation against the pushed frontend head and latest `origin/main` before PR preparation. This assessment does not authorize opening a PR or performing a merge.

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
