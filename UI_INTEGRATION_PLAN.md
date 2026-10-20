# UI integration plan

## Isolation facts

- Branch: `Frontend-Design`, dedicated linked worktree (local path intentionally omitted from published docs).
- Worktree base: `4474bfc91bcc8145b1573dfa36831c5626c5fd76` on the initial audit. Verify `origin/Frontend-Design` before publishing each phase.
- Main checkout remains on its original branch and contains concurrent backend work. Do not change it or cherry-pick its uncommitted files.
- UI work is confined to this linked worktree. Do not use the shared SQLite or execute `index`, `sync`, audit-write, project exclusion, or source mutation operations during UI verification.

## Reader integration status and remaining sequence (2026-10-20)

The authorized Markdown reader is integrated in this isolated branch. The add/add contract conflict was resolved by retaining both agents' API/UI requirements and the backend's complete reader security contract. Only the reader module, its focused tests and the endpoint-specific server route were imported from published `origin/main`; no backend-wide merge or schema migration was performed.

1. Commit the validated integration and push only to `origin/Frontend-Design`; verify the remote SHA and leave `main` unchanged.
2. Keep the typed knowledge-graph endpoint behind its own reviewed read-only contract; preserve the current document-graph fallback.
3. Continue focused real-index search/filter QA, screen-reader/browser-zoom checks and isolated canvas frame-time/heap profiling when tools permit.
4. Any future `Frontend-Design` → `main` integration remains a separately reviewed operation. Do not merge it automatically.

## Frontend/backend integration matrix

| Endpoint / data contract | Availability on tested branch | Frontend consumer | Verified format and tests | Integration state / blocker |
|---|---|---|---|---|
| `GET /api/health`, `/api/stats`, `/api/projects`, `/api/categories`, `/api/tags`, `/api/sources` | Present in the committed dashboard API; synthetic fixture covers these shapes. | Header, Dashboard, filter options, project list. | Counts, latest scan, inventory and synthetic sources; fixture API tests. | Integrated on the documented base; repeat read-only verification after backend merge. |
| `POST /api/search`, `POST /api/context` | Present. | Global and legacy search, Inspector fragments, retrieved context. | Query/filter results and cited fragment shape; isolated API test plus browser smoke. | Integrated; fixture content must never be treated as production. |
| `POST /api/graph` | Present. Typed cross-entity graph endpoint is absent. | Neural Orbit, Hex, Knowledge Tree, existing Galaxy. | Nodes/edges, filtering, relation kinds and truncation; fixture API + browser smoke through 1,000 synthetic records. | Existing document-graph fallback works; typed cross-entity semantics remain blocked on reviewed backend API. |
| `GET /api/doc/{id}`, `GET /api/related/{id}`, `POST /api/open/{id}` | Present in the documented base. | Inspector metadata/neighbors and authorized source opening. | Metadata, related records and open confirmation (`opened: true`); safe-open response behavior tested. | Integrated; do not pass caller-supplied paths. |
| `POST /api/doc/content` `{document_id,max_bytes}` | Integrated into `Frontend-Design` from published `origin/main` commit `5109981a794a41bb7b646beca61ad11045f18ea5`; exact ID-only, read-only contract documented. | User-triggered safe Markdown reader, authorized inline references and in-document search. | 35 focused Python endpoint tests; full 325-test Python suite (1 skipped); 76 Node tests; real loopback reads from authorized Obsidian, projects and internal memory; browser-rendered real Obsidian Markdown with metadata, references and explicit neighbors. Negative HTTP checks include 405/400/403/404 and bounded reads. | Integrated and validated in this worktree; commit/push is the remaining publication step. No full main merge, reindex or source write. |
| `POST /api/cyber/status`, `/api/cyber/search`, `/api/cyber/get`, `/api/cyber/sync` | Existing dashboard connector routes are consumed by the Cyber panel. Fixture exposes status/navigation only and has no vulnerability results. | CVE/CISA KEV/CVSS/EPSS panel and explicitly user-triggered public-data refresh. | UI adapter and response normalization in `web/cyber.js`; synthetic browser verified navigation only. | UI is wired; production coverage/provenance freshness must be verified against reviewed backend responses after integration. Never treat fixture counts as real. |
| `POST /api/security/search`, `/api/security/get` | Existing dashboard routes consumed by the local standards/Zero Trust panel. | Standards and controls library. | Safe reference linking and selected-record rendering in `web/knowledge.js`; fixture has no real catalog records. | UI is wired; verify real edition/source metadata and bounded relations after integration. |
| `POST /api/coding/patterns`, `/api/coding/similar`, `POST /api/decisions` | Existing dashboard routes. | Coding Memory and architecture decisions. | Existing legacy consumers retained; fixture verifies decisions empty state and panel navigation. | UI is preserved; verify real reviewed-record and source-citation semantics after integration. |
| Preferences/local graph controls | Browser-only; no backend route. | Theme, typography, transparency, movement, graph labels/density, layout and resizable panels. | Five themes, reduced-motion synchronization, local persistence and reload smoke. | Integrated; queries and Markdown body are not written to local storage. |

## Safe preview

For visual QA only, run `node tests/neural_command_center_fixture_server.mjs 8877` from this worktree and browse `http://127.0.0.1:8877/`. It serves only the three local web assets and synthetic API payloads, binds to loopback, disables source opening, and visibly labels all displayed values as fixtures. Stop the process after verification. Do not point it at the live Second Brain API or the fixture data at production.

## Scope boundaries

- No database migration or unrelated backend subsystem import. This UI branch contains only the endpoint-specific route and its dependency closure; the fixture route remains synthetic and test-only.
- No Obsidian, Hermes, Jev, project repository, or profile modification.
- No integration of uncommitted concurrent files.
- No deployment to a public host or third-party service.
