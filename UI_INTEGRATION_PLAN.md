# UI integration plan

## Isolation facts

- Branch: `Frontend-Design`, dedicated linked worktree (local path intentionally omitted from published docs).
- Worktree base: `4474bfc91bcc8145b1573dfa36831c5626c5fd76` on the initial audit. Verify `origin/Frontend-Design` before publishing each phase.
- Main checkout remains on its original branch and contains concurrent backend work. Do not change it or cherry-pick its uncommitted files.
- UI work is confined to this linked worktree. Do not use the shared SQLite or execute `index`, `sync`, audit-write, project exclusion, or source mutation operations during UI verification.

## Merge/integration sequence (not performed here)

1. Review the final `Frontend-Design` diff and its commit ancestry against the then-current `main` without force-push, reset, or automatic rebase.
2. Integrate backend changes through their own reviewed branch/PR; the current dashboard still depends on the committed base API documented in `FRONTEND_BACKEND_CONTRACT.md`.
3. Reconcile only shared web assets (`web/index.html`, `web/knowledge.js`, `web/cyber.js`) by preserving existing backend changes. Do not overwrite the original checkout or Sol’s worktree.
4. Add the typed knowledge-graph endpoint and authorized full-content endpoint only after backend review. Keep the documented fallback and explicit pending states until APIs are available.
5. Run the Python suite, all Node UI suites, and browser QA against an isolated fixture server. Run against a real local index only after separately verifying the selected server uses the authorized data and read-only APIs.
6. Confirm settings bind only `127.0.0.1`, no CDN/telemetry appears, and no private path/DB/Obsidian content is staged.
7. Open a Pull Request from `Frontend-Design` to `main` after integration review. Do not merge it automatically.

## Frontend/backend integration matrix

| Endpoint / data contract | Availability on tested branch | Frontend consumer | Verified format and tests | Integration state / blocker |
|---|---|---|---|---|
| `GET /api/health`, `/api/stats`, `/api/projects`, `/api/categories`, `/api/tags`, `/api/sources` | Present in the committed dashboard API; synthetic fixture covers these shapes. | Header, Dashboard, filter options, project list. | Counts, latest scan, inventory and synthetic sources; fixture API tests. | Integrated on the documented base; repeat read-only verification after backend merge. |
| `POST /api/search`, `POST /api/context` | Present. | Global and legacy search, Inspector fragments, retrieved context. | Query/filter results and cited fragment shape; isolated API test plus browser smoke. | Integrated; fixture content must never be treated as production. |
| `POST /api/graph` | Present. Typed cross-entity graph endpoint is absent. | Neural Orbit, Hex, Knowledge Tree, existing Galaxy. | Nodes/edges, filtering, relation kinds and truncation; fixture API + browser smoke through 1,000 synthetic records. | Existing document-graph fallback works; typed cross-entity semantics remain blocked on reviewed backend API. |
| `GET /api/doc/{id}`, `GET /api/related/{id}`, `POST /api/open/{id}` | Present in the documented base. | Inspector metadata/neighbors and authorized source opening. | Metadata, related records and open confirmation (`opened: true`); safe-open response behavior tested. | Integrated; do not pass caller-supplied paths. |
| `POST /api/doc/content` `{document_id,max_bytes}` | **Absent** in tested production branch; route is implemented only by the isolated synthetic fixture. | User-triggered Markdown reader, safe inline references and local document search. | Fixture verifies bounded request/response fields, references, all supported Markdown blocks, internal navigation, search highlights and raw HTML rendered as text. Parser and response contract tests pass. | **Backend blocker.** Add and review the authorized ID-only endpoint described in `FRONTEND_BACKEND_CONTRACT.md`; fixture proof does not count as production integration. |
| `POST /api/cyber/status`, `/api/cyber/search`, `/api/cyber/get`, `/api/cyber/sync` | Existing dashboard connector routes are consumed by the Cyber panel. Fixture exposes status/navigation only and has no vulnerability results. | CVE/CISA KEV/CVSS/EPSS panel and explicitly user-triggered public-data refresh. | UI adapter and response normalization in `web/cyber.js`; synthetic browser verified navigation only. | UI is wired; production coverage/provenance freshness must be verified against reviewed backend responses after integration. Never treat fixture counts as real. |
| `POST /api/security/search`, `/api/security/get` | Existing dashboard routes consumed by the local standards/Zero Trust panel. | Standards and controls library. | Safe reference linking and selected-record rendering in `web/knowledge.js`; fixture has no real catalog records. | UI is wired; verify real edition/source metadata and bounded relations after integration. |
| `POST /api/coding/patterns`, `/api/coding/similar`, `POST /api/decisions` | Existing dashboard routes. | Coding Memory and architecture decisions. | Existing legacy consumers retained; fixture verifies decisions empty state and panel navigation. | UI is preserved; verify real reviewed-record and source-citation semantics after integration. |
| Preferences/local graph controls | Browser-only; no backend route. | Theme, typography, transparency, movement, graph labels/density, layout and resizable panels. | Five themes, reduced-motion synchronization, local persistence and reload smoke. | Integrated; queries and Markdown body are not written to local storage. |

## Safe preview

For visual QA only, run `node tests/neural_command_center_fixture_server.mjs 8877` from this worktree and browse `http://127.0.0.1:8877/`. It serves only the three local web assets and synthetic API payloads, binds to loopback, disables source opening, and visibly labels all displayed values as fixtures. Stop the process after verification. Do not point it at the live Second Brain API or the fixture data at production.

## Non-goals in this phase

- No backend API/schema edits or database migrations. The fixture route exists strictly as a synthetic UI test adapter and does not claim server implementation.
- No Obsidian, Hermes, Jev, project repository, or profile modification.
- No integration of uncommitted concurrent files.
- No deployment to a public host or third-party service.
