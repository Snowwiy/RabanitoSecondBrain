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

## Safe preview

For visual QA only, run `node tests/neural_command_center_fixture_server.mjs 8877` from this worktree and browse `http://127.0.0.1:8877/`. It serves only the three local web assets and synthetic API payloads, binds to loopback, disables source opening, and visibly labels all displayed values as fixtures. Stop the process after verification. Do not point it at the live Second Brain API or the fixture data at production.

## Non-goals in this phase

- No backend API/schema edits or database migrations.
- No Obsidian, Hermes, Jev, project repository, or profile modification.
- No integration of uncommitted concurrent files.
- No deployment to a public host or third-party service.
