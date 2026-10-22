# H2 — scan outcome contract for frontend integration

Additive main backend contract. No frontend file or other worktree is changed.
Existing routes, HTTP success codes, status enums and counters are retained.

## Existing evidence, then additional diagnostics

Use the existing `status` (`ok`, `partial`, `error`, or a running historical row),
`errors`, `source_summary`, `scan_id` and timestamps. HTTP200 only means the HTTP
operation returned a result. It must never produce an unconditional success toast
or mark sources synchronized without checking the JSON outcome.

The CLI already exposed `scan_coverage` and `retirement_guard`. Their safe subsets
are now also returned by POST `/api/index`, GET `/api/stats` at `latest_scan`,
GET `/api/scans` on each available run and existing nested index summaries:

| Field | Meaning |
| --- | --- |
| `scan_coverage.expected_sources` | Exact configured origin count |
| `attempted_sources`, `completed_sources` | Origins attempted / fully enumerated |
| `failed_sources`, `unprocessed_sources`, `incomplete_sources` | Failure/noncompletion counters; overlapping, not additive |
| `scan_coverage.complete` | Coverage verified; this alone does not approve withdrawals |
| `retirement_guard.status` | `not_required`, `review_required`, `approved`, `approval_rejected` |
| `proposed`, `withheld` | Withdrawal candidates / retained pending review |
| `scope_incomplete` | An incomplete/unconfigured scope cannot be overridden |
| `unconfigured_documents_preserved` | Indexed rows retained from an unconfigured origin |
| `changed_source_identities` | Directory identity changes requiring attention |
| `approval_applied` | The exact plan was explicitly accepted, not browser authority |

Only bounded counts, booleans and allowlisted states are projected. Private roots,
document payloads, raw error messages and `approval_digest` are excluded. A
`source_summary[kind].errors > 0` indicates source/file failures; do not invent an
exact permission error or root from this aggregate. Missing/inaccessible roots
produce incomplete coverage. A fully enumerated empty source is distinguishable
from zero processed origins by the coverage counters.

Diagnostics are persisted per scan in existing `meta` and remain associated with
that `scan_id`. There is no new table/schema migration. Missing, malformed,
oversize or legacy diagnostics are omitted: absence means **unknown coverage**,
not complete. Old historical `ok` rows are not retroactively certified.

## Last confirmed complete index

GET `/api/stats` and GET `/api/scans` add `last_complete_scan`, either null or:

```json
{"scan_id":123,"started_at":"2026-10-22T12:00:00+00:00","finished_at":"2026-10-22T12:00:01+00:00"}
```

This is a type example, not operational data. The marker is written only by a
full accepted run: `status=ok`, zero errors, verified complete coverage and zero
withheld retirements. A partial, failed, single-note or review-held run does not
replace it. The referenced journal row and persisted coverage must still support
the marker; otherwise it is null. Before the first such run it is null, even if
the database has older `ok` history. It is a past completion timestamp, not proof
that no files changed since. Audit freshness is a separate read-only operation.

## Frontend decision rules (for Luna; not implemented in this backend patch)

1. A non-2xx response is a request failure; show its structured error, never a
   synchronization success. A transport error is not a recorded scan outcome.
2. `status=error`: show failure. `status=partial`: show partial/review, never green.
3. `review_required`/`approval_rejected` or `withheld>0`: show retained withdrawals
   and a review action/instruction. **Do not automatically approve or retry with
   force.** There is no HTTP approval writer; reviewed approval remains CLI-only.
4. `complete=false`, failed/unprocessed/incomplete counts or `scope_incomplete`:
   show incomplete coverage and retain the last confirmed full-scan timestamp.
5. Only `status=ok`, verified complete diagnostics, zero errors and zero withheld
   retirements qualifies as a full accepted run. Legacy `ok` without diagnostics
   is historical/coverage unknown, not a newly confirmed synchronization.
6. `complete=true` together with a retirement review is valid: enumeration
   completed but withdrawals were blocked. The run is still `partial`.

No code/UI branch merge is implied by this document. Tests exercise real HTTP200
partial responses, persisted history, unavailable/empty/unprocessed sources,
malformed reports and retention of the last complete marker with temporary data.
