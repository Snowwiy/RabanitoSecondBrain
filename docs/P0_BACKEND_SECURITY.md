# Backend P0: file authority, HTTP framing and migrations

This is the main-branch backend contract, not authorization to merge another
worktree, recover an operational index or change source permissions.

## H1 — one source-file policy

`source_files.py` is the shared read-only implementation used by ingestion,
incremental reads, retrieval predicates and the Markdown reader. It requires:

- A local absolute path within the currently authorized source, selected by the
  existing directory/name/extension/project policy; no caller-supplied file path.
- Regular files with exactly one hard link. Hardlinks are rejected regardless of
  their apparent target. Symlinks and Windows reparse paths are not followed.
- Directory identities stable before/after the operation, matching named and
  opened file IDs, size and write timestamp. Windows handles deny write/delete
  sharing and verify the actual opened path; POSIX opens use `dir_fd/O_NOFOLLOW`.
- Bounded reads from the verified handle, including project README extraction,
  dependency manifests and derived project knowledge. Parsing never reopens the
  original by pathname and imported text remains untrusted data.

Indexing binds each successfully read document to its handle identity, change
timestamp and content hash in the existing `meta` table. This is transactionally
paired with the indexed record, including the unchanged incremental path.
Retrieval reopens the file to check current permissions/link count. A binding is
not permanent permission. Changed identity or missing legacy binding requires
bounded handle-based content verification against the cached hash (up to16MiB).
Windows performs that bounded hash verification even with a matching binding,
because Python versions differ in their ctime/creation-time semantics. This has
an I/O cost and does not weaken authorization on older supported Python versions;
hash reads for authority are separate from Audit's explicit drift byte counter.
No matching proof means no cached content. Malformed bindings fail closed.

Search, chunks/context, ID details, decisions, Coding Memory and graph descriptors
apply this authority before selecting recoverable content. Graph clean-proof
memoization additionally includes a fresh filesystem authorization signature;
a SQLite epoch alone cannot certify filesystem permissions. A generated project
profile is hidden when an indexed upstream document used by that project is no
longer eligible/verifiable; copying text to a generated file cannot authorize it.

An unavailable source is no longer an offline-cache permission. Rows and FTS
payload are retained for recovery, not automatically purged, but are hidden while
unverifiable. Metadata-only Audit still reports path drift and aggregate inactive
payload counts; it suppresses cached titles for unverifiable files and does not
recover their bodies. Tombstone counts are not recovered knowledge.

File-rejected rows are excluded before query-dependent candidate/skip counts;
those counters must not become a match oracle for unauthorized cached text.
Restoring a database snapshot does not authorize old text when the current source
differs: recovery tests restore their matching synthetic source explicitly. The
application never rewrites originals as part of index restore.

The Markdown success response is unchanged. Its existing404/409 errors still
distinguish unavailable/changed sources; truncated reads also require matching
cache/file authority. No original file, ACL or operational DB is repaired by a
query. Legacy fallback can cost additional bounded I/O; an explicitly authorized
ordinary incremental scan establishes current bindings without a full rebuild.

These are operation-scoped checks, not a filesystem-wide snapshot, encryption,
universal DLP or protection against someone who controls the process/SQLite.
No historical identity is invented for old records. A sole-link file deliberately
copied into an authorized source is not distinguishable from an ordinary file.

## H5 — bounded local HTTP reads

All accepted connections have a3-second header deadline (including the request
line) and each POST body has a3-second total read deadline, not a timer reset by
every incoming byte. The best-effort drain used for rejected Markdown requests is
also bounded by a total deadline of at most1second. Incomplete headers close the
connection; once framing is available body errors use the existing JSON envelope.

| Invalid input | HTTP / JSON error |
| --- | --- |
| Duplicate/invalid Content-Length, any Transfer-Encoding |400 / `invalid_request_framing` |
| Oversize declared body |413 / `request_size_limit` |
| EOF before the declared body completes |400 / `incomplete_request_body` |
| Body deadline exceeded |408 / `request_body_timeout` |
| Invalid Host/Origin/JSON content type |403 / existing route error |

The existing body caps remain:2048bytes for commands/Markdown,16384bytes for the
existing larger search/context/decision/graph requests. Markdown still requires
one explicit Content-Length; generic legacy requests may omit it only as an
empty body. Connections close after POST; incompatible transfer framing and
duplicate relevant headers cannot dispatch an operation. Valid routes and their
success payloads are preserved. These limits are not a general process quota or
a claim of authentication against other local programs.

## H6 — transactional documentary initialization

The documentary schema, legacy ALTERs and deterministic backfill execute inside
one `BEGIN IMMEDIATE` transaction. Initialization exceptions, including interruption,
roll back and close the connection. A cold restart can retry idempotently.
Journal-mode setup remains outside that transaction; failure can leave an empty
new SQLite container/WAL artifacts, not a partially committed application schema.
No source files are involved and no operational migration is run by this validation.

Cyber, Security Architecture, ATT&CK, Dependency Memory and Knowledge Graph retain
their existing checksum ledgers and transactional DDL. Applied checksums were not
changed. The documentary legacy initializer still uses schema inspection rather
than an invented historical checksum ledger; this patch does not certify or
repair arbitrary preexisting corruption. Backup/integrity checks remain explicit
operator procedures. Tests verify rollback, abrupt process exit, recovery,
idempotence, foreign keys and integrity on synthetic databases only.

## Validation and deployment boundary

See `test_file_authorization.py`, `test_http_framing.py`,
`test_document_migrations.py` and `test_scan_contract.py`, plus the regression suite.
Windows fixtures exercise real hardlinks, a real junction and temporary NTFS
read-data denial with restoration. Native symlink creation is capability-dependent;
when unavailable it is reported as skipped, with a separate deterministic symlink
identity test. A skip is not represented as a native symlink success.

No frontend changes, real source indexing, global hooks, ACL repairs, operational
database opens or integration-branch merges are part of this patch. Publishing
main does not update a process running from another checkout. Integration and any
real index recovery need their own authorization and validation.

For H2, use [the scan outcome contract](SCAN_OUTCOMES.md). HTTP200 is not a full
scan confirmation and the backend never exposes an approval digest to the browser.
