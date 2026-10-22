# Safe incremental retirement

Indexing may add/update records, but failure to observe a file is not proof of
its absence. Imported text is untrusted data, never authority to delete records.
These controls do not write to imported sources, restore SQLite or purge text.

## What counts as a complete source

The indexer captures an immutable configuration/source plan. Completion belongs
to an exact `(kind, root)` origin, not every cached row sharing the same kind.
Projects also require a coherent project root under the configured collection.
A source completes only after enumeration ends and its directory identity and
modification stamp still match. Merely opening the directory is insufficient.

Enumeration, permission, stat, read and parse errors prevent absence retirement
for that kind; sibling roots of that kind are retained conservatively. Healthy
other kinds may still retire small confirmed absences, while the run is partial.
Missing/unprocessed roots and an empty source plan cannot produce status `ok`.

For unseen eligible files, a no-follow metadata check must confirm absence.
A file still present, a reparse boundary or an unverifiable path is not absence.
Explicit policy exclusions and explicit disabling are distinct from missing files.
Contradictory enabled/disabled declarations are not retirement authority.

Rows from roots no longer configured are preserved and reported, not retired
by a scan of a different empty root. Retrieval permissions continue to hide
unconfigured sources independently of their retained index status.

## Empty sources versus mass withdrawal

- Newly configured, accessible, genuinely empty sources can complete successfully
  with zero files. Coverage counters distinguish this from no completed sources.
- A small confirmed deletion from the same authorized source still retires
  normally; sources are not forced to contain files forever.
- A proposed withdrawal of at least100 documents, or at least10 and50% of the
  active/skipped population, requires review. The rule applies globally and per
  cached origin, plus missing-project counts. It is not disabled by `--force`.
- Directory identity changes between successful scans also require review when
  there are proposed withdrawals, even below the numeric threshold. Identity
  bindings are hashed, bounded metadata in existing `meta`, not files in the vault.
  Legacy databases without these bindings still receive all other protections;
  their first trustworthy observation establishes a baseline, not historical proof.
- Project `missing` transitions are deferred with the withdrawal decision. A
  blocked bulk scan cannot silently retire projects through their metadata instead.

Blocked candidates keep their rows, IDs and cached payload. This is not a claim
that stale documents still exist. Audit/native reads retain their freshness checks.

## Review and explicit approval

The full Python/CLI index result and private run journal add `scan_coverage`
(expected/attempted/completed/failed/unprocessed/incomplete sources) and
`retirement_guard` (proposed/withheld counts, scope completeness, changed
identities, preserved unconfigured rows and optional approval digest).
Failed/unprocessed counters can overlap; they are not additive populations.
The latest safe metadata report is also stored at `meta.index_retirement_guard`.
No schema migration or new HTTP writer is introduced. Existing compact dashboard
scan projections keep their fields: HTTP200 alone does not certify success;
inspect the run's `status`. Obtain approval details through the CLI, not URLs.

From an authorized checkout, with an explicitly reviewed local configuration:

```powershell
python -m rabanito --config '<reviewed-settings.json>' index
# Only after reviewing roots, availability, counts and intentional absences:
python -m rabanito --config '<reviewed-settings.json>' index --approve-retirements '<reviewed SHA256>'
```

CLI exit codes for `index`:0 complete/accepted,2 partial or review needed,
1 failed. JSON still describes the outcome. `approval_rejected` retains candidates.

The digest binds configuration, source identities, document IDs/hashes/statuses,
reasons and project candidates. It is not authentication or evidence of human
consent. Never auto-approve it, store it as a permanent automation flag or reuse
it after a changed plan. An incomplete source/configuration mismatch cannot be
overridden by approval. A complete run with a review hold is still partial.
Normal indexing may update confirmed present files before a hold; it is not a
read-only dry-run or a transaction across the entire filesystem.

## Safe recovery procedure (operator action, not automatic restoration)

1. Stop repeated scans from the old deployment; preserve scan/journal evidence
   and create a verified backup before an authorized recovery. Do not prune cache,
   rewrite scan history, restore an operational DB or use `--force` as a remedy.
2. Deploy the corrected code through a separately authorized integration. A fix
   in one checkout does not update another worktree's running process.
3. Verify the explicit config, canonical source paths, volume/directory identities,
   read access, exclusions and intended source set. Do not repair permissions or
   move original files merely to make a scan green.
4. Once the real sources are confirmed available, run ordinary incremental index.
   Existing tombstones whose files return are reactivated with their existing IDs;
   no full rebuild or database restoration is required for this case.
5. Investigate any partial/failed result before retrying. Approve only an exact,
   intentional withdrawal after complete coverage, not an unexpected empty scan.
6. Check stats, Audit, citations and links after recovery. Do not claim a full
   forensic audit from counters or a synthetic fixture alone.

Filesystem observations are not a distributed snapshot. A directory can remain
accessible while external storage is semantically wrong; identity/stamp checks,
absence checks and the review threshold are layered defenses, not certainty about
every transient filesystem state. A digest does not replace operator verification.

Tests: `python -B -m unittest tests.test_scan_retirement -v`. Fixtures include a
338-document/2734-link reproduction, empty/missing/denied/changed roots, silent
empty enumeration, read/parse failures, sibling origins, policy changes,
directory replacement, approved/stale plans and real CLI subprocesses. All sources
and SQLite files in these tests are temporary; operational DBs are not opened.
