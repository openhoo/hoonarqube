# Hoonarqube service

The service stores analysis reports, findings, reviews, and immutable review
history in SQLite. It serves a browser dashboard at `/` and project APIs under
`/api/v1`. Credentials explicitly select each user's project roles.

## Start locally

Configure `HOONARQUBE_SERVICE_CREDENTIALS` with a JSON array of credentials.
Each entry has `user_id`, `token`, and a `projects` object mapping project IDs
to `reader`, `reviewer`, or `admin`. The optional `global_admin` flag grants
access to every project. Both user IDs and bearer tokens must be unique;
ambiguous credentials prevent startup without including tokens in errors.
Keep real credential values out of source files and terminal logs.

`HOONARQUBE_SERVICE_DB` defaults to `hoonarqube-service.sqlite3`.
`HOONARQUBE_SERVICE_BIND` defaults to `127.0.0.1:8080`.

```sh
cargo run --locked -p hoonarqube-service
```

Enter a configured bearer token in the dashboard to connect. The dashboard
holds the token in memory and discards responses from earlier sessions or
project selections. Disconnect hides the loaded analysis and prevents pending
requests from repopulating it.

Ingestion and backup restoration validate native report consistency before
writing: complete reports cannot contain failed source/test measurements or
scan warnings, measured source/test metrics must match their file reports,
and project totals count complete source files only. Duplicate inventory paths,
impossible file counters, and NUL-containing paths are rejected. Incomplete
reports and excluded scopes remain supported. Previously stored contradictory
reports must be corrected before they can be restored. Restored review summaries
must match their latest immutable history entry, including the reviewed analysis,
state, version, actor, timestamp, and reason; contradictory backups are refused
before creating a project or writing any rows.

## Finding pages

Use `GET /api/v1/projects/{project}/analyses/{analysis_id}/findings/page` for
a bounded response. It uses the same project access and review rules as
`/findings`. Set `limit` to 1–500 (default 100). The response contains an
ordered `findings` array and `next_cursor`. Pass the cursor unchanged as
`cursor` on the next request. A null cursor marks the last page, including an
empty result. Cursors belong to the analysis that issued them.

The finding order stays fixed for the life of an analysis. Reviews reflect
the state when each page was read, so clients may see review changes between
pages. The existing `/findings` route still returns the full array.

## Database startup and recovery

Use a dedicated SQLite file for each instance. The service initializes empty
unversioned files and upgrades existing version 1 databases to version 2 in one
transaction. The upgrade adds a marker to distinguish reports written with
exact float parsing from older reports. It does not rewrite existing reports,
hashes, or reviews. Missing service indexes are recreated on startup. A
nonempty unversioned database, a database missing a required table, or an
unsupported version stops startup without switching its journal mode.

Reports ingested after the upgrade retain the CLI's floating-point percentages
through reads, exports, and restores. Replaying an original request for a legacy
row still resolves to its original analysis. An older row may already contain
rounded values; the service preserves those values.

Take a consistent SQLite backup before upgrading, including any committed
state in the WAL. The project backup schema stays at version 1. The new service
can restore valid older backups. An old binary cannot open a version 2 database.
It can restore a new project backup into a version 1 database only when the old
decoder reproduces every analysis hash and metric in that backup; a backup with
an affected precise value can be rejected. Keep the pre-upgrade SQLite backup
for rollback.

On refusal, preserve the database and its WAL files; inspect a backup before
choosing a compatible binary or restoring a known-good copy. Do not reset
`PRAGMA user_version` to force an older binary to start.

### Backup choice and limits

The default service applies a 16 MiB JSON limit to both project export and
restore. A project can exceed this limit even when every individual report
was accepted. Export then returns HTTP 413. For example, an Acorn project
export with one assessed analysis was 9,094,745 bytes; two analyses exceeded
the limit. Test your project export before relying on it for recovery.

Use the SQLite online backup API for a whole-instance snapshot, especially
when project exports exceed the limit. Open the live database read-only as
the backup source. Copying only the live main database file can omit
committed data that is still in the WAL. Check `PRAGMA integrity_check` and
`PRAGMA foreign_key_check` on the resulting backup. Restore to a new database
file first; start the same service version and verify the expected projects,
analyses, findings, and review history before switching the configured
database path. The database snapshot covers all projects; store it with
the corresponding access controls.

Retry an interrupted ingest with the same request body. If the original
committed, the retry returns its analysis ID with `idempotent: true`. If it
never committed, the retry creates the analysis. A different report for the
same project, branch, and commit returns HTTP 409.

### Recover one project above the HTTP limit

Use the operator script from this service revision on Linux or macOS with
Python 3.11 or later. It reads a schema version 2 service database, including
committed WAL records, in one read-only SQLite transaction. Only the exact
project is copied into a new SQLite file. The copy includes report bytes,
analysis and finding IDs, review revisions and actors, and soft deletions
and their audit records. The 16 MiB HTTP limit still applies to HTTP routes.

Run the following as an operator with filesystem read access to the service
database and write access to a private local directory. Use a destination
directory you control, on a filesystem that supports hard links. Leave each
destination filename unused, including any SQLite sidecars.

```sh
python3 scripts/service_project_snapshot.py export --project my-project \
  /srv/hoonarqube/service.sqlite3 /secure/backups/my-project.sqlite3

# Use the SHA-256 from the export receipt, kept separately from the archive.
python3 scripts/service_project_snapshot.py restore --project my-project \
  --sha256 "$project_snapshot_sha256" \
  /secure/backups/my-project.sqlite3 /secure/recovery/service.sqlite3
```

Save the export receipt from standard output in a trusted location. It contains
the project ID, SHA-256, byte size, and row counts. Keep the archive closed;
opening it as a live service database can change it and invalidate its checksum.
Restore checks the receipt hash and project ID before publishing the new database.
Both commands stage and check a private copy before making the destination
visible. They will refuse any existing destination, even an empty file. If a
process is forcibly killed, inspect the destination and remove any abandoned
`.hoonarqube-project-*` staging directory after confirming the process is gone.

Live requests can continue while the SQLite snapshot is read. A long read can
delay WAL cleanup, so allow disk space for the selected data, rollback journal
and WAL growth; schedule very large copies during a quiet period. The tool
copies database rows without going through the HTTP parser or applying
retention. It does not merge into an existing database or upgrade old schemas.

Configure the restored service separately with `HOONARQUBE_SERVICE_DB` pointing
to the new file. Supply only the intended project's reader, reviewer, and admin
assignments from your credential store. Role assignments and bearer tokens
live in `HOONARQUBE_SERVICE_CREDENTIALS`, not in SQLite, and are absent from the
snapshot. Keep the same approved `user_id` for people whose review history
should remain attributable, and issue credentials for the restored instance.
Start it in isolation until an admin confirms the project, analysis counts,
finding pages, and reviews and a reader confirms their scoped access.

### Local operations qualification

Build the service at the intended revision and supply four complete CLI
`--assessment` reports from real projects. Scan the pinned source trees
exported without Git metadata (for example with `git archive`). The probe
reuses those unchanged report bytes under test commit labels to exercise
same-branch history. It starts disposable services bound to loopback and
prints a JSON receipt. It needs no existing service, database, or credentials.

```sh
cargo build --locked -p hoonarqube-service
python3 scripts/qualify_service_operations.py --binary target/debug/hoonarqube-service \
  zod.json acorn.json ajv.json yjs.json
```

The probe runs three batches of eight clients on one project and three on
two projects, with four service workers. Each batch includes concurrent
duplicate ingests and reads of 100 findings. It checks authorization,
optimistic review updates, two process kills with subsequent retries,
project backup, and whole-instance recovery. The recorded inputs were
Zod `0b216ef674e297ebe41d8bf902262e56f8755822` (5,941 findings), Acorn
`e4516ce0f49aea06b98ae1a551644119958ed4e1` (5,311), Ajv
`9050ba1359fb87cd7c143f3c79513ea7624ea443` (5,268), and Yjs
`ee37f0a0e23a7c3e14531bae335d439e54c743e6` (4,896). Assessed inputs were
4.1–7.0 MB each. The snapshot case reached 12 analyses and 65,336 findings
in a 145 MB database. This bounded loopback check measures local timings
and process restart recovery; it does not establish production throughput,
availability, or recovery after machine or storage failure.

## Focused verification

```sh
cargo test --locked -p hoonarqube-service --all-targets
node --test crates/hoonarqube-service/tests/dashboard.test.cjs
```

The Rust tests include actual local HTTP request/response checks for API
validation and security headers. The Node tests execute the shipped dashboard
script with a small DOM harness and delayed responses; they check session and
scope isolation plus current-session success and failure controls. They do not
replace visual or browser accessibility testing.
