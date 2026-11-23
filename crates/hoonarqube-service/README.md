# Hoonarqube service

The service stores analysis reports, findings, reviews, and immutable review
history in SQLite. It serves a browser dashboard at `/` and project APIs under
`/api/v1`. Credentials explicitly select each user's project roles.

## Start locally

Configure exactly one credential source: `HOONARQUBE_SERVICE_CREDENTIALS_FILE` (a path to a UTF-8 JSON file, at most 1 MiB) or `HOONARQUBE_SERVICE_CREDENTIALS` (inline JSON). Both accept the same array.
Each entry has `user_id`, `token`, and a `projects` object mapping project IDs
to `reader`, `scanner`, `reviewer`, or `admin`. The optional `global_admin` flag grants
access to every project. Both user IDs and bearer tokens must be unique;
ambiguous credentials prevent startup without including tokens in errors.
Keep real credential values out of source files and terminal logs.

On Unix, restrict the file to the service account, replace it by atomic rename,
then send `SIGHUP` to the service process. The service validates the entire
replacement before switching credentials. Once it logs `service credentials
reloaded`, new requests use the new tokens and roles. Requests already authorized
can finish. An unreadable, oversized or invalid replacement disables all new
authenticated requests and logs `access disabled`. Repair the file and signal
again to recover. A file modification alone does not trigger a reload. On other
platforms, or with inline credentials, restart the service to change credentials.

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

## Assign a project gate

Assign a gate before the first CI upload to enforce the same conditions even
when the scanner omits its gate or submits a weaker one. Use a project
`admin` credential for policy changes. Give CI the `scanner` role: it can
upload and read analyses but cannot change policy, submit reviews, restore
backups, or delete records. Reviewers can read and review, and readers can read.

An admin can provision a project and assign its first gate with
`PUT /api/v1/projects/{project}/gate-policy`:

```json
{
  "schema_version": 1,
  "expected_version": 0,
  "config": {
    "schema_version": 1,
    "conditions": [
      {"scope": "new_code", "metric": "violations", "operator": "lte", "threshold": 0}
    ]
  }
}
```

The response contains `policy.version`, `policy.config`, `policy.updated_by`
and `policy.updated_at`. Any project reader can retrieve it with
`GET /api/v1/projects/{project}/gate-policy`; an existing unassigned project
returns `{"policy":null}`. To change the policy, send its current version as
`expected_version`. A stale update returns HTTP 409. The service accepts
one to 64 valid gate conditions. Once assigned, the policy remains active;
each update adds an immutable revision.

The service binds each new analysis to the policy active at ingestion.
The upload response, history and analysis detail expose `gate_policy_version`
and the initial service decision in `gate`. The uploaded scanner decision, if
present, stays in `report.assessment.gate`. An idempotent replay returns the
original analysis and policy. Updating the policy does not change older
analyses. Analyses submitted before assignment retain their original scanner
gate, including the possibility of no gate.

For the current verdict, read
`GET /api/v1/projects/{project}/analyses/{analysis_id}/gate`. It uses that
analysis's bound conditions and includes compatible authorized hotspot reviews
and reopenings. For an unassigned analysis it uses the submitted gate, or
returns HTTP 404 if no gate was submitted. Assignment controls the conditions;
the service still relies on an authorized scanner for its source scope,
measurements, and baseline evidence. It does not independently check out code
or authenticate coverage producers.

### Prepare the native report for upload

For an assigned gate that only checks **overall duplication density**, the
ordinary native JSON report contains the file findings, project inventory and
duplication measurements that the service needs. Start in the Hoonarqube
checkout; set `SOURCE_DIR` to the project to scan and `RUNNER_TEMP` to an
existing directory **outside** it:

```sh
set -eu
(cd "$SOURCE_DIR" && hoonarqube analyze . --profile sonar-parity --format json) \
  > "$RUNNER_TEMP/report.json"
python3 scripts/prepare_analysis_upload.py --report "$RUNNER_TEMP/report.json" \
  --branch "$BRANCH" --commit "$COMMIT" --analyzed-at "$ANALYZED_AT" \
  > "$RUNNER_TEMP/ingest.json"
```

Use the scan's original UTC timestamp; keep the envelope for idempotent retries.
The helper preserves the original JSON bytes and rejects envelopes above the
standalone service's 16 MiB limit before sending anything. If the policy or
workflow needs coverage, new-code or assessment evidence, generate the report
with those inputs. An oversized report is a failed upload; do not discard
findings, strip required evidence, or change the scan scope to make it fit.

### Enforce the upload verdict in CI

HTTP 200 acknowledges storage. A failing or unavailable gate is still stored.
The script below checks the service receipt for the exact project, branch and
commit in the CI job. It exits **0** for an assigned pass, **1** for a failed
gate, and **2** for unavailable, unassigned, malformed, or mismatched results.

```sh
# Use a trusted service URL and the scanner credential from the CI secret store.
# Use the prepared envelope from the previous step.
set -eu
curl --fail --silent --show-error \
  --oauth2-bearer "$SCANNER_TOKEN" -H 'Content-Type: application/json' \
  --data-binary "@$RUNNER_TEMP/ingest.json" "$SERVICE_URL/api/v1/projects/$PROJECT/analyses" \
  -o ingest-receipt.json
python3 scripts/check_project_gate.py --project "$PROJECT" --branch "$BRANCH" \
  --commit "$COMMIT" < ingest-receipt.json
```

The [Redux replay](../../tools/oracle/project_gate_policy_replay.py) exercises
the scanner, service, and CI script on two pinned revisions. The
[receipt](../../tools/oracle/project-gate-policy-redux.json) records each
decision, the binary hashes, concurrent updates, restart, and both restore
formats.

## Browse analysis and finding pages

The dashboard loads 25 analyses at a time for the selected branch and 100
findings at a time for the selected analysis. Use **Previous** and **Next** in
each section. The displayed count is the count for that page. Loading another
branch starts at its newest analysis.

To page through history from another client, use
`GET /api/v1/projects/{project}/analyses/page`. Supply `branch` to select one
branch or omit it for the whole project. Set `limit` to 1–100 (default 25). The
response contains an `analyses` array and `next_cursor`. Each entry includes
the analysis ID, project, branch, commit, analyzed time, report schema version
and completeness, plus the gate policy version if assigned. Order is newest
analyzed time first, with higher analysis IDs first when times are equal.

Pass `next_cursor` unchanged as `cursor` with the same project and branch
filter. A null cursor marks the last page, including an empty result. History
pages read the current state: deleted rows are omitted, and new rows ahead of
the cursor appear after a refresh from the first page.

For the selected analysis, `GET /api/v1/projects/{project}/analyses/{analysis_id}/overview`
returns the summary (including metrics and the stored gate) and scan warnings.
The existing `/analyses` list and `/analyses/{analysis_id}` detail keep their
original responses, including the full report on detail.

Use `GET /api/v1/projects/{project}/analyses/{analysis_id}/findings/page` for
a bounded response. It uses the same project access and review rules as
`/findings`. Set `limit` to 1–500 (default 100). The response contains an
ordered `findings` array and `next_cursor`. Pass the cursor unchanged as
`cursor` on the next request. A null cursor marks the last page, including an
empty result. Cursors belong to the analysis that issued them.

The finding order stays fixed for the life of an analysis. Reviews reflect
the state when each page was read, so clients may see review changes between
pages. The existing `/findings` route still returns the full array.
Clients writing reviews can set `include_review_versions=true` on the page
request to get `review_version` when a branch review exists but applies to a
different scan context. Use it as `expected_version` for the write. The field
does not include the incompatible review's state or audit history. When a
compatible review is attached, use its `version` as before.

## Database startup and recovery

Use a dedicated SQLite file for each instance. The service initializes empty
unversioned files and upgrades version 1 or 2 databases to version 3 in one
transaction. Version 2 introduced exact float parsing; version 3 adds gate
policy history and nullable analysis bindings. Existing analyses stay
unassigned. The migration preserves reports, hashes, and reviews. Missing service indexes are recreated on startup. A
nonempty unversioned database, a database missing a required table, or an
unsupported version stops startup without switching its journal mode.

Reports ingested after the upgrade retain the CLI's floating-point percentages
through reads, exports, and restores. Replaying an original request for a legacy
row still resolves to its original analysis. An older row may already contain
rounded values; the service preserves those values.

Take a consistent SQLite backup before upgrading, including any committed
state in the WAL. Older binaries cannot open a version 3 database. Keep the
pre-upgrade SQLite backup for rollback.

Project JSON exports use backup schema 1 for unassigned projects and schema 2
for assigned projects. Schema 2 includes policy revisions and the binding for
each analysis. Restore recalculates each assigned gate from its policy and
validated report. Restore into an empty destination for recovery. A destination
with an existing policy accepts only matching policy history and known analyses
with unchanged bindings; an archive cannot insert an analysis under an older
or missing policy there. Previous service binaries cannot restore schema 2
JSON exports.

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

### Back up and restart a whole instance

Run one active service process per database on local storage. Keep the
database and its SQLite sidecars in the same directory. Monitor free space
for the database, WAL and recovery copies. Retention hides old analyses and
keeps an audit record; it does not reclaim their report data.

Use the commands below with the SQLite CLI and a private backup directory.
Run them with access to the live database and its sidecars. SQLite reads the
committed database while the service is online. For a planned move, pause
uploads and changes to reviews, policies and retention before taking the
final copy. A restore contains only the data included in that copy.

```sh
set -eu
umask 077
database=/srv/hoonarqube/service.sqlite3
snapshot=$(mktemp -d /secure/backups/hoonarqube.XXXXXXXX)
(
  cd "$snapshot"
  sqlite3 -batch -bail -readonly "$database" '.backup service.sqlite3'
  for suffix in -wal -shm -journal; do
    test ! -e "service.sqlite3$suffix"
  done
  # Use immutable mode only on the closed, standalone backup.
  archive='file:service.sqlite3?mode=ro&immutable=1'
  integrity=$(sqlite3 -batch -bail -readonly "$archive" 'PRAGMA integrity_check;')
  foreign_keys=$(sqlite3 -batch -bail -readonly "$archive" 'PRAGMA foreign_key_check;')
  test "$integrity" = ok
  test -z "$foreign_keys"
  shasum -a 256 service.sqlite3 > SHA256SUMS
)
printf '%s\n' "$snapshot"
```

Record the backup time and service version, and keep the checksum receipt
in a trusted location. Back up the role assignments and credentials through
your credential store. The database contains actor IDs and project data, so
restrict the backup to operators who can access every project.

To rehearse recovery, copy the closed archive to a fresh directory and check
the copy against the trusted receipt. Use the same service version and an
isolated loopback port. The service account must be able to write the new
directory and read the supplied credentials file.

```sh
set -eu
umask 077
# Set snapshot and trusted_checksum_file to the absolute paths for this backup.
restored=$(mktemp -d /secure/recovery/hoonarqube.XXXXXXXX)
cp "$snapshot/service.sqlite3" "$restored/service.sqlite3"
(cd "$restored" && shasum -a 256 -c "$trusted_checksum_file")

env -u HOONARQUBE_SERVICE_CREDENTIALS \
  HOONARQUBE_SERVICE_DB="$restored/service.sqlite3" \
  HOONARQUBE_SERVICE_BIND=127.0.0.1:8081 \
  HOONARQUBE_SERVICE_CREDENTIALS_FILE=/secure/recovery/credentials.json \
  /path/to/hoonarqube-service
```

Verify that a reader can list only their projects. Check a known analysis
receipt, the first and last finding pages, an existing review history, any
assigned gate and a recently deleted analysis. Retry a saved upload body and
verify the expected analysis ID. Record how long copy, startup and these
checks take on your storage. Stop the old process before switching the
configured database path. Keep the untouched database and its
sidecars until you have verified the restored instance. Keep the older binary
and its pre-upgrade backup together if you need to roll back a schema upgrade.

For a restart without recovery, start the same binary against its existing
database. If you can, let pending uploads finish before stopping the process.
After startup, check a known project and use the saved request body for any
upload whose acknowledgement was lost.

### Recover one project above the HTTP limit

Use the operator script from this service revision on Linux or macOS with
Python 3.11 or later. It reads a schema version 2 or 3 service database, including
committed WAL records, in one read-only SQLite transaction. Only the exact
project is copied into a new SQLite file. The copy includes report bytes,
analysis and finding IDs, review revisions and actors, and soft deletions
and their audit records. Schema 3 also copies gate history, bound policy
versions, and initial decisions. The 16 MiB HTTP limit still applies to HTTP routes.

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
to the new file. Supply only the intended project's reader, scanner, reviewer, and admin
assignments from your credential store. Supply them through one of the two
credential sources described in [Start locally](#start-locally). The snapshot
contains review actor IDs, but no role assignments or bearer tokens. Keep the
same approved `user_id` for people whose review history should remain
attributable, and issue credentials for the restored instance.
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
project backup, and whole-instance recovery. During the SQLite backup it
pauses the copy after its first step, verifies that two reader requests and
one real upload finish, then verifies that the restored copy excludes that
later upload. The receipt includes SQLite integrity, gate versions, a
deletion audit record, and comparisons of paginated history, findings and
review history before and after restore. The recorded inputs were
Zod `0b216ef674e297ebe41d8bf902262e56f8755822` (5,941 findings), Acorn
`e4516ce0f49aea06b98ae1a551644119958ed4e1` (5,311), Ajv
`9050ba1359fb87cd7c143f3c79513ea7624ea443` (5,268), and Yjs
`ee37f0a0e23a7c3e14531bae335d439e54c743e6` (4,896). Assessed inputs were
4.1–7.0 MB each. This bounded loopback check measures local timings and
process restart recovery. The backup timing includes the deliberate pause;
use an uninterrupted rehearsal on your storage to set recovery targets.
Production throughput, availability, and recovery after machine or storage
failure remain untested.

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
