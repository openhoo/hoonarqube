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
