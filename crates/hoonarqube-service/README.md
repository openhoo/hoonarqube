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
