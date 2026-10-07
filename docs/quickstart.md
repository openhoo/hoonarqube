# Hoonarqube quickstart

Run these commands from the repository root. The checked-in
`rust-toolchain.toml` selects the required Rust toolchain.

## Build and scan

```bash
cargo build --locked -p hoonarqube-cli
./target/debug/hoonarqube --version
./target/debug/hoonarqube analyze -- src tests
```

Replace `src tests` with your source files or directories. The default
`sonar-parity` profile uses the frozen Sonar catalog. Use
`--profile recommended` to include the recommended native rules. Rule catalog
coverage and reference parity have separate evidence; a catalog entry alone
does not establish an executable detector or verified parity.

## Choose a report

| Consumer | Options |
|---|---|
| Terminal | Default text output |
| Native project findings, metrics, and completeness | `--format json` |
| SonarQube Generic Issue Import | `--format sonar` |
| GitLab Code Quality | `--format gitlab-codequality` |
| GitHub code scanning | `--profile github-code-quality --format sarif` |

```bash
./target/debug/hoonarqube analyze --format json -- src tests > report.json
./target/debug/hoonarqube analyze --profile github-code-quality --format sarif -- src tests > report.sarif
```

SARIF requires the isolated `github-code-quality` profile. JSON reports
include project completeness; finding-only exports do not replace that status.
Keep stderr and the command's exit code when exporting a report.

## Interpret the scan result

For an ordinary scan without a quality gate or parity-reference comparison:

| Exit | Meaning |
|---|---|
| `0` | Analysis completed; findings may still be present. |
| `1` | Report rendering or writing failed. |
| `2` | Invalid options or incomplete analysis. Inspect stderr and the report. |

An incomplete scan can emit a valid report and still exit `2`. A configured
quality gate that fails exits `1`; an unavailable gate exits `2`. Read the
[assessment options](../README.md#usage) before using gates or baselines.

In a shell that stops on command errors, explicitly preserve the scan status:

```bash
status=0
./target/debug/hoonarqube analyze --format json -- src tests > report.json || status=$?
printf 'Hoonarqube exit: %s\n' "$status"
# Inspect report.json and stderr before applying your CI policy.
exit "$status"
```

## Preview and apply fixes

```bash
./target/debug/hoonarqube fix --diff -- src tests
./target/debug/hoonarqube fix --apply -- src tests
```

`fix` defaults to a dry run. `--apply` reanalyzes projected content before
writing and refuses an unverifiable rewrite, including a mechanical final
newline on an unsupported explicit file. Symlinked paths and files changed
since planning are refused. A refusal leaves the affected file unchanged and
returns a nonzero exit code; a multi-file run may have applied other verified
files before encountering a refusal. Review your diff after any apply run.

See [QUICKFIX.md](../QUICKFIX.md) for rule filters, explicit suggestions,
conflicts, and compiler-backed context requirements.

## Find a rule or use the dashboard

```bash
./target/debug/hoonarqube rules list --lang py
./target/debug/hoonarqube rules search --lang py unused
./target/debug/hoonarqube rules native --profile recommended
./target/debug/hoonarqube analyze --help
```

The optional authenticated dashboard stores submitted analysis reports and
review history. Build it with `cargo build --locked -p hoonarqube-service`,
then follow the [service configuration](../README.md#optional-analysis-service-and-dashboard)
for credentials, persistent storage, API ingestion, and launch instructions.
The service consumes reports produced by the analyzer.
