# Community 26.11 Go package gates

`reference.json` records independent SonarQube Community Build 26.11.0.134175 analyses of 32 public Go root packages. The cohort was fixed before looking at findings. For each commit the input is every regular root-level `.go` file other than `_test.go`, including platform-specific files: 324 files in total. Neither the capture nor the replay builds or runs upstream code. This is a static file selection, not a Go build for a specific platform.

Capture used SonarGo 1.48.0.9254. The server image digest was `sha256:7b2296713a92b8ea0dd7a083a25faadc59376c9a1e6daf2744a89711c54ea1ba`; the scanner image digest was `sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9`.

Each package had two private reference projects. Each used its assigned built-in Go profile (Core: six rules, Extended: nine) and a project-specific gate that fails when overall `violations > 0`. The manifest records commit, tree, file digests, complete reference file index, project, compute task, analysis ID, measured gate and primary findings for both profiles. Capture verified profile settings before and after both batches; each measured gate was read by analysis ID. External issues, other rules and hotspots are counted separately.

Run from the repository root after building both release binaries:

```sh
python3 tools/oracle/community_go_packages.py target/release --output go-packages.json
```

The replay fetches the pinned Git objects without checking out or executing their code. Use `--mirrors DIR` with `OWNER--REPO/objects` stores to replay offline. Use `--case hashicorp/go-multierror --tier extended` for the known S3776 regression.

The CLI and an independently assigned service policy must agree with the reference decision; the service receives an ordinary report and must retain its gate across a real restart. The JSON output lists exact, additional and missing active findings as multisets of rule, filename, UTF-16 start/end and message. A green gate replay does not assert finding parity. Core had no active findings in this cohort. Extended had 106 active reference findings. At the repair revision, 87 match exactly, 19 appear only in the reference and 23 only in the native report. The different totals change the measured count for five packages, even though all 32 Extended gate verdicts agree. This does not cover every Go input, complete modules, external linters or the Comprehensive profile.
