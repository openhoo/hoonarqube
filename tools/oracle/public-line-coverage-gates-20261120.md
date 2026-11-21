# A measured coverage gate on Commander.js

At a 60% overall line coverage threshold, Hoonarqube and SonarQube Community Build 26.9.0.129388 reject the focused test run and accept the broader run. Comparing the same inputs at 59.2% exposes a difference in precision: SonarQube compares the rounded measurement; the default Hoonarqube gate compares the full ratio. Select `precision: "one_decimal"` for an overall line coverage condition when migrating this behavior.

| Upstream tests | Covered / eligible lines | Required minimum | SonarQube | Hoonarqube, full | Hoonarqube, one decimal |
|---|---:|---:|---|---|---|
| 43 passed | 2,485 / 4,201 | 60% | ERROR (59.2%) | fail (59.15258…%) | fail (59.2%) |
| 588 passed | 3,907 / 4,201 | 60% | OK (93.0%) | pass (93.00166…%) | pass (93.0%) |
| Same 43-test LCOV | 2,485 / 4,201 | 59.2% | OK (59.2%) | fail (59.15258…%) | pass (59.2%) |
| No LCOV supplied | No imported line counts | 60% | ERROR (0.0%) | unavailable | unavailable |

The source was `tj/commander.js` at `ba6d13ddb4243e5913367734f8c159089ffe7834`, with seven files under `index.js` and `lib`. Both engines saw the same source bytes, LCOV input, and per-file eligible and covered line counts in all three runs that supplied coverage. The 43 tests are also included in the 588-test selection. Node ran the project's tests without dependency installation, in a read-only container with networking disabled. All four Sonar background tasks succeeded. Each analyzed gate returned one evaluated condition and `ignoredConditions: false`.

Without LCOV, SonarQube classified 1,252 lines as eligible and all 1,252 as uncovered. Hoonarqube deliberately returns exit 2 for missing coverage. Its source analysis still completed. No branch coverage, new-code gates, or other editions were qualified here.

The [CI replay](community-gate-contract.md) uses the original compressed LCOV inputs to check these decisions on every pull request without Docker or upstream test execution.

## Replay the native CLI

The [receipt](public-line-coverage-gates-20261120.json) records source hashes, test selection, container digests, per-file line evidence, compute-task and analysis IDs, reference decisions and both native modes. From the root of this repository, with an empty destination:

```sh
git clone https://github.com/tj/commander.js.git commander-src
git -C commander-src checkout --detach ba6d13ddb4243e5913367734f8c159089ffe7834
docker pull --platform linux/arm64 node@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
cargo build --locked --release -p hoonarqube-cli -p hoonarqube-service --bins
python3 tools/oracle/public_coverage_gate_replay.py commander-src coverage-results target/release/hoonarqube --service target/release/hoonarqube-service
```

The replay runs both measured test sets, checks each file's covered-line map, and checks the exit code and condition emitted for all eight native cases. It scans a local clone and supplies a relative LCOV path. The service rejects reports containing absolute host paths. With `--service`, the replay uploads the unmodified reports, restarts the service, compares the stored reports, retries all eight uploads and checks that two inconsistent gate claims are rejected. No live Sonar server is needed for this step.

## Reproduce the reference

1. Start the isolated Community Build and scanner at the image digests in the receipt. Create four new private project keys on the instance; keep built-in language profiles unchanged.
2. Create custom non-default quality gates with a single `line_coverage` condition, comparator `LT`, and error thresholds `60` and `59.2`. Remove auto-seeded new-code conditions from these new gates. Assign the 59.2 gate only to the rounding-boundary project.
3. For each case, run the pinned scanner with the public checkout mounted read-only, `sonar.sources=index.js,lib`, UTF-8 encoding, SCM disabled, and the pinned SHA as the project version. For measured cases mount the appropriate replayed LCOV read-only and pass its in-container path as `sonar.javascript.lcov.reportPaths`. Omit that property and mount for the missing-input project.
4. Require `SUCCESS` from `/api/ce/task`. Read `/api/qualitygates/project_status` by the returned analysis ID. Compare `line_coverage`, `lines_to_cover` and `uncovered_lines` at project and file level via `/api/measures/component` and `/api/measures/component_tree`. A gate with zero evaluated conditions does not qualify.
