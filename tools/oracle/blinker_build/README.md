# Blinker: from a public wheel build to a blocking CI gate

The full test suite passed its assigned 80% coverage gate. A smaller suite at the same revision also passed its tests, but failed the gate. Omitting the coverage file blocked the job in both products.

| Input at Blinker `c3364059663df1ddce32799d6b1922af89a345f6` | Tests passed | Lines covered | Branches covered | Combined / line coverage | Community gate | Native CLI / assigned gate |
| --- | ---: | ---: | ---: | --- | --- | --- |
| All upstream tests | 25 | 204/217 | 65/72 | 93.1% / 94.0% | OK | 0 / pass |
| Only `tests/test_context.py` | 4 | 141/217 | 28/72 | 58.5% / 65.0% | ERROR | 1 / fail |
| No coverage input | — | — | — | Community: 0% / 0%; native: unavailable | ERROR | 2 / unavailable |

The third run uses the same three source files. Community inferred 204 executable lines from source without a report and counted them all as uncovered. Hoonarqube kept both required measurements unavailable. The two paths agree on whether to block CI; they deliberately report different evidence for that decision.

## Run the contract

From the project root, with Git, Python 3.11+, Docker and the Rust toolchain:

```sh
cargo build --locked --release -p hoonarqube-cli -p hoonarqube-service
python3 tools/oracle/blinker_build/replay.py target/release
```

The CI job rebuilds the Blinker wheel; it does not consume a prebuilt test report. It fetches the exact public Git tree, checks the hashes of all 27 tracked files, downloads seven pinned dependency wheels, and uses a digest-pinned Python 3.13.18 Linux image. Five test dependency wheels also match Blinker's own lockfile. Coverage and the Flit build backend are pinned separately. Use `--repository` and `--wheel-cache` with local mirrors for offline runs; the Docker image must already be present. `--architecture amd64` or `arm64` selects the Linux build platform.

The build and both test suites run as an unprivileged user in a fresh container with networking disabled. The three host mounts are read-only. Upstream tests import the installed wheel; the harness checks its digest and verifies its bundled source bytes against the checkout. It exports LCOV and Cobertura XML from the same coverage database for each suite.

The replay checks the LCOV bytes against the pinned digest. It checks the XML against a separate pinned digest after replacing only the root `timestamp` value with `0`. The analyzer receives the original bytes for each export, and its report must record the exact input path, format and raw digest. The two native imports must return the same coverage for every line.

The analyzer and service run outside the container. For each report, the replay checks the source revision and inventory, per-file line and branch counts, both CLI conditions, and the process exit code. It then submits the analysis **without** a scanner gate and reads the service's assigned gate by analysis ID. After a restart, the stored gate must still match, and retrying the submission must return the same stored row.

## Independent reference

The [reference responses](reference.json) come from three private projects on a local SonarQube Community Build **26.9.0.129388**. Each has a distinct successful compute task and analysis at the pinned Blinker revision, the default Python *Sonar way* profile, and an explicitly assigned, non-default gate. Both overall conditions use `LT 80`: `coverage` and `line_coverage`. All three scans indexed the exact Python sources under `src/blinker`. Nothing in the test or documentation tree entered the source metrics. The reference records both the raw digest of the XML Community imported and its digest with the timestamp replaced. A fresh wheel replay compares the latter because its XML has a new timestamp.

To recapture, run the two suites with branch coverage and Blinker's own path mappings. Use `coverage combine` and export both Cobertura XML and LCOV from the same database for each suite, including only `src/blinker/*`. Mount the source at `/job/source` to resolve the original XML source path. Import the XML in the corresponding Community scan using `sonar.python.coverage.reportPaths`; omit that setting and remove the report for the negative control. Set `sonar.sources=src/blinker`, `sonar.inclusions=**/*.py`, the pinned SCM revision and explicit UTF-8. Confirm the file inventory, wait for the compute task, fetch the gate by its analysis ID and record the per-file measures. The CI replay uses those frozen responses; it does not start another Community server on every pull request.

This contract covers overall line and combined coverage on one Python version and one change of test scope. It does not exercise new-code coverage, a multi-version upstream CI matrix, or server throughput.
