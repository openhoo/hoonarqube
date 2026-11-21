# Replaying the recorded Community quality gates in CI

The `quality-code-quality` job checks ten reports from the current CLI against completed SonarQube Community Build analyses from November 20, 2026. It fetches three public Git revisions and verifies the tree and the SHA-256 of every file in the recorded source scope. The scans use the production CLI and a local instance of the production HTTP service. They do not run public project code, install Node packages, use Docker, or need a running SonarQube instance.

| Project and OVERALL condition | Community result | Expected Hoonarqube result |
| --- | --- | --- |
| Commander, 2,485 of 4,201 lines covered, minimum 60% | 59.2%, fails | Fails at full and one-decimal precision; exit 1 |
| Commander, 3,907 of 4,201 lines covered, minimum 60% | 93.0%, passes | Passes at both precisions; exit 0 |
| Commander, 2,485 of 4,201 lines covered, minimum 59.2% | 59.2%, passes | Full precision (59.15258271840038%) fails; explicit `one_decimal` passes |
| Commander without LCOV, minimum 60% | Computes 1,252 uncovered of 1,252 eligible lines: 0.0%, fails | Both modes return `unavailable`, no measured value, exit 2 |
| Picomatch, 6 files; maximum 0 duplicated lines and 0% density | 0 lines and 0.0%, passes | Both conditions pass; exit 0 |
| Yjs, 32 files; same two maximums | 141 lines and 1.1%, fails | 141 lines and 1.1000156030581993%; both conditions fail, exit 1 |

The two compressed Commander LCOVs in `fixtures/commander-lcov/` are the actual Node test outputs used for the capture. CI checks the decompressed bytes against the [coverage receipt](public-line-coverage-gates-20261120.json), then verifies each source file’s covered-line map. The [duplication receipt](../../docs/public-quality-gates-20261120.json) records the two independent Community condition values and decisions. CI uploads every generated native report, restarts the service, reads it back and retries the upload. Two inconsistent coverage claims must receive HTTP 409.

Run from the repository root:

```sh
cargo build --locked -p hoonarqube-cli -p hoonarqube-service
python3 -m unittest discover -s tools/oracle -p test_community_gate_contract.py -v
python3 tools/oracle/community_gate_contract.py target/debug
```

For an offline run, append `--local /path/to/checkouts`. This directory must contain Git repositories named `commander`, `picomatch` and `yjs` with HEAD at their recorded revisions. The replay uses temporary clones.

These are **custom gates** on the recorded overall JavaScript scope. This contract does not qualify New Code, branch coverage, the default Community gate or changes in a newer Community server. For the wider acceptance criteria, see [Community CI acceptance](../../docs/engineering/community-ci-acceptance.md). For the separate procedure that regenerates LCOVs by running the pinned upstream tests, see [the coverage experiment](public-line-coverage-gates-20261120.md).
