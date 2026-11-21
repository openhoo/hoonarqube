# Go: elapsed time until a persisted result can be read

On four pinned public Go projects, both services returned the same 81 source files and the same 25 primary locations for S1135, S1186, S1192 and S3776. Five measured runs per project followed one excluded warm-up. The table gives the median elapsed wall time. The final column counts all ordinary findings returned by each service, including rules outside the four-rule comparison.

| Project | Files | Shared primaries | No-TODO policy | Hoonarqube | SonarQube Community Build | All findings, native / Sonar |
|---|---:|---:|---|---:|---:|---:|
| chi | 35 | 14 | fail | 0.131 s | 6.050 s | 36 / 14 |
| mux | 6 | 6 | pass | 0.060 s | 5.961 s | 18 / 6 |
| cors | 3 | 4 | pass | 0.041 s | 6.090 s | 6 / 4 |
| pflag | 37 | 1 | pass | 0.119 s | 6.161 s | 19 / 1 |

The clock starts immediately before launching the scanner. For Hoonarqube it includes writing the native report, submitting it over HTTP to a running service, and reading the persisted report and findings. For SonarQube it includes the scanner upload, the compute-engine task and reading the indexed files and findings over HTTP. Both checks use a new analysis on each run. Native per-file caching is off. Each Sonar run uses a fresh private project; installed scanner dependencies, both servers and the OS file cache stay warm. Scanner order alternates. Source checkout, server startup, temporary project creation/deletion and subsequent correctness checks are outside the clock.

The [raw samples](public-go-pipeline-timing-20261120.json) include the separate scanner time, any outliers, source commits, executable hashes and all result digests. The [contract](public-go-pipeline-contract.json) was derived independently from an earlier Sonar API capture and checked against the native replay. Each timed run verifies the native and reference rule parameters, normalized file names and bytes, and the multiset of rule, file and UTF-16 primary range. A simple policy that rejects TODO findings fails for Chi and passes for the other three. It is calculated from the retrieved results; this does not exercise either product’s configured quality gates.

The native scanner and SonarScanner CLI 8.0.1.6346 ran as arm64 host processes on one shared Apple M4 Max. SonarQube Community Build 26.9.0.129388 ran in a Linux arm64 container limited to four CPUs and 5 GiB, with embedded H2; Hoonarqube used its host SQLite service. The servers have different resource limits and persistence models. These are four small codebases and five measurements each. They establish elapsed time for this installation and agreed output. They do not establish equivalent full profiles, a product-wide speed ratio, production capacity, p95 latency or all-in resource cost.

## Verify the persisted results in CI or locally

Normal CI runs this check with the candidate CLI and service binaries. It
fetches the four commit and tree pins, scans the declared scopes as source
data, starts a private loopback service with a fresh database, and reads the
persisted reports and indexed findings. It compares the file inventory and
content digest, primary location multiset, and no-TODO result with the
versioned Sonar contract. It needs Git and access to the four public GitHub
repositories. It does not build the Go projects or need a Sonar service.

```sh
python3 tools/oracle/public_go_pipeline.py --check-persisted \
  --native /path/to/hoonarqube --service /path/to/hoonarqube-service \
  --output /path/to/new-run
```

Use a fresh output path for each run. On success, `result.json` lists the
observed digests and counts. For a failure control, copy the versioned
contract, replace one project's `primaries_sha256` in the copy, and repeat
with `--expected-contract /path/to/copy.json` and a new output path. The
command should exit nonzero and name the changed field.

## Repeat the timing comparison

Use isolated native and reference services, check out the four repositories at the exact commits in the [manifest](public-corpus-projects-20261120.json) in subdirectories named chi, mux, cors and pflag, and supply an empty output directory **path that does not yet exist**. The reference token must be able to create and delete private projects on the disposable reference instance. The runner only deletes its own newly created project. Project source is scanned as data. The output directory contains scan logs, native reports and raw API pages; only the portable timing summary is committed here.

```sh
python3 tools/oracle/public_go_pipeline.py --sources /path/to/pinned-checkouts \
  --output /path/to/new-run --rounds 5 \
  --native /path/to/release/hoonarqube --service /path/to/release/hoonarqube-service \
  --java /path/to/jdk/bin/java --scanner-jar /path/to/sonar-scanner-cli.jar \
  --scanner-cache /path/to/scanner-cache --server http://localhost:9000 \
  --token-file /private/path/to/reference-token
```
