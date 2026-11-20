# Reading reviewed findings from SQLite

Listing findings used to execute a review lookup for each unambiguous finding. If a review came from an earlier scan, it also loaded and parsed two entire assessments for every match. The service now reads the findings, looks up the eligible review identities together, and loads only the relevant context objects. The analysis must still be live and visible to the project; a soft-deleted earlier analysis can supply review provenance. The operations share one read transaction. A request uses at most four data queries, independent of finding count.

A scan rooted at `.` also exposed a data binding bug: the report can present `./middleware/realip.go` while the assessment records `middleware/realip.go`. The service now matches the same normalized path as the scanner, after its existing path validation. The response keeps the original display path.

## Measurement

[Per-run samples, response digests and source pins](service-findings-benchmark-2026-11-20.json). Both service binaries used the same Rust release settings on one shared Apple Silicon host. The inputs were complete native reports with assessments from Chi, Requests and serde_json. Each comparison used a fresh SQLite database and the same data for both binaries. The second analysis replays the original report with an explicit test commit label and no source revision. It tests review inheritance, not a second source revision.

| HTTP findings response | Files | Findings / reviewed | Same-analysis median, before → after | Inherited median, before → after |
| --- | ---: | ---: | ---: | ---: |
| Chi | 35 | 35 / 12 | 0.53 → 0.50 ms | 5.77 → 0.61 ms |
| Requests | 19 | 194 / 12 | 1.05 → 0.77 ms | 13.63 → 1.25 ms |
| serde_json | 37 | 1,994 / 10 | 3.63 → 3.50 ms | 61.28 → 5.95 ms |

The runner warms each route, measures 11 requests per process in candidate/baseline/baseline/candidate order, and requires byte-identical HTTP response bodies on all 22 measurements per route and binary. The timer includes a fresh loopback connection, request handling, SQLite, JSON serialization and body transfer. The Chi timing uses its original 35 files passed explicitly because the previous service rejected the directory-rooted report. The repaired endpoint also accepted the original directory-rooted report.

To repeat with complete raw CLI reports produced by `hoonarqube analyze --assessment --format json ...`:

```sh
python3 scripts/benchmark_service_findings.py --baseline /path/to/old-service \
  --candidate /path/to/new-service chi.json requests.json serde-json.json
```

This measures a warm findings endpoint, not scan time, concurrent capacity, or performance against SonarQube. As a separate intake check, the service accepted all 29 first-wave native report payloads (including the incomplete Redux report) and three assessed reports. Six payloads contained floating-point duplication densities that did not round-trip exactly on the baseline or candidate; finding-list comparisons are unaffected.
