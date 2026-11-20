# Qualification after integrating the original pull requests

## Decision

Keep the native Rust scanner, versioned report, separate report service, and independent Sonar comparison harness. Use the product in shadow mode on a team repository with an existing quality gate. The results below do not establish drop-in compatibility or a performance advantage over SonarQube.

The original review found 76 open pull requests and two open issues. Both issues and all 76 original pull requests were reconciled on GitHub. This is the verification baseline for the integrated C# and Python changes: `1884c8bca3f62fa83964914ce972392ad21af383`. Newly opened qualification and repair pull requests have separate status.

## Fresh public replay

The release build was executed again on 70 pinned public-source scopes. The independent reference is SonarQube Community Build 26.9.0.129388. The reference results were retained from actual server analyses, including the indexed sources and compute-engine results. The table counts only complete scans with identical paths and file contents on both sides. A project can have more than one attempted scope. C# compiler-backed checks have a separate [four-project pilot](../../tools/oracle/public-csharp-pilot-20261120.md).

| Language | Attempted scopes | Identical scopes | Files | Same primary finding | Native only | Sonar only |
|---|---:|---:|---:|---:|---:|---:|
| Go | 10 | 10 | 163 | 94 | 8 | 7 |
| Java | 9 | 7 | 407 | 123 | 175 | 4 |
| JavaScript | 10 | 8 | 429 | 794 | 703 | 210 |
| Python | 13 | 13 | 337 | 1309 | 262 | 413 |
| Ruby | 11 | 10 | 704 | 132 | 334 | 18 |
| Rust | 7 | 6 | 240 | 40 | 195 | 0 |
| TypeScript | 10 | 5 | 285 | 734 | 120 | 153 |
| **Total** | 70 | 59 | 2565 | 3226 | 1797 | 805 |

6,403 of 7,691 compared file metric values matched. A primary match requires the same implemented rule with the same declared parameters, relative path and UTF-16 range. Messages, secondary locations, issue flows, fixes, profiles from commercial editions and quality gates each require their own evidence. One-sided findings require adjudication before they can be classified as false positives or false negatives.

[Per-project data, source commits, builds and inventory hashes](core-public-replay-2026-11-20.json) · [First corpus method](../../tools/oracle/public-corpus-20261120.md) · [Second corpus method](../../tools/oracle/public-corpus-wave2-20261120.md)

## Architecture and release criteria

| Interface | What the evidence supports | What must pass before migration |
|---|---|---|
| Source discovery and compiler context | Comparing the indexed file bytes catches scope drift. Real projects can still yield incomplete analysis. | Inventory the target repository, build inputs and exclusions. A missing compiler context or missing coverage must never yield a passing required gate. |
| Analyzer and report | Rule IDs and primary spans can be checked independently of rendering. The comparison shows how many findings remain one-sided. | Adjudicate differences in the pilot’s blocking rules, including messages and secondary evidence. Keep regression controls for renames and formatting. |
| CLI and performance | [Five native workloads](../../tools/oracle/public-native-load-20261120.md) and [four Go pipelines](../../tools/oracle/public-go-pipeline-timing-20261120.md) have distinct measurement boundaries. | Set runner, compiler context, concurrency and cache state before comparing p50/p95 elapsed time, CPU and peak memory. Accept speed gains only if the reports remain equivalent. |
| Service | The baseline supports authenticated ingestion, deterministic retries and restart. Public-corpus scanner evidence does not qualify deployment or tenant recovery. | Exercise isolation, credential revocation, retention, backup/restore and rollback with the pilot’s largest report. Specify recovery targets and the supported deployment topology. |
| Compatibility | Native reports and CI exports have tests. No commercial-edition baseline or general project-history migration is demonstrated here. | List the customer’s required API calls, scanners, quality profiles, historical measures and permissions. Verify each required workflow on the target edition. |

Retain the existing quality gate until the team accepts the comparison and completes a rollback rehearsal.
