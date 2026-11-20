# Java and Ruby: tested catalog implementations

The coverage audit counts six directly tested Java detectors out of 733 frozen rules, and seven Ruby detectors out of 42. It previously counted only the two comment tags (S1134 and S1135) in each language. The implementation-gap flag takes precedence over code markers: nine entries from the original catalog import still said these shipped detectors were awaiting implementation. Their boundary descriptions now identify what each detector actually checks.

The two positive controls in `xtask/tests/fixtures/coverage` run through the public analyzer with its default `sonar-parity` profile. For each language the test compares the keys emitted with the exact set counted as implemented and directly tested by the audit. Existing detector-specific tests provide positive and negative semantic controls; three Java tests now also assert the rule key of the returned finding. The change affects audit metadata and tests. It does not add detections or change which rules run.

## What the public reference observed

We reused the independent SonarQube Community 26.9.0.129388 captures and the native release replay from commit `1884c8bca3f62fa83964914ce972392ad21af383`. We included all seven Java and ten Ruby projects for which both scanners completed on identical files with the same source hashes. These 17 scopes contain 1,111 files in total. Devise, Gson and jsoup were incomplete or unavailable in these waves and are excluded. The figures cover the 13 dispatched Java/Ruby rules only.

A match requires the same rule key, repository-relative path, start and end in UTF-16 coordinates, preserving duplicate occurrences. File-level issues match without a range. The last column also requires identical message text. “Inactive” means that the reference’s captured default language profile did not enable the rule on any included project; native findings on those rules are not evidence of a detector mismatch.

| Rule | Reference profile | Matched | Native only | Reference only | Same primary and message |
|---|---|---:|---:|---:|---:|
| java:S1117 | active | 10 | 19 | 1 | 10 |
| java:S1134 | active | 1 | 0 | 0 | 1 |
| java:S1135 | active | 92 | 0 | 0 | 92 |
| java:S1854 | active | 7 | 156 | 3 | 7 |
| java:S2143 | active | 13 | 0 | 0 | 13 |
| java:S2211 | inactive | 0 | 26 | 0 | 0 |
| ruby:S1067 | inactive | 0 | 13 | 0 | 0 |
| ruby:S1134 | active | 3 | 0 | 0 | 3 |
| ruby:S1135 | active | 19 | 0 | 0 | 19 |
| ruby:S1192 | active | 40 | 0 | 0 | 40 |
| ruby:S126 | inactive | 0 | 62 | 0 | 0 |
| ruby:S134 | inactive | 0 | 19 | 0 | 0 |
| ruby:S1764 | active | 0 | 0 | 0 | 0 |

For example, Java S1854 reports dead stores, but the two implementations disagree on these inputs: 7 primary matches, 156 findings only on the native side, and 3 only on the reference side. Ruby S1192 matches all 40 observed findings, including messages. There are no occurrences of Ruby S1764 on either side of these public scopes; its dispatch is exercised by the committed positive control. This comparison does not qualify secondary flows, every possible input, or the unimplemented 727 Java and 35 Ruby keys.

The [per-project receipt](java-ruby-coverage-20261120.json) records the exact upstream projects and commits, input scopes, reference settings for these rules, individual counts, raw native/reference output hashes, and excluded projects. The underlying public corpus methods and captured scope descriptions are in [wave one](https://github.com/openhoo/hoonarqube/pull/955) and [wave two](https://github.com/openhoo/hoonarqube/pull/960). No source project was rebuilt or rescanned on the server for this audit.

## Check locally

```sh
cargo test --locked -p xtask coverage_matches_observed_sonar_parity_rules
cargo test --locked -p hoonarqube-java -p hoonarqube-ruby --lib
cargo run --locked -q -p xtask -- catalog coverage --strict --allow-infra
```
