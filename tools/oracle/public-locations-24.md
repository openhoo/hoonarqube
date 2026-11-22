# Public source locations on 24 more repositories

The [CI replay](public_locations.py) checks 196 pinned source files from 24
public GitHub repositories. Each of the six languages has four repositories.
Community Build 26.9.0.129388 produced 390 ordinary issues on the shared rules
and parameters. The native baseline `3f9c1a55` matched 356 primary locations,
missed 34 and reported 52 extra. A matching location has the same rule, file,
start and end in UTF-16 coordinates. Counts include repeated occurrences.

A change fails if it loses a previously matched location, introduces an extra
one, or increases the multiplicity of an existing difference. Known differences
can disappear. Improving one repository cannot compensate for a new discrepancy
elsewhere. A green replay means no difference outside the recorded allowances.
After a fix lands, narrow its allowance against the same independent evidence
to prevent a later regression.

| Language | Repositories | Files | Matched | Only native | Only Community |
| --- | ---: | ---: | ---: | ---: | ---: |
| Go | 4 | 19 | 27 | 2 | 0 |
| Python | 4 | 60 | 235 | 8 | 20 |
| Rust | 4 | 45 | 26 | 15 | 0 |
| Ruby | 4 | 47 | 7 | 0 | 6 |
| JavaScript | 4 | 6 | 24 | 16 | 3 |
| TypeScript | 4 | 19 | 37 | 11 | 5 |

Run from the repository root:

```sh
python3 tools/oracle/public_locations.py target/release/hoonarqube
```

For offline use add `--local-sources PATH` pointing to a JSON map of GitHub
slugs to Git repositories checked out at the recorded revision. Git stages
only regular source blobs whose tree and SHA-256 match the fixture. The CLI
runs with an empty PATH and HOME; project scripts and package managers do not run.

The [fixture](fixtures/public-locations-24.json.gz) contains the 24 distinct
Community analysis and task IDs, hashes of the captured issues and scanner log,
the rule parameters, and the individual reference locations and allowances.
The [capture tool](public_locations_capture.py) rebuilds it from the archived
cohort, including both source indexes and paginated Community issues:

```sh
python3 tools/oracle/public_locations_capture.py CAPTURE_DIR OUTPUT.json.gz
```

This is a source-only comparison. It excludes hotspots, unsupported rules,
differently configured rules and project-level findings. For example, the
baseline produced 1,960 findings for rules inactive in the reference profile;
they are outside this comparison. It covers the listed source files rather
than an entire built application. Java and C# are outside this cohort.

The [Community 26.11 comparison](community-profiles-26.11.md) keeps the same source pins and reports three profiles separately.

## Fixes enforced after the baseline

The frozen fixture above preserves the original measurements. The [resolved
locations](fixtures/public-locations-resolved.json) subtract individual allowances
for fixes that have their own before/after replay. Ten extra S6643 locations in
`jshttp/accepts` were removed on candidate `3825e152`. An older scanner now fails
on these ten exact locations; the corrected scanner passes all 24 projects with
356 matches, 42 additional locations and 34 missing locations.
