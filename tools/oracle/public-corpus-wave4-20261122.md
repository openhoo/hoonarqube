# Public source comparison with SonarQube, Wave 4

On November 22, 2026, SonarQube Community Build `26.9.0.129388` completed
84 independent analyses. The [manifest](public-corpus-wave4-projects-20261122.json)
pins 84 distinct repositories, their commits and trees, and the Git blobs
and SHA-256 hashes of 1,217 selected files. These scopes do not repeat a
repository, commit, or tree from the preceding corpus and C# pilot manifests.

## Retained comparison and merged scanner replay

The retained Hoonarqube `0.11.1` capture at
`649f27bc3e7af3f8c7ce988354c31075773da5a4` completed 83 scopes. For
`sindresorhus/got`, SonarQube analyzed all 26 files. Hoonarqube completed
25 and reported `source/index.ts` incomplete. Got is excluded from the
retained comparison: 83 pairs, 1,191 files, 1,974 matching primaries,
731 native only, 1,168 reference only, and 3,095 of 3,573 equal file metrics.

After [the parser fix](https://github.com/openhoo/hoonarqube/pull/999)
merged, we built the scanner from its signed squash commit and reran all
84 scopes. We paired the new native results with the same frozen reference
analyses and verified every selected path and its bytes. Both engines
completed all 84 scopes.

| Selection language | Pairs | Files | Matching primaries | Native only | Reference only | Equal / compared file metrics |
|---|---:|---:|---:|---:|---:|---:|
| Go | 18 | 72 | 84 | 6 | 0 | 216 / 216 |
| JavaScript | 12 | 88 | 543 | 326 | 187 | 264 / 264 |
| Python | 14 | 259 | 757 | 72 | 83 | 777 / 777 |
| Ruby | 15 | 344 | 42 | 1 | 1 | 709 / 1,032 |
| Rust | 16 | 184 | 26 | 111 | 0 | 397 / 552 |
| TypeScript | 9 | 270 | 557 | 247 | 912 | 810 / 810 |
| **Total** | **84** | **1,217** | **2,009** | **763** | **1,183** | **3,173 / 3,651** |

The original 83 pairs kept identical native JSON reports and comparison
counts. Got accounts for the entire change: 26 newly comparable files,
35 matching primaries, 32 native only, 15 reference only, and 78 of 78
equal file metrics. The native issue total stayed at 35,605 raw records
across all 1,217 selected file reports, including findings outside the
comparison filter.

## What the numbers mean

A primary finding matches by rule, relative path, and full normalized
UTF-16 range. Counts include only implemented rules active in both
profiles with equal declared parameters. One-sided findings need review
before classifying them as false positives or missed findings. File metrics
are lines, code lines, and comment lines.

The Rust sensor logged completion for all 16 Rust scopes without a
per-file count; the paired indexes verified the paths and file bytes.
A separate earlier reference attempt on the Wave 2 server stopped at
Elasticsearch's disk watermark and yielded zero pairs. The table uses
the successful run on a separate Community Build instance.

These are bounded static source scans. The run did not install upstream
dependencies or execute project scripts. It does not establish agreement
on secondary locations, data flow, fixes, coverage or duplication gates,
commercial analyzers, or acceptance on a team's own repositories.

## Provenance and reproduction

- Merged product commit: `80837cdef018272d1994b7809fa97c5ddff88967`.
  Tree: `75468849c34e09768d76f2f21248c9c9ab94277d`.
- Native release build: Hoonarqube `0.11.1`, Rust `1.96.0`, Darwin arm64.
  Binary SHA-256: `f3b24ae7af0861e7f57e5442c161e667a14760e23ab292779edc6b9eda586812`.
- Reference: the pinned Linux arm64 Community Build server and amd64
  scanner images. All 27 effective profiles matched before and after the
  reference run and against the historical pin. The normalized profile
  SHA-256 was `ea664d94fa59a597760f4f78aaad2c5e2136ef48d4196ee3d6853fd726f8fe80`.

The local harness uses `wave4_prepare.py --manifest` to restore the
pinned files. Run `wave4_build_receipt.py` from the clean product checkout
after a locked release build, then run the `native`, `reference`, and
`summary` phases of `wave4_capture.py` with the same state directory.
The reference phase requires a fresh private Community Build instance
and unused project keys. Leave at least 5 GiB of host disk free.

The [manual Actions workflow](../../.github/workflows/public-corpus-wave4.yml)
shows the container and capture commands, using six language shards on
Linux amd64. The results above come from local runs. The manual hosted
workflow has not been run.
