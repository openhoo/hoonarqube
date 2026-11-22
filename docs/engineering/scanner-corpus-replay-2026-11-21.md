# Pinia and Black scanner replay

Replayed **122 pinned scopes in 120 public repositories** with the Pinia parser and Black Python fixes, using the same SonarQube Community Build 26.9.0.129388 captures and source pins. The scanner ran with the `sonar-parity` profile. The #996 contract passed **25/25 repositories** against the candidate CLI.

| Comparison population | Before | After |
| --- | ---: | ---: |
| Exact indexed scope | 108 | 108 |
| Comparable shared files only | 8 | 9 |
| Reference sensor scope excluded | 1 | 1 |
| Incomplete or unavailable | 5 | 4 |
| Files in exact scopes | 3,434 | 3,434 |
| Primary matches in exact scopes | 4,582 | 4,583 |
| Native-only primaries in exact scopes | 1,299 | 1,299 |
| Reference-only primaries in exact scopes | 708 | 707 |

Pinia's scan exit changed from 2 to 0. Its previous failed path, `packages/pinia/src/devtools/formatting.ts`, now completes. Hoonarqube reports 19 files; the reference indexed 18 and omitted `packages/pinia/src/global.d.ts`. On the 18 shared files, the comparison reports 48 matched, 14 native-only and 7 reference-only primaries for active rules with equal declared parameters. The incomplete baseline had no eligible Pinia comparison. The exact-scope totals exclude Pinia and the other partial or unavailable scopes.

Black remains an exact-scope comparison in the release run (25 files). Python S1066 counts (matched / native-only / reference-only) are 9/0/1 before and 10/0/0 after.

In a separate debug run of the Pinia-only build, Black exited 101 in Python S1066. A multiline nested condition ended in a lower column than it started, and the previous implementation subtracted those columns as unsigned values. The Black patch corrects that case.

Scopes with a changed native JSON report: black, pinia.
Papa Parse remains excluded from the comparable scope because its retained reference JavaScript sensor skipped analysis. An exact indexed scope does not show that every file passed through every sensor. One-sided primaries do not establish detection accuracy.

Source `649f27bc3e7af3f8c7ce988354c31075773da5a4`; compiled tree `9a4c6d089080bc95be4786013b45d39aaf2b932c`; CLI SHA-256 `50d85c9c44a6cd44588bda22ecbdbebd9dfb79a02db7a7d8f45d56ad0a35d4ba` (release profile).

[Machine-readable comparison, exact build and project checks](scanner-corpus-replay-2026-11-21.json).
