# TypeScript S8786: the duration parser in ms

The detector now reports the same finding as Community Build
`26.11.0.134175` in vercel/ms `src/index.ts`, line 78, UTF-16 offsets
4–155. Both tools anchor the finding on the complete regex literal and use
the same issue message. The [original four-project
comparison](typescript-core-public-26.11.md) records the missed finding
before this change.

The duration parser anchors its regex at the start and end of a string. The
previous detector checked whether a match could restart at many positions.
It missed the case where **two repetitions within one anchored match** can
consume the same characters with an optional separator between them. The new
check uses the parsed regex and tests that the prefix, both repeats and the
remaining suffix support this case. It does not execute the regex. The
detector still makes no general claim about all regexes, all flags, or the
application's runtime performance.

## Public evidence

The [receipt](../../tools/oracle/typescript-core-s8786-public-26.11.json)
records 37 matching source paths and hashes across seven repositories, the
pinned analysis IDs, and exact findings including nonmatching rules. Four
scopes reuse #1031's verified reference analyses; three further single-file
analyses used the same Community Build and default TypeScript Core profile.
The new reference tasks succeeded and their scopes, profile assignments and
revision IDs matched. No reference project reported a review hotspot.

| S8786 observations | Before | After | Reference |
|---|---:|---:|---:|
| vercel/ms: duration parser | 0 | 1 | 1 |
| sindresorhus/ky: source folder | 1 | 1 | 1 |
| date-fns/date-fns: parseISO implementation | 1 | 1 | 1 |
| formkit/tempo: ISO validator | 0 | 0 | 0 |
| denoland/std: media-type parser | 0 | 0 | 0 |
| developit/mitt and scopsy/await-to-js: source folders | 0 | 0 | 0 |

The two new negative controls contain anchored regexes with required delimiters
or bounded fields. The date-fns positive remained at line 115, UTF-16
offsets 12–24. The two native CLI builds returned identical complete reports
on all six unchanged scopes, under both `sonar-parity` and
`community-26.11-typescript-core`. On ms, both profiles gained just the
recorded finding; file and project measurements stayed unchanged.

Across all rules in these seven Core scans, 25 ordinary issues agree by key,
file, full primary range and message; two appear only natively and four only
in the reference. The three original discrepancies remaining after ms are in
Ky. The public native scans ran without TypeScript compiler context and two
reference scopes (Ky and date-fns) had unresolved extended tsconfigs. The
results apply to these file scopes; they do not certify CI-gate parity.

## Replay

Build the CLI and prepare clean, detached checkouts for the seven repository
names and commits in the receipt, using `OWNER-REPO` as the checkout name.
Run these commands from the HoonarQube root with Python 3.11 or newer:

```sh
cargo build --locked -p hoonarqube-cli
python3 tools/oracle/replay_typescript_core.py \
  --cli target/debug/hoonarqube --sources /absolute/path/to/checkouts
```

The default receipt is this seven-scope comparison. For the original four-scope
result, the older receipt path and CLI revision are documented separately.
