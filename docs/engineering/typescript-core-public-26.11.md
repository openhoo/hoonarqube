# TypeScript Community 26.11 Core: four public projects

These are the original #1031 results. For the current detector and three more
public controls see the [S8786 follow-up](typescript-s8786-26.11.md).

On November 23, 2026, Community Build `26.11.0.134175` indexed the 34
TypeScript source files below. Each private reference analysis used an unchanged
public Git checkout mounted read-only and a short-lived project token. We checked
the assigned built-in TypeScript profile and its 199 activation records before
and after each analysis. The compute tasks succeeded, the revisions matched the
analysis history, and the indexed paths and languages matched the source
inventory. The [receipt](../../tools/oracle/typescript-core-public-26.11.json)
identifies each commit, Git tree, numeric repository ID, file SHA-256, analysis
and compute task. The scanner image is pinned there; the server and analyzer
digests are in the [selection snapshot](../../catalog/reference/typescript-core-community-26.11.json).

| Repository | Analyzed scope | Files | Legacy findings | Core findings | Exact matches | Native only | Reference only |
|---|---|---:|---:|---:|---:|---:|---:|
| vercel/ms | `src/index.ts` | 1 | 17 | 2 | 2 | 0 | 1 |
| scopsy/await-to-js | `src` | 1 | 4 | 0 | 0 | 0 | 0 |
| developit/mitt | `src` | 1 | 22 | 2 | 2 | 0 | 0 |
| sindresorhus/ky | `source` | 31 | 423 | 2 | 1 | 1 | 2 |

The comparison counts ordinary issues with equal rule, relative file, full
UTF-16 primary range **and** message, preserving duplicates. The separate
hotspot API returned zero results for every project. Filtering removed 460
findings of inactive rules. The original and updated CLI returned identical
`sonar-parity` reports for these scopes. Both native profiles measured the
same files and project metrics. The reference and native results share five
findings across three rules; the quiet await-to-js result contributes no
positive detector evidence. The ms and await-to-js repository IDs were absent
from the previous 235-repository inventory.

## What differs

- In ms, only SonarQube reports `S8786` at `src/index.ts:78`. The same
  rule does match in Ky at `source/core/Ky.ts:252`. An active catalog key is
  not a promise that all its cases match.
- Only HoonarQube reports `S2245` for retry jitter at `source/core/Ky.ts:676`.
- Only SonarQube reports `S6544` at `source/core/Ky.ts:986` and `S7733` at
  `source/utils/body.ts:236`. The latter key is missing from the native catalog.
- The native public replay used no TypeScript compiler module; the legacy
  reports marked TypeScript context missing. The reference reported one
  unresolved extended TypeScript configuration in Ky. Shallow checkouts had
  no SCM blame. These are source-scope observations, not SCM/new-code gate
  comparisons or a performance benchmark.

The snapshot covers the default assigned profile, not custom profiles. The
`effective_rules_capture_sha256` for TypeScript is the SHA-256 of the
UTF-8 JSON object keyed by active rule, with sorted object keys, no spacing
or trailing newline. Each value contains its assigned `severity` and
`parameters` map. Project identifiers, timestamps and API response order do
not affect this digest. The scanner's selection digest covers the entire
embedded snapshot.

## Replay the pinned observations

Use Python 3.11+ and the original CLI from commit `aa740bc012f7934bed6b74f38361920d01a8727e`. In a new directory, prepare
one checkout per receipt row named `OWNER-REPO` (for example `vercel-ms`).
Check out its recorded commit detached. Do not install dependencies or generate
files inside these checkouts. Then run from the HoonarQube repository root:

```sh
python3 tools/oracle/replay_typescript_core.py \
  --receipt tools/oracle/typescript-core-public-26.11.json \
  --cli /absolute/path/to/original/hoonarqube --sources /absolute/path/to/checkouts
```

The replay checks the clean checkout, source hashes, file inventory, legacy
activation counts, compiler context, snapshot digest and both sets of findings.
A changed result prints the affected project and comparison. To collect a new
reference, apply the recorded scope as `sonar.sources`, pass the pinned commit
as `sonar.scm.revision` and use the scanner/server images in the receipt and
snapshot. Verify the assigned profile and parameters, completed analysis ID,
indexed TypeScript files, ordinary issues, and hotspots separately.

The mixed JS/TS CLI tests use TypeScript 6.0.3 when configured. They exercise
fallback selection, cache and baseline isolation. On the pinned ms file, a
native gate requiring exactly one measured file passed under `sonar-parity`
(actual 1, exit 0). The TypeScript Core profile returned `unavailable`
(actual null, exit 2). The local service independently evaluated both reports
against the assigned policy and returned the same decisions after a restart.
This checks how HoonarQube treats partial reports; the policy is a local file
count control, not the upstream default quality gate.
