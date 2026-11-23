# Community 26.9: new violation gate with detector coverage

The optional `community_26_9_qualified_violations` condition counts new findings
classified by the built-in **Sonar way** profile on Community Build
**26.9.0.129388** as bugs, vulnerabilities or code smells. Use it with
`--profile sonar-parity`, a compatible baseline, and this quality gate:

```json
{"schema_version":1,"conditions":[{"scope":"new_code","metric":"community_26_9_qualified_violations","operator":"lte","threshold":0}]}
```

For every language in the scanned files, the evaluator checks every active
violation key from the [reference profile](../../catalog/reference/community-26.9-sonar-way-types.tsv).
A key needs membership in the frozen native profile **and** a row in the
[detector controls](../../catalog/reference/community-26.9-detector-controls.tsv).
Each row pins a positive source and a clean source by SHA-256. CI scans both and
requires the named finding only on the positive source. Both scanner contexts
must declare the exact manifest digest, and both native parity analyses must be
complete. Re-scan old baselines to use this condition.

Missing evidence gives `unavailable`, no numeric value, and exit **2**. The
diagnostic distinguishes active keys absent from the native profile from
declared keys without a verified control. With full coverage the condition
counts findings exactly like `community_26_9_violations`: a value over zero
fails this example (exit **1**); zero passes (exit **0**). The older mapped
condition, native conditions, hotspot reviews and assigned policies keep their
existing behavior. Projects opt in by selecting the new metric.

## What the real projects showed

Three adjacent revision pairs were scanned on the same isolated reference
server using a custom gate whose only failure condition was `new_violations >
0`. Each project used its built-in language profile, one unchanged upstream
source path, full Git history, and a specific baseline analysis. The baseline
and candidate analysis dates were their respective Git committer timestamps
plus one second. The [capture](community-qualified-violations-26.9.json) records
the server and scanner image digests, source and tree hashes, analysis IDs,
period timestamps, issue keys and reference responses.

| Public source, candidate | SCM lines in period | Community new issues | Mapped native | Strict native |
| --- | ---: | --- | --- | --- |
| [Yjs, IdSet.js](https://github.com/yjs/yjs/commit/a5e390160ca8686b9a54b3d924f37041e89407b3) | 5 | 1, ERROR: `javascript:S7724` on line 470 | 0, pass | unavailable; names `javascript:S7724` |
| [chi, client_ip.go](https://github.com/go-chi/chi/commit/7f9b7448f51d28804fac98c0a17bc2a7cec1079f) | 86 | 1, ERROR: `go:S3776` on line 121 | 1, fail | 1, fail; same rule and line |
| [chi, sunset.go](https://github.com/go-chi/chi/commit/fff8bb28cbeb658c3c916aff02a780b89532841e) | 19 | 0, OK | 0, pass | 0, pass |

The Yjs change adds an ESLint suppression without naming a rule. The pinned
native profile declares the TypeScript S7724 detector; it has no JavaScript
S7724 key. Matching rule numbers across languages does not qualify a detector.
The strict condition also blocks a mixed Go/JavaScript scan when only Go
changed. Ranges in the table are as reported by the analyzers.

Go and Rust currently have positive and clean controls for all 22 and 78
active violation keys respectively. Ruby has three controlled keys; the rest
of its scope remains unavailable. Other languages are unqualified by this
inventory. A missing control says nothing about whether an untested
implementation exists. A passing control establishes that a detector responds
to these examples; it cannot establish full recall, precision, parameter
equivalence, or parity for another profile or version. These public decisions
cover the named files and periods. They do not qualify the full default gate.

## Replay

Build the CLI and service, and supply full local clones of `yjs/yjs` and
`go-chi/chi` containing the pinned commits:

```sh
cargo build --locked -p hoonarqube-cli -p hoonarqube-service
python3 tools/oracle/community_detector_controls.py target/debug/hoonarqube
python3 tools/oracle/community_qualified_smoke.py target/debug
python3 tools/oracle/community_qualified_violations.py \
  --scanner target/debug/hoonarqube --service target/debug/hoonarqube-service \
  --yjs /path/to/yjs --chi /path/to/chi
```

To refresh the reference, use a separate Community project for each pair. Set
the recorded file as the only inclusion, the pinned revision as
`sonar.scm.revision`, and the recorded date as `sonar.projectDate`. On the
baseline, wait for a successful compute task and select its analysis ID as the
`SPECIFIC_ANALYSIS` period. After the candidate task succeeds, read
`qualitygates/project_status` by analysis ID, `issues/search` with
`inNewCodePeriod=true`, and the source file inventory. The Yjs scan used
`sonar.nodejs.executable=/usr/bin/node` in the scanner container.

The public replay checks the Git parent, tree and source digests before running
the native scanner on disposable clones. An assigned service policy evaluates
the submitted reports without using a precomputed gate. The test checks the
stored and reopened outcomes, CI exit codes, and the missing or mismatched
manifest on both the baseline and candidate. The service trusts its authorized
scanner to supply genuine source evidence; the manifest digest identifies the
controls claimed by that build and is not a cryptographic scanner attestation.
