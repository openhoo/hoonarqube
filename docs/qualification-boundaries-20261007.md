# Qualification boundaries and executable follow-up

This document distinguishes measured campaign acceptance from the historical
full-corpus and quick-fix qualifications. Old statuses identify work to repeat;
they do not qualify the current source or binary.

## Current Go secondary locations

The Go analyzer emits one supporting flow for each cognitive-complexity
contribution. Each contains the exact keyword/operator range and the increment
message, including nesting. Else-if chains attach their flat contribution to
`else`; ordinary control flow attaches to `if`, `for` or `switch`. Logical
operator runs and labeled jumps retain their original scoring semantics.

Fresh SonarQube 26.9.0.129388 scans of pinned Chi commit
`167e1e3bd039d060696b99c8da4e876ae04f42c1` yielded ten S3776 findings. The source
library probe and integrated CLI matched their primary ranges and messages and
all 129 supporting locations. This is a selected-rule result on pinned Chi.
The additional switch/jump control exposed an incorrect charge for `goto`;
the committed regression and repaired CLI now match both findings and all
18 supporting locations while labeled break/continue remain charged. The Chi receipt is
`tools/oracle/go-secondary-qualification-20261007.json`.

The comparator preserves finding/flow/location multiplicity. Distinct API flows
are unordered, while locations inside a flow remain ordered. Missing native
flows fail comparison against populated reference flows. It also rejects
incomplete native reports and locations outside the reference project.

```sh
python3 tools/oracle/secondary_locations.py \
  --native /absolute/complete-native-report.json \
  --reference /absolute/reference-issues.json \
  --project-key hq-parity-20261007-chi --rule go:S3776 \
  --output /absolute/secondary-comparison.json
```

## Finite historical inventory

Regenerate the explicit residual ledger with:

```sh
python3 tools/oracle/qualification_ledger.py \
  --output tools/oracle/remaining-qualification-ledger-20261007.json.gz
```

The ledger binds each input by SHA256 and retains each rule/application identity.
It contains 1,553 historical corpus rows that were not PASS, 275 quick-fix replay
applications, and 17 Enterprise sensor rules. Its acceptance conditions do not
promote an unavailable observation to equality.

The corpus contains deliberately malformed S2260 fixtures. Whole-project native
incompleteness contaminated other otherwise valid fixture observations. Keep the
malformed fixture's fail-closed contract, qualify independent valid fixtures in
explicit scopes, and retain source and semantic context. Removing malformed
files and renaming the old whole-project result as complete is invalid.

The quick-fix archive contains 181 historical passes, 26 safety refusals, 63
cases expecting no action, four withheld native actions and one reference
difference. Safety refusal and no action are separate outcomes. Reanalysis,
projection equality, actual written bytes and no-write negatives must be
repeated against the final binary. Existing portable archives embed replay
manifests and the black-box harness; verify every decoded file's SHA256 before
execution. A new replay must also check that expected detectors and safety
controls use the intended profile. Default-profile inactivity cannot prove that
a regression guard is broken, and a stale manifest projection cannot silently
replace an observed native edit.

## Licensed Enterprise applicability

The exact 17 C# keys are in the ledger. Historical ownership identifies the
`securitycsharpfrontend` server sensor and records local direct-analyzer execution
without licensed server-sensor execution. Community results and local analyzer
DLL execution cannot certify that sensor's findings or secondary locations.

Current Sonar documentation describes .NET scanning as begin/build/end, project
analysis tokens as requiring Execute Analysis, and Browse as necessary for
private project access. A licensed applicable server, captured effective profile,
scanner/build identity and raw sensor results are required. This document does
not infer license applicability merely from an analyzer DLL filename.

Documentation consulted through Context7:

- SonarQube Server: `analyzing-source-code/dotnet-environments/getting-started-with-net`
- SonarQube Server: `instance-administration/user-management/user-permissions`
- SonarQube Server: `user-guide/managing-tokens`

## Default CodeQL run

Run `37654570203`, source `369db7aa17fb16a4358ffe81323846519009449f`, completed
five language jobs. Its Rust job extracted 1,690 files and reached SARIF upload
before failing. The retained job logs and annotations do not establish an
analyzer implementation cause. The authenticated rerun-job endpoint returned
HTTP 403 with `Jobs in this workflow run cannot be re-run`. Replacing default
setup or suppressing the job would not qualify its upload. Acceptance requires
a fresh successful default-setup run, retaining the failure separately until
then.

## Fresh baseline quick-fix replay

`prepare_quickfix_replay.py` extracts every embedded manifest/harness only after
checking its decoded size and SHA256. Its optional `--typescript-6-config` mode
records a distinct migrated harness digest and explicitly acknowledges the
`baseUrl` deprecation inherited from the fixture tsconfig, using TypeScript 6's
`ignoreDeprecations: "6.0"`. Original files and failure receipts remain separate.
It does not change native analysis diagnostics or the apply regression gate.

```sh
python3 tools/oracle/prepare_quickfix_replay.py \
  --output /absolute/replay --typescript-6-config
```

Fresh replays of the baseline 0.11.0 binary, with the migrated fixture config,
covered 65 Python, 61 JavaScript and 89 TypeScript applications. The portable
receipt `tools/oracle/quickfix-baseline-qualification-20261007.json` lists the
exact failed application/action identities and result hashes. These are baseline
observations, requiring a new run against the final integrated release:

| Language | Applied passes | Safety refusals | No action expected | Withheld actions | Failed |
|---|---:|---:|---:|---:|---:|
| Python | 57 | 1 | 0 | 0 | 7 |
| JavaScript | 24 | 8 | 26 | 1 | 1 |
| TypeScript | 44 | 4 | 37 | 2 | 2 |

The JavaScript S2990 reference projection removes `this` but introduces S7764
(prefer `globalThis`). The independent apply gate refuses this cross-rule
regression. A refused write remains explicit; changing an expectation to a
success or weakening the gate would not repair the interaction. Python missing
detectors/safety controls need current profile checks, and TypeScript S2871 and
S4322 require detector/action classification checks.
