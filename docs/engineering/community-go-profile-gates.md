# Use Community 26.11 Go profiles in a quality gate

A Go-only project can count native findings using the active rules, scope and
parameters measured on Community Build **26.11.0.134175**. Select an overall
condition in a local quality gate or a project policy:

```json
{"schema_version":1,"conditions":[{"scope":"overall","metric":"community_26_11_go_extended_violations","operator":"lte","threshold":0}]}
```

```sh
hoonarqube analyze match.go --profile sonar-parity --quality-gate gate.json --json
```

| Metric | Active rules in the reference | Native gate behavior |
| --- | ---: | --- |
| `community_26_11_go_core_violations` | 6 | Counts the six active bug rules. |
| `community_26_11_go_extended_violations` | 9 | Includes the six core rules, empty functions, duplicate string literals (threshold 3) and cognitive complexity (threshold 15). |
| `community_26_11_go_comprehensive_violations` | 23 | Unavailable. The native profile lacks `go:S978`; thirteen other active rules have no qualified runtime evidence for this gate. |

The scanner still runs **native `sonar-parity`** and returns its full findings.
The gate selects findings from that report only if every active reference rule
has a qualified detector with the measured scope and effective runtime settings.
It does not configure the scanner or accept custom rules or parameter overrides.
Supply the selected Go source paths explicitly. Directory walks can skip file
types outside the native catalog and therefore cannot qualify this gate.
A mismatch, an old scanner without runtime evidence, an empty, mixed or
incomplete inventory, or a missing active key makes the metric unavailable.
Inspect the condition's diagnostic. A supported decision returns exit 0
(pass) or 1 (fail); an unavailable gate returns 2 with no numeric value.
These metrics cover overall violations; they do not use a baseline, SCM period,
coverage, hotspots, or new-code assignments.

For a server policy, put the same condition in the project's versioned gate
configuration. Upload the native JSON from a normal `hoonarqube analyze --json`
run. The service evaluates its assigned policy on ingestion; the upload does
not need a local gate result. A later assignment applies to a new analysis.
Historical decisions retain their policy version and result after a restart.
File caches are configuration-sensitive: changing the gate configuration
cannot reuse the previous decision. A separate optional generic parity
comparison completes before the gate or baseline is saved.

## Reference and replay

The [manifest](../../catalog/reference/community-26.11-go-profiles.json)
contains all 6, 9 and 23 active keys, scopes, parameters and source digests.
[Reference evidence](../../tools/oracle/fixtures/community-go-26.11/evidence.json)
records six successful Community analyses, including the project assignments
and analysis IDs. The same boundary source has two copies of one string and
three of another, and functions with complexity 15 and 16. Community Extended
and the native gate report only the third-copy threshold and complexity 16.
On `tidwall/match` at `afc69bce`, the single selected `match.go` file has zero
Core and three Extended findings in both tools. Community Comprehensive has
five, including two `go:S978` findings; the native gate declines to supply
a count. These examples establish agreement on the pinned sources and
parameters, not general behavioral equivalence.

```sh
python3 tools/oracle/community_go_profile_gates.py target/release
python3 tools/oracle/community_go_profiles_capture.py /path/to/community-26.11 > reconstructed.json
cmp reconstructed.json catalog/reference/community-26.11-go-profiles.json
```

The replay checks the source bytes, locations, messages, threshold boundaries,
nine positive/negative detector controls and test-source scope. It also checks
cache reuse, conflicting scanner parameters, unsupported profiles, server
reassignment, stored results and CI exits. Pass `--public-repo /path/to/match`
to use an existing local checkout containing the pinned Git objects.
