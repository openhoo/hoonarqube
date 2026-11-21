# Public project quality gates: November 20, 2026

SonarQube Community Build and Hoonarqube agreed on two overall duplication
gate decisions. Each engine evaluated both conditions on the same file paths
and bytes. The [capture](public-quality-gates-20261120.json) includes the Sonar
compute task and analysis IDs, the native gate reports and exit codes, and the
per-file SHA-256 hashes.

| Project | Byte-identical files | Duplicated lines | Density reported by Sonar / Hoonarqube | Sonar / Hoonarqube |
| --- | ---: | ---: | --- | --- |
| Picomatch | 6 | 0 | 0.0% / 0.0% | OK / pass (exit 0) |
| Yjs | 32 | 141 | 1.1% / 1.1000156030581993% | ERROR / fail (exit 1) |

The reference compute task reached `SUCCESS` in each case. The gate response
for each analysis ID had exactly the two configured conditions, with actual
values and `ignoredConditions: false`. Yjs's `ERROR` is a gate decision. Its
scanner also emitted a file encoding warning for the pinned `src/structs/Item.js`
with a literal U+FFFD character. The file remained unchanged and was included
in the matched file set. The two historical Sonar way analyses returned
`OK` with zero evaluated conditions; they are excluded from the comparison.
Their analysis IDs, gate assignments, profiles and the instance default gate
were unchanged on readback.

The density values have different precision. Both are on the same side of
the zero threshold in these cases. The runs cover two conditions on overall
JavaScript duplication, with both conditions passing or both failing. They do
not establish behavior at a rounding boundary, with mixed condition outcomes,
for new code, or for other metrics, languages, or editions.

## Missing data controls

- **SonarQube:** A third private project had the same custom gate and no
  analysis. The API returned `NONE` with an empty condition list, and the
  analysis search returned zero records.
- **Hoonarqube:** A full Picomatch scan used the same duplication conditions
  and an additional overall line coverage condition of at least 80%. With no
  coverage input, both duplication conditions passed, line coverage was
  `unavailable` with `actual: null`, and the CLI exited 2. The source analysis
  still reported `project.complete: true`.

These controls check different missing inputs. The reference control does
not measure Sonar's handling of an analyzed project without coverage.

## Reproduce

Use the pinned image digests, source trees, scan scopes and exclusions in the
capture. Create detached clean checkouts with line-ending conversion disabled
and check each `HEAD^{tree}` against the capture. Make the checkouts read-only
for both scans. The experiments use static analysis and do not install or
run the public projects' dependencies.

| Checkout | Commit | Source roots |
| --- | --- | --- |
| `micromatch/picomatch` | `9fab7bf61913ea334c4203ed321c426cfde44a42` | `index.js`, `lib` |
| `yjs/yjs` | `ee37f0a0e23a7c3e14531bae335d439e54c743e6` | `src` |

### SonarQube Community Build

Start an isolated Community Build 26.9.0.129388 instance from the captured
image and retain its built-in default quality profiles. The recorded run
used a dedicated internal Docker network and isolated storage for Sonar.
An earlier Yjs report was evaluated before its compute task failed to index
the result due to Elasticsearch's disk watermark. That failed task is not
one of the two decisions above.

On the isolated instance, use its Web API with authorized credentials:

1. Create a custom gate with `POST /api/qualitygates/create` (`name`).
   For this build, creation seeds new-code conditions. List them with
   `GET /api/qualitygates/show` (`name`) and remove those conditions from your
   new gate with `POST /api/qualitygates/delete_condition` (`id`).
2. Add `duplicated_lines` and `duplicated_lines_density` with
   `POST /api/qualitygates/create_condition`
   (`gateName`, `metric`, `op=GT`, `error=0`). Verify that these are the only
   two conditions and the gate is not the instance default.
3. Use `POST /api/projects/create` (`project`, `name`, `visibility=private`)
   to create three unused keys. Select the custom gate for each using
   `POST /api/qualitygates/select` (`gateName`, `projectKey`) and verify each
   with `GET /api/qualitygates/get_by_project` (`project`).
4. Before any scan on the control key, check
   `GET /api/qualitygates/project_status` (`projectKey`) and
   `GET /api/project_analyses/search` (`project`). Leave that key unscanned.

Export a scanner token as `SONAR_TOKEN` without putting its value in the
command line. Set `reference_network` to the isolated Docker network and
`reference_url` to the server URL reachable there. Set `picomatch` and `yjs`
to the absolute checkout paths, and `picomatch_key` and `yjs_key` to their new
project keys. Define this function in a Bash shell:

```bash
scanner_image='sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1@sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9'
exclusions='**/__tests__/**,**/__mocks__/**,**/__fixtures__/**,**/*.spec.*,**/*.test.*,**/*.bench.*'

scan_reference() {
  local checkout=$1 key=$2 pin=$3 roots=$4
  docker run --rm --platform linux/amd64 --network "$reference_network" \
    --cap-drop ALL --security-opt no-new-privileges --cpus 2 --memory 2500m \
    -e SONAR_TOKEN -e "SONAR_HOST_URL=$reference_url" \
    -v "$checkout:/usr/src:ro" "$scanner_image" \
    "-Dsonar.projectKey=$key" "-Dsonar.projectVersion=$pin" \
    -Dsonar.working.directory=/tmp/scanner-work -Dsonar.scm.disabled=true \
    -Dsonar.cpd.exclusions= -Dsonar.sourceEncoding=UTF-8 \
    "-Dsonar.sources=$roots" "-Dsonar.exclusions=$exclusions"
}
```

After running the replay command below, use the task ID printed by each
scanner. Poll `GET /api/ce/task` (`id`)
until `SUCCESS` and record its `analysisId`. Verify that the pinned project
version and analysis ID appear in `GET /api/project_analyses/search`. Fetch
`GET /api/qualitygates/project_status` by `analysisId`, and check the
condition values against `GET /api/measures/component` (`component`,
`metricKeys=files,duplicated_lines,duplicated_lines_density`). List all
source paths with `GET /api/components/tree` (`component`, `qualifiers=FIL`),
paging through every result. Compare their hashes from the clean read-only
checkout against the paths and hashes from the native report. Analysis and task
IDs are specific to each run.

### Hoonarqube

Use a release build from revision `b8411407357d1eabf8d2bce59035d7343996e6ec`
(`cargo +1.96.0 build --locked --release -p hoonarqube-cli --bin hoonarqube`). Set
`native_bin` to the absolute binary path. Store the following as a JSON file
outside both source checkouts and set `gate` to its absolute path:

```json
{
  "schema_version": 1,
  "conditions": [
    {"scope": "overall", "metric": "duplicated_lines", "operator": "lte", "threshold": 0},
    {"scope": "overall", "metric": "duplicated_lines_density", "operator": "lte", "threshold": 0}
  ]
}
```

Sonar's error predicate `GT 0` and Hoonarqube's acceptance predicate `lte 0`
give the same decision for the observed values. Make a second copy with this
additional condition and set `missing_coverage_gate` to that copy:

```json
{"scope": "overall", "metric": "line_coverage", "operator": "gte", "threshold": 80}
```

Set `out` to an absolute output directory outside both checkouts. Define the
native scan and run the two reference scans and three native scans with the
replay command:

```bash
scan_native() {
  local checkout=$1 config=$2 label=$3 expected=$4 status=0
  shift 4
  (
    cd "$checkout" && "$native_bin" analyze "$@" --format json \
      --profile sonar-parity --quality-gate "$config" \
      --exclude '**/__tests__/**' --exclude '**/__mocks__/**' \
      --exclude '**/__fixtures__/**' --exclude '**/*.spec.*' \
      --exclude '**/*.test.*' --exclude '**/*.bench.*'
  ) > "$out/$label.json" 2> "$out/$label.stderr" || status=$?
  printf '%s\t%s\n' "$label" "$status"
  [[ "$status" -eq "$expected" ]]
}

replay_public_quality_gates() {
  unset HOONARQUBE_TYPESCRIPT_PACKAGE NODE_PATH
  mkdir -p "$out" &&
    scan_reference "$picomatch" "$picomatch_key" 9fab7bf61913ea334c4203ed321c426cfde44a42 index.js,lib &&
    scan_reference "$yjs" "$yjs_key" ee37f0a0e23a7c3e14531bae335d439e54c743e6 src &&
    scan_native "$picomatch" "$gate" picomatch 0 index.js lib &&
    scan_native "$yjs" "$gate" yjs 1 src &&
    scan_native "$picomatch" "$missing_coverage_gate" picomatch-no-coverage 2 index.js lib
}

replay_public_quality_gates
```

Read `project.complete` and `assessment.gate` from each JSON report. The
capture hashes each original report for provenance; another build and scan
can produce a different raw hash. The canonical file-set hash uses UTF-8
compact JSON with sorted keys for the map from relative file path to SHA-256.
The recipe can be run independently of the automated corpus helpers from
the #960 stack.
