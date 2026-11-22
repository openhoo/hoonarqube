# Hotspot review on a public change

Redux commit `e6f6c7da7b39ed46273d05d150cf1f578973ac3c` introduced two calls reported by Hoonarqube's native `javascript:S2245` at lines 8 and 9 of `src/utils/actionTypes.js`. The test scans that one unmodified file at the commit and its direct parent. It never runs the upstream project.

Run `community_hotspot_replay.py --scanner SCANNER --service SERVICE --base BASE_CHECKOUT --head HEAD_CHECKOUT --output RESULTS`. It verifies Git parents, source and binary hashes, scanner exit codes and actual HTTP responses. The [recorded run](community-hotspot-native-redux.json) reached 0%, 50%, 100%, survived a service restart, and fell to 50% after reopening. The unchanged revision has a complete empty hotspot population: the condition has no value and passes the aggregate gate. A missing baseline is unavailable (CLI exit 2).

Authorized scanner and admin submissions can provide a baseline classification. The service validates its context and current finding inventory; it does not rescan the historical source. Reviews must come from a permitted service account. `GET /api/v1/projects/{project}/analyses/{id}/gate` computes the current gate; the original analysis retains the submitted gate. Existing databases retain previously stored ambiguity flags; a new analysis uses exact issue ranges and distinct assessment identities. Restore accepts the older, stricter flags only when consistent with the prior duplicate algorithm.

These are native results. Community Build 26.9.0.129388 classifies the active S2245 as a vulnerability. The Redux review sequence is not a reference gate or reference review sequence.

## Community Build 26.9.0.129388: type mapping and live comparison

Use the versioned new-code metrics `community_26_9_violations` and `community_26_9_security_hotspots_reviewed` only to apply the captured built-in **Sonar way** rule membership and types to Hoonarqube's own new findings. They do not change which source lines or findings Hoonarqube considers new. Other profiles and builds need their own verified mapping.

The [type map](../../catalog/reference/community-26.9-sonar-way-types.tsv) covers the eight languages in the native catalog. Each row is an active reference rule with its actual type, or a frozen native rule absent from that complete active export (`NOT_ACTIVE`). A key absent from both sets is unknown. An active reference key outside the native catalog has no implied native detector. In the JS, TS, Python and C# profiles respectively, 42, 42, 35 and 21 native hotspot keys have a different active reference type. None of the eight captured profiles has an active hotspot. The evaluator requires a complete new-code baseline, the identified source catalog, the native sonar-parity profile and its declared rule membership for the scanned languages. Unsupported languages, missing inputs and unknown finding types cannot prove an empty population.

The deterministic audit joins complete rule metadata pages to an independent export with the exact profile activation for each rule. It checks all pages, duplicate keys, languages, profile totals, and types. The [input manifest](../../catalog/reference/community-26.9-sonar-way-inputs.json) lists SHA-256s for both sets of pages, the reference environment, profiles and source catalog. Reproduce the files with:

```sh
python3 tools/oracle/community_rule_types.py --capture METADATA_DIR --effective ACTIVATION_DIR \
  --environment REFERENCE_ENVIRONMENT_JSON --output RESULT_DIR
```

The [live Community receipt](community-hotspot-reference-redux.json) contains the two successful CE task and analysis IDs, source revisions, assigned new-code period, gate, measures and raw response hashes. The candidate indexed one JavaScript file. Both S2245 occurrences were present as vulnerabilities with a creation date of November 16, 2017. The reference project reported four total issues, zero new issues, zero new lines and zero hotspots. Its gate returned **OK** with one evaluated condition: `new_violations = 0`. It omitted the reviewed-hotspot percentage. Hoonarqube applies its revision diff to the same source: the 26.9 aliases count the two active vulnerabilities as new and return no reviewed-hotspot value. **The rule classification agrees; the new-issue gate decisions differ.**

`community_hotspot_replay.py --mapped` adds the versioned CLI and service comparison to the native lifecycle. To read current Community evidence again, use a read-only token file, the dedicated Redux project, and the recorded base and candidate CE task IDs:

```sh
python3 tools/oracle/community_hotspot_reference.py --url "$SONAR_HOST_URL" \
  --project hq-community-269-redux-hotspots-live-20261122 --branch main \
  --base-task 754fdca0-8735-4a1b-9da3-d8979c19bb4b --task 53448538-f8bd-4ed5-b589-9c80fd5bb0cc \
  --server-version 26.9.0.129388 --token-file TOKEN_FILE --output RAW_DIR
```

Use `--container NAME` instead of `--url` for an isolated container with no host port. The verifier refuses to attach current inventories to a superseded analysis and checks that neither revision changed during readback. The base analysis evaluated zero conditions; it supplies a baseline, not evidence for a passing reference gate.
