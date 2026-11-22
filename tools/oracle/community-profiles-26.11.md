# Compare public sources against three Community 26.11 profiles

On Community Build 26.11.0.134175, a newly created Go project received **Sonar way core**, with six active Go rules. The same build also offered **extended** with nine and **comprehensive** with 23. A project on the older Community 26.9 server received the 22-rule **Sonar way** profile. These names and counts come from the running servers.

The [CI replay](community_profiles.py) scans 16 public repositories once per native build and checks the results against **48 distinct Community analyses**. Each repository was analyzed separately with all three profiles. The replay compares ordinary issue locations only when the rule and its declared parameters match. It rejects a new missing, additional, shifted or repeated primary location per profile and repository. A rule can be absent from a native implementation even if its key exists in the catalog. Those known gaps remain outside this comparison. The replay does not change the profile that the native scanner runs.

| Effective profile | Active Go / Python / JavaScript / TypeScript keys | Exact primary locations | Only native | Only Community |
| --- | --- | ---: | ---: | ---: |
| core (installation default) | 6 / 232 / 200 / 199 | 9 | 4 | 5 |
| extended | 9 / 266 / 252 / 252 | 136 | 10 | 12 |
| comprehensive | 23 / 407 / 425 / 440 | 323 | 37 | 28 |

The native baseline was the same release binary from commit `3f9c1a55` in every comparison. Both products indexed the same 104 source files with matching Git blobs and SHA-256 digests. On just these files the complete multisets of comparable reference locations, extra native reports and missing reports under 26.11 comprehensive matched those under 26.9 Sonar way. The profiles and their rules still differ. These are source-only scans; the counts do not establish agreement on upstream builds, all findings or CI gates.

We also submitted the remaining eight repositories from the 26.9 cohort. The pinned 26.11 Community image did not list Ruby or Rust in its languages or installed analyzers. All eight compute tasks succeeded, yet the reference returned no language-associated source files for their 92 source blobs. The fixture records these task and analysis IDs separately. Rules such as Ruby S1192 are therefore outside the 26.11 finding comparison. The existing [26.9 contract](public-locations-24.md) continues to cover those languages.

## Replay

From the repository root, with a built CLI and Git:

```sh
python3 tools/oracle/community_profiles.py target/release/hoonarqube
```

Add `--local-sources FILE` to use a JSON map from GitHub repository slug to an existing checkout containing the pinned commit. Without it the replay fetches the exact public Git objects. Repository scripts are never run.

The [fixture](fixtures/community-profiles-26.11.json.gz) records individual locations, original allowances, project IDs, source pins, analysis/task IDs and capture digests. Once the corresponding detector fix has landed, an exact allowance can be retired in a `community-profiles-26.11-resolved-*.json` file. The replay checks that every retirement names a captured location in the stated project and profile. This keeps the original measurement reproducible and makes a recurrence fail CI.

To regenerate the original fixture from an archived default capture and its `assigned-extended` and `assigned-comprehensive` subdirectories:

```sh
python3 tools/oracle/community_profiles_capture.py CAPTURE_ROOT SOURCE_MANIFEST OUTPUT.json.gz
```

The capture used the official Community image index `sha256:7b2296713a92b8ea0dd7a083a25faadc59376c9a1e6daf2744a89711c54ea1ba` on Linux arm64. The historical scanner image stayed fixed. Before and after each run, the collector checked the server build, installed analyzer versions and JAR digests, and all activated rules with their severity and parameters. Both non-default profiles were assigned and read back on fresh projects. The first probe using the removed hotspot search parameter failed to capture results and is excluded.
