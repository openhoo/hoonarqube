# Pinned public source contracts

The candidate CLI must reproduce **214 SonarQube primary locations** on 309 pinned files from 25 public repositories. The contracts cover 91 project/rule pairs and 58 distinct rule keys. Each pair has at least one real Sonar issue with a text range, equal declared rule parameters, and no missing or extra occurrence in the qualifying native scan.

| Language | Repositories | Files | Primary locations |
| --- | ---: | ---: | ---: |
| Go | 4 | 35 | 31 |
| Java | 4 | 86 | 26 |
| JavaScript | 4 | 21 | 83 |
| Python | 4 | 14 | 20 |
| Ruby | 3 | 66 | 14 |
| Rust | 4 | 64 | 14 |
| TypeScript | 2 | 23 | 26 |

The language groups describe project scopes. The Java total includes the HTML source document indexed in Commons CLI. All four Rust contracts exercise the cognitive-complexity rule; the number of projects does not imply broader Rust rule coverage.

## Run the gate

From the HoonarQube repository, build the same release profile used to qualify the contracts. The runner allows 120 seconds per project's analysis:

```sh
cargo build --locked --release -p hoonarqube-cli
python3 tools/oracle/public_contract.py --binary target/release/hoonarqube
```

Use `--project commander` to replay one repository. For an offline replay, add `--local-sources checkouts.json`, a JSON object mapping GitHub names such as `tj/commander.js` to local checkout paths at exactly the pinned commit. The workflow runs on pull requests and pushes to main; it can also be started manually. Network failures fail the job.

[The manifest](public_contract.json) records the public repository, full commit and Git tree, original scan roots and exclusions, path and SHA-256 of every indexed source file, declared rule parameters, and expected locations. Each location is `[rule, path, start line, start UTF-16 offset, end line, end UTF-16 offset]`. Lines are one-based and offsets are zero-based. The comparison preserves duplicate occurrences. A missing file, incomplete parse, changed semantic context, changed parameter, or additional/missing/shifted occurrence for a contracted rule fails the check.

CI fetches Git objects into a bare repository. Only recorded regular source blobs with matching hashes are copied to an empty temporary directory; executable permissions are discarded. The candidate CLI runs with an empty executable search path. CI does not check out upstream build scripts, compile the public projects, install their dependencies, use Docker, or connect to a live SonarQube server. The captured Java reference used the recorded release and class-context hash; the native replay does not build or load those classes. The JS/TS native baseline has no TypeScript compiler context.

## Evidence and limits

The reference is SonarQube Community Build **26.9.0.129388**, captured on November 20, 2026. The manifest records each successful compute task and analysis ID, scanner log digest, reference issue digest, and the native report digest for the qualifying build. Its native commit, tree, and executable digest identify the measured baseline; CI builds and tests the candidate under review.

The selection is deliberately biased toward inexpensive, already matching regressions. We selected 25 distinct repositories from three capture campaigns, with at most 35 indexed files per scope. Within those scopes the manifest retains every eligible rule with matching text locations and multiplicity. Project-level issues, file-level-only or unranged findings, security hotspots, documented gaps, parameter mismatches, and rules with known differences do not qualify. JS/TS requires a unique completed language-sensor block with a count equal to the full index and no ambiguous generated-bundle notice. An index alone does not prove a sensor analyzed every file. These results cover only the selected revisions, source files, rule parameters and primary locations. They do not establish project-wide accuracy, semantic parity, message equality, or general sensor coverage.

To regenerate the manifest, supply the original reference archives (campaign directories `corpus`, `wave2`, `wave3`), the matching final native replay directories, and the retained, verified analyzer and receipt:

```sh
python3 tools/oracle/public_contract_capture.py \
  --captures /path/to/campaigns --qualified /path/to/measured-final \
  --retained /path/to/retained-final --check
```

The generator checks the retained binary and replay digests, completed reference tasks, raw issue pages, matching indexed source bytes, effective profiles and native reports. Remove `--check` only to write a reviewed replacement baseline. A failing candidate is not evidence to update expected locations. For corpus-wide findings and known differences, see the [initial](public-corpus-20261120.md), [second](public-corpus-wave2-20261120.md) and [third](public-corpus-wave3-20261120.md) campaign reports.
