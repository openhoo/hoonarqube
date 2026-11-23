# JavaScript Core on public source

The partial JavaScript Core scanner removed all 14 and 4 extra new findings on the two Commander comparisons. Both Community runs counted zero new issues. On five other pinned repositories, the scanner matched 14 of 17 Community findings by rule, file, complete primary range and message, reported 11 additional findings and missed 3. The two Commander observations do not establish detector parity.

| Public source | New to the recorded inventory | Community issues | Exact matches | Additional | Missing |
| --- | --- | ---: | ---: | ---: | ---: |
| npm/ini, `lib/ini.js` | No | 2 | 1 | 1 | 1 |
| debug-js/debug, `src/common.js` | Yes | 1 | 1 | 0 | 0 |
| jshttp/negotiator, `lib/mediaType.js` | Yes | 1 | 1 | 3 | 0 |
| caolan/async, `lib/auto.js` | Yes | 2 | 0 | 0 | 2 |
| feross/buffer, `index.js` | Yes | 11 | 11 | 7 | 0 |

The four new repositories were absent from the 276 distinct, case-insensitive repository names in the three prior inventories identified in [reference.json](reference.json). Each was a public, nonfork, unarchived GitHub repository when selected. Six repositories were screened using pinned source without running upstream code. Four single-file scopes were then submitted for independent Community analysis: three with potential native quality findings and one without any native Core candidate (async). These are purposefully selected controls. The fractions above describe these inputs only.

The two missed async issues are separate S2189 findings on line 226, with different spans and messages. On npm/ini the scanner retained S6959, missed S2871 and added S5850. All four new repos have positive Community controls, including async. [observed.json](observed.json) records every extra and missing primary location along with the measured scanner binary digest. The measured product head was `86071ab5b34d0cc964d38676f9ddf62f18af934c`. Among matching findings, the Sonar-format export also matched rule type, severity, software-quality impacts and clean-code attribute. Display titles and secondary locations are outside that comparison.

## Reference and coverage

The reference is SonarQube Community Build 26.11.0.134175, using JavaScript analyzer 14.3 (build 46350). The archive pins both container images and the analyzer JAR digest. The effective built-in default profile was **Sonar way core**, with 200 active keys and five rules with parameters. The fixture records names, scope, status, severity, type, impacts, clean-code attributes, inheritance, prioritization and effective parameter values. The freeze compares both independent Commander memberships (captured as one agreed membership), the earlier cohort's start/end effective rule responses, and the before/after responses for each new project. It checks that the same reference container and JAR remained in use. It also checks every field of the scanner activation file against independent reference data. The replay requires its digest in the scanner output and verifies that every parameterized rule is explicitly accounted for.

Commander contributes four successful compute tasks, in two separate projects, using two different baselines and one shared candidate revision. Each run indexed the seven JavaScript source files under `index.js` and `lib`. Only the two **candidate** analyses establish zero new findings. The replay verifies all four trees and file hashes, each selected baseline analysis ID and revision, and the existing broad/focused LCOV digests. It rebuilds each scanner baseline inside a disposable checkout. Legacy produced 14/4 new findings; every corresponding rule was inactive in Core. The partial Core scanner returned exit 2 and an unavailable gate both times, even though it reported zero new findings. The fixture does not claim a passing native default gate.

The four new controls bind the server's analysis history and scanner invocation to each explicit Git revision, project key and successful compute task. The earlier npm/ini capture disabled SCM on the reference side; its revision is bound by the verified checkout tree, blob inventory and indexed source hashes rather than an independent Community SCM revision. Every replay verifies Git trees and file bytes before invoking the scanner. The source scope is one file per control, not a whole-project scan with installed dependencies.

## Run the comparison

From the repository root:

```sh
python3 tools/oracle/js_core_2611/replay.py target/release/hoonarqube --mode legacy-audit
python3 tools/oracle/js_core_2611/replay.py target/release/hoonarqube --mode core-audit --output audit.json
python3 tools/oracle/js_core_2611/replay.py target/release/hoonarqube --mode core-guard --output ci.json
python3 tools/oracle/js_core_2611/replay.py target/release/hoonarqube --mode core-accept --output strict.json
```

`legacy-audit` uses `sonar-parity`, checks the unfiltered Commander counts, and projects its control output onto the active reference keys for diagnostic comparison. `core-audit` runs the actual `community-26.11-javascript-core` scanner and records all discrepancies without filtering the product's results. Both check the same physical source pins and report bindings. `core-guard` compares the exact remaining differences with the measured ones; it permits improvements and fails if a previously matched finding disappears, a new finding is added without reference evidence, or export metadata changes. `core-accept` additionally fails for extra or missing findings or differing export metadata; it **fails on the measured scanner**. It tests this explicitly partial selection and cannot certify complete language coverage. These scripts do not change production scanner or gate policy.

All modes use temporary checkouts and never run upstream package scripts. They fetch pinned public Git objects directly unless `--mirrors mirrors.json` supplies a complete local Git mirror for each repository. Commander requires the three revisions and the history connecting each baseline to the candidate. The recorder regenerates the frozen reference from independent archived responses:

```sh
python3 tools/oracle/js_core_2611/freeze.py \
  --cohort /path/to/community-26.11 --commander /path/to/default-gate-commander \
  --captures /path/to/js-core-captures --screened /path/to/screened.json \
  --history /path/to/public-cohort-24 \
  --selection /path/to/catalog/reference/javascript-core-community-26.11.json \
  --output regenerated.json
cmp regenerated.json tools/oracle/js_core_2611/reference.json
```
