# Python regex alternatives and boundaries (S6323, S5996)

An unquantified group can use an empty first or last alternative to make a match optional. Community 26.11 permits one such edge. An additional empty branch, or a quantified group, can still produce a finding. Its primary location is the pipe, including when the empty branch ends the pattern.

The previous implementation reported two extra findings in real packages: the optional empty branch in pipx's inline script metadata expression and the conditional expression used to render code blocks in readme_renderer. Both independent project scans were silent at those locations.

Run from the repository root:

```sh
cargo build --locked --release -p hoonarqube-cli
python3 tools/oracle/python_empty_alternatives/replay.py target/release/hoonarqube --output /tmp/regex-comparison.json
```

The replay fetches 16 public GitHub revisions, checks each tree and all 248 Python blob digests, and verifies the inventory covers the chosen package or module. It compares candidate S6323 findings against the separately captured Python Core issues from Community Build 26.11.0.134175. These scopes are negative controls for this rule. The independent 30-pattern reference probe also checks all 19 positive findings, including their exact primary ranges and messages. This directory contains the inputs, analysis IDs, observations and replay; repository code is read as data.

The optional output also lists results for other Python rules. Those differences are measured for diagnosis and do not imply full Core parity. This comparison does not execute the public projects' own tests or match analysis of their non-Python files.

## Boundaries and multiline flags

The inline script metadata pattern in pipx uses `re.VERBOSE | re.MULTILINE`, so `^` and `$` can match line boundaries. The old scanner diagnosed three impossible boundaries in this pattern. Community reports none. The replay checks S5996 and S6323 across the same 248 public source files.

Four independent Community Build 26.11.0.134175 analyses cover 134 additional regex calls. Their 75 boundary findings include required and optional input, the full range of absolute anchors, nested groups, both lookaround directions, inline flags and escaped literals. Each fixture has a hash; `boundaries/community.json` records its analysis ID, primary ranges and messages. These observations describe the analyzer. It can treat a trailing encoded character differently from the same literal character.

External flag recognition covers `re.M`, `re.MULTILINE` and their bitwise-OR combinations in the flags argument. Resolving arbitrary flag variables or imported aliases is outside this change.
