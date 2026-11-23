# Ruby S1192 on 49 public repositories

The candidate matches Community Build 26.9.0.129388 on all **120 findings and 440 supporting locations** for this rule. Both analyzers received the same 1,722 source files (1,717 Ruby) from 49 pinned repositories. Twenty-two projects contain a finding; 27 are silent. This is a source analysis, without an upstream package build.

| Compared against Community | Before | After |
| --- | ---: | ---: |
| Matching primary range and message | 109 | 120 |
| Additional / missing primary findings | 2 / 11 | 0 / 0 |
| Matching primary, message and complete flow structure | 0 | 120 |

For example, GitHub Linguist repeats six static pattern fragments inside a multiline regular expression. Ruby JSON, URI, ERB and PublicSuffix use escapes or interpolation that separated content in the native syntax tree. Conversely, matching only the beginning of a pattern caused extra findings in Psych and Benchmark. Previously the native scanner also grouped all subsequent occurrences in a single flow. Community emits a separate one-location flow for each duplicate. The other 1,660 findings and all per-file metrics in these scopes remained unchanged.

Six independent Community control scans cover 75 valid input files and 71 findings. They distinguish regex and command escapes, quoted values, interpolation, continuation lines, CRLF, custom delimiters and Unicode. The captured ranges for Ruby count code points, including on a line with a preceding emoji. The minimum literal length uses UTF-16 code units. A separate unterminated Ruby source file is checked for a native incomplete-scan error; it is excluded from the tally of matching inputs.

## Repeat the comparison

```sh
cargo build --release --locked -p hoonarqube-cli
python3 tools/oracle/ruby_duplicate_literals.py --binary target/release/hoonarqube
```

Every run includes the controls. Use `--case github-linguist-linguist` to select one public case or `--output result.json` for individual differences. For an offline replay, supply `--local-repositories FILE`: a JSON map of case names to repositories at the exact pinned commit. Each [public case](fixtures/ruby-s1192-public-20261122.json.gz) records its commit, tree, individual blob digests, Community analysis/task IDs, messages and supporting ranges. The [controls](fixtures/ruby-s1192-controls-20261122.json.gz) include their original source bytes as UTF-8 strings and reference identities. The comparison ignores the order between independent flows and preserves order and multiplicity within each flow.

These results cover the captured sources and the default threshold of three. They do not qualify every Ruby rule or every valid Ruby literal.
