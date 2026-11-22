# Ruby S1186: empty methods on public source

The candidate matched all 140 Community findings across 45 pinned public GitHub repositories. Each match requires the same file, start and end line, both UTF-16 offsets and the complete issue message. All selected files were analyzed. The comparison is for S1186; it does not establish parity for other rules, languages, hot spots or runtime performance.

| Scope | Projects | Source files | Ruby files | Projects with findings | Matching findings | Native only | Reference only |
|---|---:|---:|---:|---:|---:|---:|---:|
| Prior public captures | 33 | 1,226 | 1,221 | 15 | 124 | 0 | 0 |
| Additional, independently scanned projects | 12 | 449 | 449 | 5 | 16 | 0 | 0 |
| Total | 45 | 1,675 | 1,670 | 20 | 140 | 0 | 0 |

The 33 earlier cases reuse the original CE analysis and file hashes from the November public corpus. The other 12 projects were selected by name before collecting their results. Every regular Ruby file under `lib/` in those 12 Git revisions was sent to an isolated SonarQube Community Build **26.9.0.129388** with S1186 active in the Ruby Sonar way profile. On both cohorts the staged bytes, paths and project revision were checked. Repository code was not run. This is a mixture of library directories and smaller scopes, not 45 complete applications.

| Additional project | Pinned commit | Ruby files | S1186 |
|---|---|---:|---:|
| ruby/logger | `fc3aa2dc706d` | 7 | 0 |
| ruby/erb | `944c1923898f` | 5 | 1 |
| ruby/benchmark | `8fb5f745853c` | 1 | 0 |
| rails/globalid | `01a1a1cf9bab` | 11 | 0 |
| ruby-i18n/i18n | `a0a416e570fd` | 46 | 0 |
| mperham/connection_pool | `fef7eab683a8` | 5 | 0 |
| puma/puma | `596151f3fb0d` | 44 | 8 |
| collectiveidea/delayed_job | `1e116deafef0` | 24 | 3 |
| rails/rails-html-sanitizer | `33590fc359d8` | 4 | 0 |
| simplecov-ruby/simplecov | `1d528ebc20d5` | 200 | 2 |
| dry-rb/dry-monads | `11b865d437c5` | 29 | 0 |
| ruby/irb | `a21604dda83c` | 73 | 2 |

## Before and after

The d184370f CLI missed all 140 findings and could not complete `dry-rb/dry-monads`: its parser rejected the command in `def value! = raise UnwrapError, self`. MRI 4.0.10 accepted the pinned source with `ruby -c`. The candidate analyzes all 29 files in that case and correctly reports zero S1186 findings. Comparing the syntax trees for all 1,670 Ruby files, only `right_biased.rb` changed. On the 45 inputs, every emitted issue for rules other than S1186 was unchanged, including ranges and messages.

Four separate synthetic Community analyses (excluded from all public totals) check constructors, operators, singleton and wrapped methods, endless definitions, nested and trailing comments, positional arguments, Unicode and empty separators. The expected line sets are in the Ruby rule's tests. A trailing comment on the method's closing line suppresses a finding only when the reference regards it as part of the enclosing expression. Do not generalize the result to arbitrary Ruby inputs.

| Control | Community analysis UUID | Findings |
|---|---|---:|
| ruby-syntax-control | `74fc3d1e-8513-49f5-b259-cb28c00ae5f8` | 7 |
| ruby-context-control | `295c2a3b-2340-44c2-a4a5-eef5770d8858` | 7 |
| ruby-parent-control | `17fbfe30-917f-449b-94fa-a15cc8457288` | 7 |
| ruby-scope-control | `480618f6-941b-49f8-9818-888551169f57` | 5 |

## Replay

From the repository root:

```sh
cargo build --release --locked -p hoonarqube-cli
python3 tools/oracle/ruby_empty_methods.py --binary target/release/hoonarqube --output /tmp/ruby-s1186.json
```

The [compressed reference manifest](fixtures/ruby-s1186-public-20261122.json.gz) contains all 45 immutable commits and trees, per-file SHA-256, captured primary locations and messages, CE and analysis IDs, and reference response hashes. The replay reads regular Git blobs without running checkout hooks, filters, submodules or project scripts. It fails on incomplete scans, scope changes, invalid coordinates, missing or additional findings. Use repeated `--case` arguments to run a subset. The pull request workflow exercises Rack and Puma (48 findings total), Ruby Logger (silent) and dry-monads (silent, previously incomplete).
