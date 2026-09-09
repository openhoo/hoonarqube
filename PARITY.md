# SonarQube Parity Contract and Evidence

## Claim boundary

Hoonarqube ships the frozen 1,741-rule catalog:

- C#: 467.
- JavaScript: 406.
- TypeScript: 412.
- Python: 335.
- Go: 36.
- Rust: 85.

The separate 47-rule `hoonarqube-*` native catalog is excluded from every
Sonar parity count and oracle claim. Native rules carry their own upstream
provenance and profile membership; enabling them cannot turn local evidence
into a SonarQube-equivalence claim.

Seventeen C# rules are owned by SonarQube's Enterprise analyzer. Hoonarqube
keeps their implementations, fixtures, and local tests, but the Community
oracle cannot certify their upstream behavior. These rules carry the explicit
`enterprise-unverified` classification. They must pass local bad/good controls,
but routine Community gates report them separately instead of requiring a
commercial license. They are never counted as Community passes.

The remaining rule records carry `community-base`. Development and Community
oracle runs need no commercial license. Full SonarQube parity cannot be claimed
without valid Enterprise oracle evidence for the 17 commercial rules.

## Project-measurement scope

Rule parity and project-measurement parity are separate contracts. The
versioned project report provides source size, scope/completeness, and
within-/cross-file duplication for Python, JavaScript, TypeScript, C#, Go,
Java, Rust, and Ruby. Java/Ruby measurement support does not add either
language to the frozen Sonar rule catalog.

The native duplication defaults resemble SonarQube's documented thresholds:
100 normalized syntax tokens across 10 physical lines for non-Java input,
and 10 statement units for Java. This is not equivalent to an oracle pass.
Structural tokens, normalized literal kinds, Java declaration/control units
and nested statement streams, comment-only line accounting, and exclusion
denominators have explicit native semantics. Exact SonarQube metric values,
block grouping, and all-language lexical equivalence remain unverified.

Clone occurrences use inclusive line ranges and half-open UTF-8 byte offsets.
Line totals union overlaps; block totals identify distinct byte spans.
Incomplete analysis has no duplication aggregate, and empty density
denominators are null. Generic Issue Import, SARIF, and GitLab Code Quality
exports continue to carry issues only, not duplication measures.

Coverage import, new-code baselines, metric-based quality gates, issue/hotspot
review state, a persistent analysis service, and a dashboard are not included
in this measurement milestone.

Project measurement itself is controlled by `--exclude`, `--test-include`,
`--generated-include`, `--vendor-include`, `--duplication-exclude`, and the
`--duplication-min-tokens`, `--duplication-min-lines`, and
`--duplication-min-statements` thresholds. `--cache-dir` is a separate
opt-in per-file cache and does not change this semantic boundary.

## Focused evidence — 2026-09-09 (not whole-corpus parity)

The repository manifests below preserve focused reference captures and
worktree qualification state. They do not replace the historical whole-corpus
baseline or establish release-binary parity. Temporary filesystem paths are
intentionally omitted, and blocked or pending drafts are not final evidence.

### Opt-in semantic context boundary

The ordinary `analyze` route is native and syntax-oriented; it does not retain
source snapshots or load compiler contexts. Current project-context options
are `--typescript-project` (optionally `--typescript-module`),
`--csharp-project`, `--allow-project-build`, and `--python-project`.
Semantic options opt into the bounded source-snapshot path. Assessment,
coverage, baseline, and quality-gate options use that same retained-source
path for their artifacts but do not themselves establish semantic parity.
`--allow-project-build` is a C# trust gate for a supplied project; it is not a
standalone analyzer switch.

Explicitly requested contexts are loaded for JavaScript/TypeScript, C#, and
Python. Missing files, runtimes, helpers, references, compiler diagnostics, or
incomplete owner contexts remain diagnostics and make the context incomplete;
they must never become a successful zero-finding semantic result. Razor is
registered with the C# family, but ordinary native dispatch rejects `.razor`;
trusted compiler-generated and mapped facts require a complete C# project
context.

### Current configured worktree qualifications

- The configured C# proof establishes exactly 21 canonical target findings
  (`reference=21`, `native=21`). All other context findings remain retained in
  the comparison/report but are outside that target-only exactness claim. The
  portable reference manifest is
  [`tools/oracle/roadmap-focused-reference-20260909.json`](tools/oracle/roadmap-focused-reference-20260909.json).
- The configured issue36 JavaScript/TypeScript proof covers six cases and 30
  exact target findings in total, including one whitelist finding. This is
  worktree qualification, not final published-binary evidence. Its portable
  reference manifest is
  [`tools/oracle/roadmap-jsts-python-reference-20260909.json`](tools/oracle/roadmap-jsts-python-reference-20260909.json).
- Valid JSX reserved-attribute syntax and valid C# contextual-keyword
  identifiers named `async`/`await` remain `SourceFacts` limitations. Missing
  or incomplete facts stay non-pass evidence; they are not safe negatives.
- C# `S3005` and `S3169` diagnostics may lack a quick-fix attachment; that gap
  remains unfixed. The exact `S1116` reference edit is correctly refused when
  its projected result introduces `S1186`; that refusal is not completed fix
  parity.

Full-corpus comparisons intentionally include malformed-input rows. An
incomplete malformed-input result remains fail-closed and non-pass (normally
with exit `2`); it is never counted as a clean or exact parity result.
Reference captures and their recorded identities remain unchanged. The
security wrapper
[`tools/oracle/security-qualification-20260909.json`](tools/oracle/security-qualification-20260909.json)
remains `SECURITY_PARITY_UNVERIFIED` and explicitly preserves Enterprise,
flow, and secondary-location `UNVERIFIED` states. Its recorded native identity
`444c56f682998e7e638bd230104bfa1a3628cf57` is historical implementation
evidence only, not the current checkout `HEAD` or a release identity.

These focused results prove only the listed contexts and fixtures. They do not
equate native syntax support, compiler-context support, or a target-only
finding comparison with whole-corpus SonarQube parity.

### Native project metrics versus the captured Sonar reference

`tools/oracle/fixtures/metrics/corpus.json` defines seven aggregate metrics:
`lines`, `ncloc`, `comment_lines`, `duplicated_lines`,
`duplicated_blocks`, `duplicated_files`, and `duplicated_lines_density`.
The corrected comparison uses the captured SonarQube 26.8.0.126808 reference
in `tools/oracle/metrics-reference-20260909.json`. Cells below are
`native/reference` project aggregate values; `=` is an `EXACT` comparison and
`≠` is `DIFFERENT`. This is an explicit difference table, not a similarity
score.

[`tools/oracle/metrics-qualification-20260909.json`](tools/oracle/metrics-qualification-20260909.json)
publishes all 17 executed scenarios: 16 exit `0` and one intentional
malformed-input case exits `2`. The malformed row is deliberately included in
the full scenario comparison, remains incomplete/non-pass, and is never treated
as a clean or exact parity result. Every row records uncached/cold/warm byte
equality. It includes portable replay commands, input/capture hashes,
per-file and project comparisons, and explicit unavailable provenance.
The historical native commit and executable hash were not recorded and are
not inferred from the current checkout. Native determinism is not reference
parity: 15 scenarios are `DIFFERENT` and two remain `UNVERIFIED`.

| case (language) | lines | ncloc | comment_lines | duplicated_lines | duplicated_blocks | duplicated_files | duplicated_lines_density |
|---|---:|---:|---:|---:|---:|---:|---:|
| `baseline-python` (python) | 140/147 ≠ | 133/133 = | 7/9 ≠ | 64/62 ≠ | 2/2 = | 2/2 = | 84.21052631578947/42.2 ≠ |
| `baseline-javascript` (javascript) | 146/153 ≠ | 139/139 = | 7/4 ≠ | 66/64 ≠ | 2/2 = | 2/2 = | 82.5/41.8 ≠ |
| `baseline-typescript` (typescript) | 146/153 ≠ | 139/139 = | 7/4 ≠ | 66/64 ≠ | 2/2 = | 2/2 = | 82.5/41.8 ≠ |
| `baseline-csharp` (csharp) | 177/188 ≠ | 170/172 ≠ | 7/4 ≠ | 72/72 = | 2/2 = | 2/2 = | 71.28712871287128/38.3 ≠ |
| `baseline-go` (go) | 160/167 ≠ | 146/146 = | 7/9 ≠ | 66/64 ≠ | 2/2 = | 2/2 = | 73.33333333333333/38.3 ≠ |
| `baseline-java` (java) | 156/163 ≠ | 151/151 = | 5/4 ≠ | 62/64 ≠ | 2/2 = | 2/2 = | 72.09302325581395/39.3 ≠ |
| `baseline-rust` (rust) | 152/159 ≠ | 145/145 = | 7/10 ≠ | 66/64 ≠ | 2/2 = | 2/2 = | 78.57142857142857/40.3 ≠ |
| `baseline-ruby` (ruby) | 146/153 ≠ | 139/139 = | 7/4 ≠ | 66/64 ≠ | 2/2 = | 2/2 = | 82.5/41.8 ≠ |
| `threshold-python-99` (python) | 40/42 ≠ | 40/40 = | 0/0 = | 40/40 = | 2/2 = | 2/2 = | 100.0/95.2 ≠ |
| `threshold-python-100` (python) | 40/42 ≠ | 40/40 = | 0/0 = | 40/40 = | 2/2 = | 2/2 = | 100.0/95.2 ≠ |
| `threshold-python-101` (python) | 40/42 ≠ | 40/40 = | 0/0 = | 40/40 = | 2/2 = | 2/2 = | 100.0/95.2 ≠ |
| `java-statements-9` (java) | 20/22 ≠ | 20/20 = | 0/0 = | 0/18 ≠ | 0/2 ≠ | 0/2 ≠ | 0.0/81.8 ≠ |
| `java-statements-10` (java) | 22/24 ≠ | 22/22 = | 0/0 = | 20/20 = | 2/2 = | 2/2 = | 90.9090909090909/83.3 ≠ |
| `java-statements-11` (java) | 24/26 ≠ | 24/24 = | 0/0 = | 22/22 = | 2/2 = | 2/2 = | 91.66666666666666/84.6 ≠ |
| `java-structure-ranges` (java) | 67/73 ≠ | 67/67 = | 0/0 = | 50/52 ≠ | 6/8 ≠ | 6/6 = | 74.6268656716418/71.2 ≠ |

The complete comparison rows show `lines` and density differing in every
case; C# also differs on `ncloc`, and the Java nine-statement boundary differs
on every duplication aggregate. Duplication occurrence identity remains
`UNVERIFIED` because the Sonar API exposes line ranges while native reports
half-open UTF-8 byte offsets.

Unavailable or deliberately unverified reference cases are separate from the
table:

- `no-denominator-empty` has native zero size counters while the reference
  marks those size metrics absent; both sides have zero duplication counters
  and no density denominator. Its absent-reference comparisons are
  `UNVERIFIED`, not equality.
- `invalid-input-unverified` exits `2` with an incomplete native report while
  the reference state is `UNVERIFIED`; all seven metric comparisons remain
  unverified. Malformed-input recovery is not represented as complete parity.
- `unsupported-kotlin` and `unsupported-php` are reference-only manifest
  cases. Sonar has analyzers for them, but the native language registry does
  not; every metric is `UNVERIFIED` and no equality is claimed.

### Captured CSS/HTML/Docker inventory versus native support

`catalog/reference/issue-52-language-inventory.json` captures CSS, HTML/Web,
and Docker reference/profile observations, but its implementation matrix
marks each as `missing/planned only`, `local_dispatch_supported=false`, and
measurement support is not in the current eight-language native dispatch. The
planned package matrices do not add rules to the frozen catalog. Reference
server/profile counts are observations, not shipped detector counts, and
embedded HTML JavaScript behavior remains reference-only.

For provenance, the Community 26.8.0.126808 capture (image
`sha256:9026624a61cd25542a402a9e7213dd7dbb39724ac9597e331e6b85362558c079`)
records these default Sonar Way profile observations:

| reference language | active default profile | all server rules | profile key |
|---|---:|---:|---|
| CSS | 40 | 43 | `9ec5a3be-d6b6-40e2-81ef-99285a7cb0c9` |
| Web/HTML | 61 | 104 | `f222b12d-0a35-4dac-9327-6e40c54fb0ad` |
| Docker | 25 | 28 | `83c3ad5e-5f4c-48e6-acf8-0225808e4a92` |

These active/all values are server inventory only. They are distinct from
the planned local implementation-matrix records, which remain unimplemented
and do not imply native dispatch.

Native directory inventory behavior is part of the current CLI contract:
recognized unsupported names and suffixes (`style.CSS`, `style.css`,
`index.HTML`, `index.html`, `Dockerfile`, and `dockerfile`) appear as
`classification=excluded`, `status=unsupported` inventory entries with no file
metrics or duplication. The ordinary `main.py` measurement remains
`files=1`, `lines=1`, `code_lines=1`, `comment_lines=0`, zero duplication, and
`complete=true`. An explicitly supplied unsupported file remains
`classification=source`, `status=unsupported`, with no metrics or duplication,
`complete=false`, and exit `2`. This inventory behavior does not provide CSS,
HTML, or Docker syntax support.

Native metric support, native language syntax support, Sonar server reference
evidence, and optional IDE actions are separate contracts. Java and Ruby add
measurement support only; they do not add frozen Sonar rule families.
Reference plugins or profiles do not create local analyzers. Optional rule
quick fixes are tracked in `QUICKFIX.md`, not inferred from semantic-context
or metric evidence.

### Evidence publication status

Portable repository-relative manifests preserve the captured inputs and
qualification boundaries:

- [`tools/oracle/roadmap-focused-reference-20260909.json`](tools/oracle/roadmap-focused-reference-20260909.json)
  preserves the C# reference corpus and marks native qualification as pending.
- [`tools/oracle/roadmap-jsts-python-reference-20260909.json`](tools/oracle/roadmap-jsts-python-reference-20260909.json)
  preserves the focused JavaScript/TypeScript reference cases and pending
  native replay contract.
- [`tools/oracle/security-qualification-20260909.json`](tools/oracle/security-qualification-20260909.json)
  preserves the security wrapper's explicit unverified boundaries.
- [`tools/oracle/metrics-qualification-20260909.json`](tools/oracle/metrics-qualification-20260909.json)
  records the native metric comparison and its incomplete malformed-input row.

The configured C# and JavaScript/TypeScript results described above remain
worktree qualification, not final published-binary evidence. Captured JSON
findings, source hashes, and reference identities are not rewritten, and no
pending or blocked draft is represented as a final release result.


## GitLab Code Quality scope

`analyze --format gitlab-codequality` emits GitLab's single-array Code Quality
contract for the default `sonar-parity` profile and cumulative native profiles.
Each finding carries its message as `description`, its rule key as `check_name`,
a stable SHA-256 `fingerprint`, a lowercase GitLab severity, and a
repository-relative `location.path` with inclusive positive `lines.begin` and
`lines.end`. The fingerprint uses length-delimited normalized primary path, rule
key, message, and primary range only; nested flow/fix metadata does not change
identity. Paths are raw POSIX-style checkout paths without a `./` prefix;
ordinary colon filename components are preserved, while drive- and URI-like
prefixes, backslashes, and control characters fail closed. File-level findings
use line 1 as their conventional anchor.

Empty findings emit `[]`. Invalid non-file ranges, outside-checkout paths, and
non-UTF-8 paths fail closed. The report remains issue-only: project metrics,
scope inventory, duplication, and completeness stay in the versioned JSON
report. A valid incomplete scan still emits its report and exits 2; findings
alone do not fail the scan.

## GitHub Code Quality scope

The separate `catalog/github-code-quality.json` is authoritative metadata for
382 GitHub Code Quality definitions captured from CodeQL. Its definitions and
help links are not evidence that a detector exists. The
`github-code-quality` profile deliberately exposes only the conservative,
high-confidence implemented subset in Hoonarqube's C#, Go, Java,
JavaScript/TypeScript, Python, and Ruby analyzers. Missing definitions are not
approximated, and this subset is not full behavioral parity with CodeQL or
GitHub Code Quality.

The executable registry currently covers 54/382 definitions: C# 13/69, Go
5/22, Java 15/89, JavaScript/TypeScript 13/98, Python 5/101, and Ruby 3/3.
`cargo run --locked -q -p xtask -- catalog github-coverage` verifies registry
coherence and prints all 328 missing IDs. `--require-full` is the release gate
for any future complete-parity claim and currently fails closed.

Rust is intentionally outside this profile: the core route returns no GitHub
Code Quality findings for Rust. Rust remains covered only by its separate
Sonar-compatible/native analyzer contracts. Hoonarqube does not depend on or
bundle the CodeQL CLI; the catalog is captured metadata and the detectors are
implemented in Hoonarqube.

The CLI contract is `analyze --profile github-code-quality --format sarif`.
It emits SARIF 2.1.0 with a `Hoonarqube` driver. `Maintainability` and
`Reliability` are the catalog categories; `Error` maps to SARIF `error`,
`Warning` to `warning`, and `Recommendation`/`Info` to `note`. Internal
0-based columns become SARIF 1-based columns, and flow locations become
`relatedLocations`. Coordinate-dependent partial fingerprints are omitted
unless a stable content fingerprint is available.
`actions/code-quality` validates this report and uploads it only when explicitly
enabled, through the pinned
`github/codeql-action/upload-sarif@cdf488f595d80d6e07e03d4674febd5ab45fa938`
revision. Optional `fail-on` gating runs after upload, so blocking findings are
still published to code scanning. That action transports third-party SARIF into
GitHub code scanning; it neither runs CodeQL nor injects findings into GitHub's
native Code Quality dashboard.

Consumers should declare only `contents: read` and `security-events: write`.
The latter is unavailable for fork pull-request tokens, so workflows must keep
upload disabled for forked code or condition it on a push or same-repository
pull request. `actions/analyze` remains the SonarQube Generic Issue Import
action and does not accept the isolated GitHub Code Quality profile.

No full Code Quality parity claim is allowed until every one of the 382
definitions has an implemented, independently verified query with matching
fixtures, locations, messages, categories, severities, and interaction
behavior. This boundary is independent of the SonarQube parity requirements
below.

## Full-parity requirements

1. Every catalog rule must be executable. No rule may be hidden by an `INFRA`,
   parser, type-system, cross-file, runtime-configuration, or Razor exemption.
2. For every rule, the matching SonarQube edition and Hoonarqube must emit the
   exact same finding multiset on bad, good, boundary, malformed-syntax, and
   interaction fixtures. Equality includes rule key, file, message, start/end
   line and column, and count.
3. Python, JavaScript, TypeScript, JSX/TSX, C#, Go, and Rust must use their real upstream
   analysis routes. C# requires successful MSBuild/Roslyn-integrated evidence;
   a zero-finding scan is blocked evidence, never a pass.
4. Mixed-language CLI analysis must preserve deterministic issue ordering,
   metrics, paths, parser recovery, defaults, and parameter overrides.
5. `--format sonar` must be accepted by Generic Issue Import and preserve rule
   identity, classification, impacts, messages, and locations.
6. Every upstream quick fix in scope needs equivalent preview, conflict, apply,
   and post-apply verification behavior. `QUICKFIX.md` tracks this separately.
7. Fixtures and generators must be reproducible from a clean checkout. Ignored
   or stale local artifacts are not proof.
8. Required CI gates must run on the exact claimed commit. Skipped,
   allowed-failure, stale, or wrong-version evidence does not count.

## Strict oracle semantics

`tools/oracle/parity.py` compares this normalized finding identity as a
multiset:

```text
(rule, file, message, start_line, start_column, end_line, end_column)
```

Important statuses:

- `PASS`: exact bad-fixture equality and both good controls clean.
- `ENTERPRISE_UNVERIFIED`: local fixture passes, but Community cannot execute
  the Enterprise rule. Explicit non-pass accepted by routine Community gates.
- `UPSTREAM_UNVERIFIED`: local bad/good controls pass, but the current Community
  analyzer cannot emit valid evidence because its Clippy contract is incompatible.
  Explicit non-pass accepted only for a documented upstream defect.
- `BAD_MISMATCH`: missing, extra, differently messaged, or differently located
  findings despite both sides meeting the minimum trigger count.
- `OURS_MISS`, `SQ_MISS`, `BOTH_MISS`: one or both analyzers lack the required
  bad-fixture finding.
- `GOOD_FIRE`: either analyzer fires on the near-miss control.
- `BEYOND_CE`: an ordinary catalog rule is absent from the Community oracle,
  usually because of analyzer-version drift. Strict failure.
- `ORACLE_UNVERIFIED`, `INVALID_EXPECTATION`, blocked projects, `SKIPPED`, and
  `INFRA` all fail closed. `PASS`, `ENTERPRISE_UNVERIFIED`, and
  `UPSTREAM_UNVERIFIED` are non-failing; only `PASS` is exact parity.

Every `INFRA` row must match an exact key and reason in
`catalog/infra-boundaries.json`. Fixture manifests cannot self-classify a new
exception, change its reason, or silently retain a removed boundary. The same
manifest identifies the 17 implementation gaps used by catalog coverage.

Enterprise-unverified rules still require local evidence. If Hoonarqube misses
their bad fixture or fires on their good control, the result is `OURS_MISS` or
`GOOD_FIRE`, not `ENTERPRISE_UNVERIFIED`.

Oracle artifacts use schema version 2 and retain complete messages/ranges.
Paginated API reads require unique issue/hotspot keys across every page;
missing or repeated keys are rejected even when page counts and totals match.
Legacy line-only artifacts are rejected. `--quick` validates cached artifacts;
a full run refreshes scanner results.

## Historical whole-corpus baseline — 2026-08-29

The following counts describe a captured qualification baseline; they do not
identify the current checkout `HEAD` or a release artifact. Current state is
**not full parity**. Full-corpus comparisons include intentional malformed-input
rows, and incomplete rows remain fail-closed/non-pass rather than being counted
as clean results.

- Coverage audit finds direct repository tests for all 1,724 actionable
  implementations: 460 C#, 403 JavaScript, 406 TypeScript, 334 Python,
  36 Go, and 85 Rust.
  Seventeen additional rules remain `INFRA`; strict coverage exits 1.
- Go's current Community oracle has 36 exact passes. Rust has 80 exact passes
  and five upstream-unverified rows (`S1858`, `S3723`, `S3807`, `S4275`,
  `S7450`); all 85 Rust bad/good fixture contracts pass locally.
- A fresh SonarQube 26.8 scan gives 117 Python, 119 JavaScript, and 115
  TypeScript exact passes. The three projects retain 833 fail-closed rows:
  284 `BAD_MISMATCH`, 15 `GOOD_FIRE`, 451 `SQ_MISS`, 31 `BEYOND_CE`,
  31 findings from new upstream rules outside the frozen catalog, 11 legacy or
  configuration skips, and 10 approved infrastructure boundaries.
- Seventy-seven local oracle/import harness tests pass as of 2026-08-31, including
  fail-closed Rust Clippy report generation and upstream-unverified semantics.
- Seventeen Enterprise C# rules remain implemented and locally tested. Their
  exact keys and analyzer ownership are integrity-checked in
  `catalog/community-artifact-resolution.json`.
- The latest public C# analyzer (`SonarAnalyzer.CSharp` 10.33.0.1635) gives 302
  exact full-corpus passes. Another 106 rules match their designated bad/good
  fixtures exactly but diverge on findings produced in other rules' fixtures;
  these remain failing `BAD_MISMATCH` rows. Forty-two rows remain exact,
  manifest-approved infrastructure gaps, and 17 are Enterprise-unverified.
- Commercial analyzer execution is not part of routine development or CI.
  Enterprise parity for those 17 rows remains intentionally unverified.
- Expectation manifests cover all 1,741 catalog keys. Tracked corpus contains
  3,436 language source files, including 72 Go and 170 Rust bad/good fixtures.

## Commands

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo run --locked -q -p xtask -- catalog audit --require-pages-complete
cargo run --locked -q -p xtask -- catalog coverage --strict --allow-infra
PYTHONPATH=tools/oracle python3 -m unittest discover -s tools/oracle -p 'test_*.py' -v
python3 tools/oracle/csharp_direct_oracle.py \
  --analyzer /path/to/SonarAnalyzer.CSharp.dll \
  --result .oracle/sonar/results/oracle-cs.community-base-direct.sq.json
SONAR_ORACLE_RESULT_TAG=community-base-direct \
  python3 tools/oracle/parity_suite.py --project oracle-cs --quick
python3 tools/oracle/parity_suite.py \
  --project oracle-go --project oracle-rust
python3 tools/oracle/verify_rust_upstream.py \
  .oracle/sonar/projects/oracle-rust /path/to/sonar-rust-plugin.jar \
  .oracle/sonar/results/oracle-rust.upstream-contract.json
```

A full Community server refresh requires `SONAR_DOTNET_SCANNER` and a .NET 10
SDK for C#. Generic scans fall back to Podman; Rust fallback builds the tracked
scanner image and mounts the local Rustup toolchain so SonarQube runs Clippy
itself. Token remains outside repository in
`.oracle/sonar/token` or `SONAR_ORACLE_TOKEN`. File-backed tokens must be
caller-owned regular files with no group or other permissions.

GitHub workflow runs reproducible local gates. Routine Community certification
can be green with explicit unverified rows; exact full parity remains unclaimed
while Enterprise, upstream, or infrastructure gaps exist.
