# Hoonarqube

Rust-native SonarQube-compatible static analyzer for Python, JavaScript/TypeScript,
C#, Go, Java, Ruby, and Rust. It combines a frozen Sonar-parity catalog with a
separate, provenance-rich native catalog and emits text, JSON, SARIF, SonarQube
Generic Issue Import JSON, or GitLab Code Quality JSON.

## Workspace

| Crate | Purpose |
|---|---|
| `hoonarqube` | Public facade crate: re-exports `analyze`, `Language`, `AnalyzerOptions`, catalog, IR |
| `hoonarqube-core` | Language dispatch, per-file analysis, project measurements, and duplicate-block detection |
| `hoonarqube-catalog` | Frozen Sonar catalog plus separate native metadata/provenance catalog and cumulative profiles |
| `hoonarqube-ir` | Findings, execution/data-flow locations, and fix IR: `Issue`, `IssueFlow`, `Fix`, reports and metrics |
| `hoonarqube-python` | Python analyzer (ruff parser) |
| `hoonarqube-jsts` | JavaScript/TypeScript/JSX/TSX analyzer (oxc) |
| `hoonarqube-csharp` | C# analyzer (tree-sitter-c-sharp) |
| `hoonarqube-go` | Go analyzer (tree-sitter-go) |
| `hoonarqube-java` | Java frontend, local control-flow facts, and GitHub Code Quality checks (tree-sitter-java) |
| `hoonarqube-ruby` | Ruby frontend, local data-flow facts, and GitHub Code Quality checks (tree-sitter-ruby) |
| `hoonarqube-rust` | Rust analyzer (tree-sitter-rust with Clippy-compatible contracts) |
| `hoonarqube-dataflow` | Generic intra-procedural engine: CFG builder, worklist solvers, dominators; consumed by Go's native decompression-flow rule |
| `hoonarqube-cli` | `analyze` (text / JSON / SARIF / SonarQube generic-issue / GitLab Code Quality), `fix`, plus `rules`/`snapshot` catalog queries |
| `hoonarqube-service` | Optional authenticated SQLite-backed analysis/history service, dashboard, and JSON API (`hoonarqube-service` binary) |
| `hoonarqube-bench` | Multi-language throughput benchmark over seeded synthetic fixtures |
| `xtask` | Catalog audit + implemented-rule coverage reporting |

All workspace packages are source-only and inherit `publish = false`; GitHub
source releases do not imply crates.io publication.

## Analyzer architecture

The Python and JS/TS analyzers follow this shared per-rule layout. C#, Go, and
Rust use tolerant tree-sitter traversals and language-specific semantic helpers:

```
src/
├── lib.rs            # public API only: language enum, AnalyzerOptions, analyze() orchestration
├── context.rs        # per-file analysis context handed to rules
├── support/          # shared helpers: positions, issue constructors, scanners
├── engine/           # shared machinery: scope/symbol models, regex pattern parsers
├── rules/
│   ├── mod.rs        # explicit registry: run_all(ctx) calling each rule's check in order
│   └── <rule>.rs     # ONE FILE PER RULE: pub(crate) fn check(...) -> Vec<Issue>
│                     #   + #[cfg(test)] mod tests co-located with the rule
└── tests.rs / tests/ # cross-rule integration tests only
```

Invariants:

- Sonar rule keys remain `<repository>:<key>` and resolve only through the frozen catalog.
  Native keys use `hoonarqube-<language>:<key>` and resolve only through the separate native catalog;
  analyzers never duplicate either metadata source.
- Per-file rule analysis remains tolerant: partial syntax trees can produce findings.
  Project analysis separately reports parser/read failures as incomplete and exits nonzero;
  it never presents an incomplete duplication scan as zero duplication.
- Positions follow the SonarQube convention (1-based line, 0-based column); issues are sorted.
- Flow-aware findings can carry ordered `IssueFlow` locations. Generic Issue Import output
  exports non-primary flow steps as `secondaryLocations` because that schema has no code-flow group.
- Project reports normalize physical, code-bearing, and comment-only line counts across all
  supported frontends. Test measurements remain separate from source aggregates.

## Coverage

Audited by `cargo run -p xtask -- catalog coverage [--lang <id>] [--strict] [--allow-infra]`
against the frozen catalog:

| Language | Implemented | Directly tested | Untested | Infra gaps | Total | Tested coverage |
|---|---:|---:|---:|---:|---:|---:|
| JavaScript | 403 | 403 | 0 | 3 | 406 | 100.0% |
| TypeScript | 406 | 406 | 0 | 6 | 412 | 100.0% |
| Python | 334 | 334 | 0 | 1 | 335 | 100.0% |
| C# | 460 | 460 | 0 | 7 | 467 | 100.0% |
| Go | 36 | 36 | 0 | 0 | 36 | 100.0% |
| Rust | 85 | 85 | 0 | 0 | 85 | 100.0% |

### Documented gaps

The uncovered keys require out-of-repository infrastructure or reflect deliberate
parser-fidelity limits. Each exact key and reason is recorded in
`catalog/infra-boundaries.json`:

- TypeScript-checker semantic symbol and dependency metadata —
  `javascript:S1874`, `typescript:S1874`.
- Cross-file module resolution — `javascript:S6627`, `typescript:S4328`,
  `typescript:S6627`.
- TypeScript-checker-grade type semantics — `typescript:S4325`, `S6606`.
- Roslyn-grade type lattice / inheritance coupling graphs — `csharpsquid:S110`, `S1200`,
  `S1944`, `S3242`, `S3246`, `S4047`.
- Blazor compilation and semantic invocation binding — `csharpsquid:S6802`.
- Third-party GraphQL symbol resolution and inheritance semantics — `python:S6786`.
- ASI reconstruction from a tolerant parse — `javascript:S1438`, `typescript:S1438`.

All 1,724 actionable implementations now have direct, repository-qualified test
evidence. The strict audit remains deliberately red because 17
infrastructure-classified rows are still parity gaps. Direct tests and
implementation markers do not prove SonarQube-equivalent behavior. See
[PARITY.md](PARITY.md) for the exact oracle contract and current failures.

The captured public C# analyzer baseline (`SonarAnalyzer.CSharp` 10.33.0.1635)
certifies 302 exact full-corpus contracts. Another 106 rules match their
designated bad/good fixtures exactly but diverge on cross-fixture interactions,
so remain failing `BAD_MISMATCH` rows. Forty-two rows remain direct-oracle
infrastructure gaps; 17 implemented commercial rules are explicitly
`enterprise-unverified` because Community cannot execute them. They remain
shipped and locally tested, but no Enterprise parity claim is made.

Go Community parity is 36/36 exact. Rust Community parity is 80/85 exact;
five implemented rules are upstream-unverified because SonarQube 26.8 requests
removed or invalid Clippy contracts. They still require bad-fire/good-clean
local evidence and are not counted as exact passes.

A captured SonarQube 26.8 run certifies 117 Python, 119 JavaScript, and 115
TypeScript full-corpus contracts. Those projects still have 833 fail-closed
rows spanning finding mismatches, misses, good-control fires, catalog drift,
legacy/configuration skips, and approved infrastructure boundaries. These
whole-corpus comparisons intentionally include malformed-input rows; an
incomplete row remains non-pass and is never counted as clean or exact parity.
Local coverage therefore does not imply analyzer parity.

### Current qualification and publication boundaries

- The configured C# worktree proof establishes exactly 21 canonical target
  findings (`reference=21`, `native=21`). All other context findings remain
  retained outside that target-only exactness claim. See the
  [portable C# reference manifest](tools/oracle/roadmap-focused-reference-20260909.json).
- The configured issue36 JavaScript/TypeScript worktree proof covers six cases
  and 30 exact target findings in total, including one whitelist finding. It
  is worktree qualification, not final published-binary evidence. See the
  [portable JS/TS reference manifest](tools/oracle/roadmap-jsts-python-reference-20260909.json).
- The parsers accept valid JSX `IdentifierName` element, attribute, member, and
  namespace names, plus valid C# declarations using contextual `async`/`await`
  (including `static`/`async` local functions). `S2306` remains
  declaration-only: valid `async`/`await` references are not reported.
- Malformed JavaScript/TypeScript/JSX/C# input, and TypeScript-only JSX syntax
  supplied through a `.jsx` input, remain fail-closed: project analysis exits
  `2`, marks the report incomplete, and does not expose duplication.
- A bounded working-tree CLI proof covers guarded C# `S3005` and `S3169`
  actions: safe diff/apply/reanalysis goes from target count `1` to `0`, while
  comment-bearing attribute trivia and custom `ThenBy` selected actions exit
  `1`, leave source unchanged, and retain the diagnostic. The exact `S1116`
  reference edit remains refused when its projected result introduces `S1186`;
  these results are not a full quick-fix parity claim.
- The [security qualification wrapper](tools/oracle/security-qualification-20260909.json)
  remains `SECURITY_PARITY_UNVERIFIED` and preserves explicit Enterprise,
  flow, and secondary-location `UNVERIFIED` states. Its recorded native
  identity `444c56f682998e7e638bd230104bfa1a3628cf57` is historical
  implementation evidence only, not the current `HEAD` or a release identity.
- The separate `#43`/`#44` evidence comparisons remain open; these focused
  qualifications do not close them.

Reference captures and their recorded identities are not rewritten, and
pending or blocked drafts are not presented as final release evidence.

## Native rules and profiles

Forty-seven rules are independently implemented from published CodeQL,
gosec, Staticcheck, ESLint, Ruff, .NET analyzer, and Clippy behavior. No third-party rule
source is embedded. Every native record declares original tool/rule ID, source
URL, upstream license, expected precision, implementation capability, impacts,
and minimum profile. This catalog stays structurally separate from captured
Sonar facts.

| Language | Native rules | Sources |
|---|---:|---|
| Go | 29 | gosec G110/G112/G114/G116/G117/G124/G301/G302/G303/G305/G306/G307/G401/G402/G403/G405/G406; Staticcheck SA1004/SA1012/SA2000/SA2001/SA2003/SA4006/SA4008/SA4010/SA5000/SA5001/SA5003/SA6000 |
| Python | 3 | CodeQL `py/side-effect-in-assert`, `py/file-not-closed`; Ruff S113 |
| JavaScript | 4 | CodeQL skipped splice iteration and piped-stream errors; ESLint Promise executor rules |
| TypeScript | 4 | Same CodeQL and ESLint behaviors with a distinct TypeScript namespace |
| C# | 3 | .NET CA2022/CA2024/CA2026 |
| Rust | 4 | Clippy async-guard, readonly-permission, and open-option rules |

Profiles are cumulative:

- `sonar-parity` — default compatibility contract; disables all native rules.
- `recommended` — 37 high-value, conservative native rules.
- `extended` — 46 rules, including broader local-flow checks.
- `strict` — all 47 rules; additionally enforces explicit `0600` file creation
  instead of `os.Create`'s umask-dependent `0666` mode.

The shared CFG engine now provides deterministic taint facts; Go G110 is its
first taint-fact consumer and emits ordered source-to-sink locations. Rules needing
unavailable type, SSA, or interprocedural proof stay absent instead of being
approximated with broad text matching. Native results are not claims of
CodeQL/gosec/Staticcheck/ESLint/Ruff/Roslyn/Clippy implementation parity.
`sonar-parity` is the default compatibility profile, not a blanket behavioral
parity promise. Native project metrics/duplication, native rules, compiler-backed
semantic facts, and IDE-style suggestions are separate features; their
availability does not turn them into SonarQube-equivalent metrics, rules, or IDE
behavior. Parity claims are limited to the contracts recorded in
[PARITY.md](PARITY.md).
The source-by-source adoption and deferral record is maintained in
[RULE_RESEARCH.md](RULE_RESEARCH.md).

## Usage

```bash
cargo run -p hoonarqube-cli -- analyze <paths...>              # text report
cargo run -p hoonarqube-cli -- analyze --profile recommended <paths>
cargo run -p hoonarqube-cli -- analyze --profile extended <paths>
cargo run -p hoonarqube-cli -- analyze --format sonar <paths>  # Generic Issue Import JSON
cargo run -p hoonarqube-cli -- analyze --format gitlab-codequality <paths> # GitLab Code Quality JSON
cargo run -p hoonarqube-cli -- rules native                    # native provenance catalog
cargo run -p hoonarqube-cli -- rules native --profile recommended --lang go
cargo run -p hoonarqube-cli -- rules info hoonarqube-go:G110
cargo run -p hoonarqube-cli -- fix <paths>                     # dry-run automatic fixes
cargo run -p hoonarqube-cli -- fix --diff <paths>              # preview unified diff
cargo run -p hoonarqube-cli -- fix --apply <paths>             # write and verify
cargo run -p hoonarqube-bench -- --iterations N                # throughput table
cargo run -p xtask -- catalog coverage                         # parity audit
```

### Project contexts and prerequisites

`analyze <paths>` is source-only by default: supported source inputs are
classified as `Source`, no test/generated/vendor filename heuristics are
inferred, and no compiler/project, coverage, baseline, or quality-gate context
is loaded. Native per-file findings and project measurements still run for
supported languages.

Project/compiler contexts are explicit and use these existing flags:

- `--typescript-project PATH` loads `PATH` when it is a `tsconfig.json` file, or
  `PATH/tsconfig.json` when `PATH` is a directory. `--typescript-module PATH`
  optionally supplies the project-local TypeScript package/compiler location;
  it is only valid with `--typescript-project`.
- TypeScript semantic analysis requires an installed Node.js `node` executable
  and runs a helper that resolves a project-local TypeScript package only; it
  never searches a global compiler or downloads one. The loaded compiler must
  be exactly the pinned **6.0.3** release.
- `--typescript-dependency-whitelist PACKAGE` supplies a repeatable S4328
  allowlist entry as a package name or scope. It requires
  `--typescript-project`; when omitted, the whitelist remains empty.
- `--csharp-project PATH` selects a C# project or solution. Pair it with
  `--allow-project-build` to explicitly trust project evaluation and the
  bounded `dotnet build --no-restore` used for project references and Razor
  generated sources. An installed .NET SDK capable of the bundled `net10.0`
  helper is required; `HOONARQUBE_DOTNET` can select its executable. Without
  this flag the project is not executed and compiler-backed C# facts are
  unavailable, while native analysis remains.
- `--csharp-timeout-ms MS` optionally changes the C# helper deadline from its
  default **30,000 ms**. It requires `--csharp-project` and accepts only a
  positive finite `u64` millisecond value; for example, `180000` allows a
  larger trusted workspace without introducing retries or an unbounded wait.
- TypeScript config resolution delegates to the pinned compiler: relative and
  package-based `extends`, directory or file-form project `references`, and
  `include` globs are resolved against the project root plus supplied source
  snapshots. Config files and package manifests actually read are recorded as
  digest-bearing context dependencies.
- Each invocation validates the root `tsconfig.json` bytes against its captured
  digest before helper analysis and caches that validated root config locally for
  the invocation. A later on-disk mutation cannot change its options; missing
  or invalid config/reference input remains an incomplete diagnostic.
- `--csharp-s110-max N` overrides S110's maximum parent-type depth (default
  **5**). It requires `--csharp-project`.
- `--csharp-s110-filtered-class PATTERN` supplies a repeatable S110 wildcard
  filter for class names. It requires `--csharp-project`; when omitted, the
  filter list remains empty.
- `--csharp-s1200-max N` sets S1200's maximum dependency count and explicitly
  enables that rule (default disabled, threshold **30**). It requires
  `--csharp-project`.
- `--python-project PATH` supplies a project root/module namespace for the
  source-snapshot cross-file rules; it does not execute Python code.

These options apply to both `analyze` and `fix`. Missing configuration, runtimes,
references, or compiler facts remain diagnostics and never become fabricated
semantic findings. The isolated `github-code-quality` profile cannot be combined
with compiler-backed project contexts.

Standalone release binaries embed the TypeScript CJS helper and the C# helper
project/program, `QuickFixPlanner`, and `RazorSourceFacts`, then materialize those
sources at runtime. A Hoonarqube checkout is not needed. The helpers do not bundle
external runtimes or packages: TypeScript still needs Node.js and the project-local
TypeScript **6.0.3** package, while C# still needs a .NET SDK capable of the
bundled `net10.0` helper. Keep `--allow-project-build` as an explicit trust
boundary and use it only with trusted project inputs.

### Incremental analysis cache

Repeated scans can opt in to a local per-file cache:

```bash
cargo run --release -p hoonarqube-cli -- analyze --cache-dir .cache/hoonarqube src
```

Unchanged files reuse successful findings and parsed source facts. Every run
still reads and hashes current source contents, discovers added/deleted files,
applies current scope settings, and recomputes full-project metrics and
cross-file duplication. This is not a partial Git-diff scan: unchanged files
remain represented in all results.

Cache keys include the executable's SHA-256, effective analyzer options
(including profile), working directory, exact file path and source bytes.
Changing the executable invalidates reuse, including development builds with
the same version. Cold runs pay cache-writing overhead; warm benefits depend
on parsing/rule costs relative to file I/O, deserialization, and duplication.
Use a release build for performance-sensitive pipelines.

Entries live in an owned hidden `.hoonarqube-cache-v1` child beneath the supplied
directory; `--cache-dir .` does not exclude your source tree. The ordinary
directory walker skips hidden cache artifacts. Failed analyses are not cached.
Corrupt, oversized, incompatible, or inaccessible entries fall back to fresh
analysis without changing report completeness. Writes are best-effort and
atomic. Omit the flag to disable caching; `fix` never uses it.

Treat cache storage as trusted local state, not an authenticated report source.
Checksums detect corruption, not deliberate cache forgery. Never restore
untrusted cache archives into a privileged pipeline. See [the Actions cache
example](actions/README.md#optional-caller-managed-analysis-cache) for
restore-only pull requests and protected-branch saves. Old entries are not
automatically pruned; remove the owned `.hoonarqube-cache-v1` child when you
want to reclaim space or force a cold run.

### Project metrics and duplication

`analyze` measures Python, JavaScript/JSX, TypeScript/TSX, C#, Go, Java, Rust,
and Ruby. Measurement support is independent of each language's rule-catalog
coverage. It detects repeated blocks within a file and across files of the
same language; JavaScript and TypeScript are separate matching domains.

```bash
cargo run -p hoonarqube-cli -- analyze --format json \
  --test-include '**/tests/**' \
  --generated-include '**/generated/**' \
  --vendor-include '**/vendor/**' \
  --exclude '**/fixtures/**' \
  --duplication-exclude '**/*.min.js' \
  src tests
```

Each glob option is repeatable and accepts one complete, quoted glob.
Brace alternatives such as `--exclude '**/*.{js,ts}'` are supported. Paths
inside the current working directory are matched relative to that directory;
paths outside it are matched as absolute paths. Existing ignore-file and
hidden-entry walking rules still apply. No test/generated/vendor filename
heuristics are enabled implicitly.
The resulting default project classification is source-only; opt into other
scopes with the explicit include/exclude flags above.

Classification precedence is **excluded → vendor → generated → test → source**.
Source files contribute to project size and duplication. Tests retain their
findings and individual measurements, but do not contribute to those source
aggregates. Generated, vendor, and excluded scopes are not analyzed.
`--duplication-exclude` removes a source file only from duplication, preserving
its findings and size measurements.
Excluded directory roots remain visible as scope entries with no measurements;
their contents are not enumerated. Recursive scope globs ending in `/**`
support subtree pruning; other globs still apply to matching paths.

The JSON report has `schema_version: 1` and retains the existing `files`
array for findings. Its `project` object contains:

- `roots`, scope inventory in `files`, `complete`, and `warnings`.
- `metrics`: source file count, physical `lines`, `code_lines`, and
  comment-only `comment_lines`, accumulated with 64-bit counters.
- `duplications`: clone groups with every occurrence's path, inclusive
  1-based line range, and half-open UTF-8 `start_byte`/`end_byte` offsets.
  Byte offsets distinguish separate blocks on the same physical line.
- `duplication`: duplicated line/block/file counts and
  `duplicated_lines_density`, also available for eligible individual files.

Duplicated lines are the union of matching line ranges within each file;
overlapping groups cannot count a line twice. Blocks count distinct source
byte spans, not groups. Project density uses the total physical lines of
duplication-eligible source files, rather than averaging file percentages.
An empty denominator produces `null`, not a fabricated percentage.

Default detection thresholds are **100 normalized syntax tokens across
10 physical lines**, or **10 statement units for Java**, irrespective of
line count. Override them with `--duplication-min-tokens`,
`--duplication-min-lines`, and `--duplication-min-statements`; all must be
positive. Comments and layout are ignored, plain string contents are
normalized, and identifiers, operators, numeric literals, and embedded
interpolation expressions remain significant. Structural markers retain
layout-sensitive boundaries. Java uses separate direct-statement streams
for nested blocks, with control/declaration signatures and nonmatching
boundaries between streams.

These are native measurement semantics, **not an established SonarQube
metric-equivalence claim**. In particular, syntax-token accounting and Java
statement selection require separate oracle evidence. See [PARITY.md](PARITY.md).

Failed reads/parses, unsupported explicit inputs, or exhausted resource budgets
make `project.complete` false and duplication unavailable (`null`), while
preserving available findings and scope diagnostics. Recognized CSS, HTML, and
Docker files found during a directory walk are instead retained in the JSON
inventory as `classification: "excluded"` and `status: "unsupported"` entries
with no metrics, so they leave metrics unchanged and do not make the project
incomplete (`complete: true`, exit 0). Passing one directly as a file (without
an explicit excluded/generated/vendor classification) retains it as
`Source`/`Unsupported`, makes `complete: false`, and exits **2**. The CLI
still emits the report. Facts collection limits individual inputs to 16 MiB.
The default project matcher accepts up to 2,000,000 normalized units and
1,000,000 candidate pairs, with an additional bounded comparison budget. Limit
failures are explicit, never silently truncated results.

Text output summarizes source/test measurements, scope, completeness, and
matching locations. Detailed scope inventory is in JSON. SonarQube Generic
Issue Import, SARIF, and GitLab Code Quality remain issue-only formats: they do
not transport these project measures or create artificial duplication issues.

### Coverage, baselines, and quality gates

Assessment is optional native JSON data. `--assessment` records versioned
provenance and source-derived finding identities; the other assessment flags
are explicit inputs:

- `--coverage-lcov PATH` and `--coverage-opencover PATH` are repeatable. They
  import LCOV or OpenCover XML against the exact analyzed source snapshots.
  Inputs must be regular, non-symlink, UTF-8 files within the 64 MiB bounded
  assessment-input limit.
- `--baseline PATH` compares against the exact prior native `AnalysisReport`
  JSON (schema 1) supplied at that path. Its assessment context must match the
  analyzer, catalog, effective options, and scope; this is a pinned-reference
  comparison, not Git-history or merge-base discovery.
- `--write-baseline PATH` atomically writes the current native report with its
  assessment artifact to that path. Use a complete result as the subsequent
  pinned reference.
- `--quality-gate PATH` reads a versioned JSON gate configuration. The accepted
  shape is `{"schema_version":1,"conditions":[...]}`; conditions use
  `scope: "overall"` or `"new_code"`, `metric`, `operator` (`lt`, `lte`, `eq`,
  `gte`, or `gt`), and a finite non-negative `threshold`. Supported metrics are
  `files`, `lines`, `code_lines`, `comment_lines`, `issues`,
  `duplicated_lines`, `duplicated_blocks`, `duplicated_files`,
  `duplicated_lines_density`, `line_coverage`, and `branch_coverage`.
  `new_code` does not support `code_lines` or `comment_lines`, and any
  `new_code` condition requires `--baseline`.

Coverage, baseline, and gate results are versioned under the native
`assessment` object. Missing, invalid, or incomplete assessment data, an
unavailable gate, or an incomplete native project yields exit **2**; a
configured gate that evaluates to `fail` yields exit **1**. The report is still
emitted when its requested output format can be rendered. Native JSON (`--format
json` or global `--json`) carries the optional assessment; text includes a
summary, while SonarQube Generic Issue Import, SARIF, and GitLab Code Quality
remain issue-only exports. These contracts are native assessment behavior, not
SonarQube coverage, baseline, or quality-gate parity.

## CSS, HTML, and Docker inventory

The reference-only
[`catalog/reference/issue-52-language-inventory.json`](catalog/reference/issue-52-language-inventory.json)
records SonarQube Community server **26.8.0.126808** observations. Counts are
`all / active` reference rules, not shipped detector counts:

| Reference language | Server key | All | Active | Hoonarqube status |
|---|---|---:|---:|---|
| CSS | `css` | 43 | 40 | `planned_not_implemented` |
| HTML | `web` | 104 | 61 | `planned_not_implemented` |
| Docker | `docker` | 28 | 25 | `planned_not_implemented` |

All three languages are absent from the frozen local rule catalog, native
language dispatch, and current eight-language measurement dispatch. The
reference counts are server/profile observations only; all listed rule work is
planned, not implemented locally.

When a directory is analyzed, recognized CSS, HTML, and Docker paths are kept
as `Excluded`/`Unsupported` inventory entries with reason `language is
unsupported` and no metrics. Recognition is case-insensitive for CSS
(`.css`, `.less`, `.scss`, `.sass`), HTML (`.html`, `.xhtml`, `.cshtml`,
`.vbhtml`, `.aspx`, `.ascx`, `.rhtml`, `.erb`, `.shtm`, `.shtml`, `.cmp`,
`.twig`, `.htm`), and Docker (`Dockerfile` or any `.dockerfile` basename).
The ordinary supported-source metrics and cross-file CPD remain unchanged,
`project.complete` stays true, and the exit code stays 0. Passing one of those
files explicitly (without an explicit exclusion or another inventory
classification) keeps it as `Source`/`Unsupported`, makes the project
incomplete, and exits 2.

## GitHub Code Quality action

`catalog/github-code-quality.json` is the authoritative metadata catalog for
GitHub Code Quality: it contains 382 definitions captured from CodeQL. A
definition is not an implementation claim. The `github-code-quality` profile
intentionally runs only Hoonarqube's conservative, high-confidence implemented
subset across C#, Go, Java, JavaScript/TypeScript, Python, and Ruby. The
remaining definitions are not silently approximated, so this action must never
be described as implementing all 382 queries or as full CodeQL behavioral
parity.

The executable registry currently covers **54 of 382** definitions: C# 13/69,
Go 5/22, Java 15/89, JavaScript/TypeScript 13/98, Python 5/101, and Ruby 3/3.
Audit the registry and print every missing ID with:

```bash
cargo run --locked -q -p xtask -- catalog github-coverage
```

Add `--require-full` when a release is intended to claim complete parity; it
currently fails closed because 328 definitions remain unimplemented.

Rust is deliberately excluded from this profile. Rust files produce no GitHub
Code Quality findings; use the regular Sonar-compatible profile when Rust
analysis is required. Hoonarqube runs its own detectors and does not install,
invoke, or require the CodeQL CLI. The catalog preserves CodeQL query
metadata, but metadata presence is not detector coverage.

The CLI emits the SARIF 2.1.0 contract directly:

```bash
cargo run --locked -q -p hoonarqube-cli -- analyze \
  --profile github-code-quality --format sarif -- src
```

The SARIF driver is `Hoonarqube`. Query categories are `Maintainability` and
`Reliability`. Query severities map to SARIF levels as follows: `Error` to
`error`, `Warning` to `warning`, and `Recommendation` or `Info` to `note`.
Hoonarqube converts its internal 0-based columns to SARIF's 1-based columns
and declares `columnKind: unicodeCodePoints` so non-BMP characters keep correct
source locations. Artifact paths are percent-encoded relative URI references,
including filenames containing colons. Flow evidence is retained as
`relatedLocations` and `codeFlows`. Coordinate-dependent partial
fingerprints are intentionally omitted unless a stable content fingerprint is
available.

`actions/code-quality` installs through the verified setup action, validates
the SARIF document, and exposes `report`, `result-count`, and
`blocking-findings` outputs. Upload is opt-in. The `fail-on` input accepts
`none` (default), `findings`, `note`, `warning`, or `error`; when enabled, a
validated report is uploaded before the threshold gate fails the job. GitHub's
`upload-sarif` action publishes third-party results to code scanning; it does
not inject them into GitHub's native Code Quality dashboard. The existing
`actions/analyze` action remains for SonarQube Generic Issue Import JSON.

Copy-paste workflow example:

```yaml
name: Code quality

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  code-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - id: hoonarqube
        uses: openhoo/hoonarqube/actions/code-quality@03b34bc8957995959d43531e82130a2c95bf01fa # pin to the consuming commit
        with:
          paths: |
            src
            crates
          output: .reports/hoonarqube-code-quality.sarif
          upload: ${{ github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository) }}
      - run: echo "Hoonarqube reported ${{ steps.hoonarqube.outputs.result-count }} finding(s)"
```

Uploading to code scanning requires `security-events: write`; `contents: read`
is sufficient for checkout. GitHub downgrades the token for pull requests from
forks, so that permission is unavailable there. The condition above uploads
pushes and same-repository pull requests only; fork pull requests still get a
local validated report, but cannot upload it. Keep upload disabled for
untrusted contexts and do not grant write permissions to forked code.

### Automatic fixes

`fix` combines quick fixes attached to catalog findings with a safe mechanical
repair for missing final newlines. It never writes by default. Use `--diff` to
inspect the projected rewrite and `--apply` to write it. `--rule <prefix>`
limits finding-backed fixes (repeatable or comma-separated); the final-newline
repair remains enabled. Generic trailing-space and leading-tab rewrites are
intentionally excluded because that whitespace can be data inside multiline or
raw string literals.
Use `--suggestion RULE=ACTION_ID` (repeatable) to select one finding alternative
explicitly; when supplied, only those selected suggestions are planned, not
automatic fixes. Compiler-backed suggestions require the corresponding complete
project context above. These native/IDE-style actions are not a SonarQube quick-fix
parity claim.

Each multi-edit rule fix is atomic. If fixes overlap, deterministic earlier
fixes win and complete later fixes are skipped and reported. Apply mode rejects
a file changed since planning, then analyzes projected content before writing:
every rule fix must work independently, targeted rule counts must decrease by
the number of applied fixes, and no rule count may increase, including after a
mechanical-only rewrite. Failed verification returns a nonzero exit status and
leaves the file untouched. File content is checked again immediately before
the write.
Apply mode also rejects symlinked files and directories and rechecks each path
before writing. Analysis remains read-only and may inspect symlinked source
files, but never follows symlinked directories.

Global `--json` keeps stdout as one JSON document, including requested diffs as
per-file `diff` fields instead of mixing human text into machine output. Current
finding-backed coverage includes the syntax-checked `python:S1721` redundant-
parentheses remedy and guarded C# `csharpsquid:S3005`/`S3169` actions. See
[QUICKFIX.md](QUICKFIX.md) for the parity inventory and bounded proof.

## GitLab Code Quality report

The CLI emits GitLab's required single-array report with:

- `description` from the finding message and `check_name` from its rule key.
- A stable SHA-256 `fingerprint` over length-delimited normalized primary path,
  rule key, message, and primary range; nested flow/fix metadata is excluded.
- Lowercase `severity` (`info`, `minor`, `major`, `critical`, or `blocker`).
- A raw repository-relative POSIX `location.path` without a `./` prefix and
  inclusive positive `location.lines.begin`/`end` values. File-level findings
  use line 1 as their conventional anchor.

Ordinary colon filename components are preserved. Drive- and URI-like prefixes,
backslashes, control characters, outside-checkout paths, non-UTF-8 paths, and
invalid non-file ranges fail closed.

Use `--format gitlab-codequality` with the default `sonar-parity` profile or a
cumulative native profile. It is intentionally separate from the isolated
`github-code-quality` SARIF profile. Empty findings emit `[]`; invalid
non-file ranges, outside-checkout paths, and non-UTF-8 paths fail closed.
The report carries findings only, not project metrics or completeness. A
complete scan with findings exits 0; an incomplete scan still emits its valid
report and exits 2, while report/serialization failures exit 1.

GitLab consumes the report from a CI job's `codequality` report artifact. Use a
Linux x86_64 runner with a release binary installed and verified using the
repository's [release installer checks](actions/setup/install.sh):

```yaml
stages: [quality]

gitlab-code-quality:
  stage: quality
  script:
    - hoonarqube --version
    - set +e
    - hoonarqube analyze --format gitlab-codequality -- src tests > gl-code-quality-report.json
    - status=$?
    - set -e
    - test -s gl-code-quality-report.json
    - exit "$status"
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

The explicit status capture keeps an operational/incomplete exit 2 distinct
from a policy failure chosen by the consuming job; `artifacts: when: always`
keeps the report available for review.

## Optional analysis service and dashboard

`hoonarqube-service` stores already-produced native `AnalysisReport` JSON; it
does not analyze source itself. It opens a persistent SQLite database and serves
an optional dashboard plus a JSON API.

The service binary has three environment variables:

- `HOONARQUBE_SERVICE_DB` selects the SQLite file; it defaults to
  `hoonarqube-service.sqlite3`.
- `HOONARQUBE_SERVICE_CREDENTIALS` is required and contains a JSON array of
  unique credentials. Each entry has `user_id` and `token`, with an optional
  `projects` map (`project` to `reader`, `reviewer`, or `admin`) and optional
  `global_admin: true`. Tokens are static startup configuration; keep them
  outside source control.
- `HOONARQUBE_SERVICE_BIND` selects the listen address; it defaults to
  `127.0.0.1:8080`.

For a local standalone deployment, keep the database and credential file private.
Populate the credential file with a newly generated token using the JSON shape
above; the launch below passes its contents through the existing credential
variable without placing a reusable token in the command:

```bash
install -d -m 0700 "$HOME/.config/hoonarqube" "$HOME/.local/share/hoonarqube"
credentials_file="$HOME/.config/hoonarqube/service-credentials.json"
test -s "$credentials_file"
chmod 600 "$credentials_file"

exec env \
  HOONARQUBE_SERVICE_DB="$HOME/.local/share/hoonarqube/service.sqlite3" \
  HOONARQUBE_SERVICE_BIND="127.0.0.1:8080" \
  HOONARQUBE_SERVICE_CREDENTIALS="$(<"$credentials_file")" \
  hoonarqube-service
```

The SQLite file and its WAL state persist under
`$HOME/.local/share/hoonarqube`; open `http://127.0.0.1:8080/` and provide the
configured bearer token when prompted.

The dashboard is served at `/` (also `/index.html`) and keeps the entered
bearer token only in the current tab. All `/api/v1` endpoints require
`Authorization: Bearer ...`. The UI can list visible projects and branches,
browse immutable analysis history/details/findings, and create/read finding
reviews. Ingestion and administrative operations remain API-only:

- Read endpoints are `GET /api/v1/projects`, `GET
  /api/v1/projects/{project}/branches`, `GET
  /api/v1/projects/{project}/analyses`, `GET
  /api/v1/projects/{project}/analyses/{analysis_id}`, `GET
  /api/v1/projects/{project}/analyses/{analysis_id}/findings`, `GET
  /api/v1/projects/{project}/reviews`, and `GET
  /api/v1/projects/{project}/reviews/{review_id}/history`.
- `POST /api/v1/projects/{project}/analyses` ingests a request with
  `schema_version: 1`, `branch`, `commit`, `analyzed_at`, and the native
  `report`; re-ingesting the same project/branch/commit is idempotent.
- `POST /api/v1/projects/{project}/reviews` records a versioned finding or
  hotspot review with an audit reason. `GET /api/v1/projects/{project}/export`
  and `POST /api/v1/projects/{project}/restore` provide the backup boundary.
- `POST /api/v1/projects/{project}/retention` and `DELETE
  /api/v1/projects/{project}/analyses/{analysis_id}?reason=...` or `DELETE
  /api/v1/projects/{project}?reason=...` are administrative and retain
  deletion/audit records.

`reader` may read project data, `reviewer` may also mutate review state, and
`admin` may ingest, delete, export, restore, and apply retention. A
`global_admin` bypasses per-project mappings. There is no login or external
identity-provider flow: credentials are static bearer tokens, project-scoped
unless global admin, and every API request is authenticated. The SQLite store
uses WAL and foreign keys; the service defaults to a loopback plain-HTTP
listener, so TLS or a wider network boundary must be provided by the
deployment.

The standalone binary enforces bounded request/report sizes (16 MiB request
bodies, 100,000 report files, and 500,000 issues). These limits, static
credentials, and the dashboard's read/review-only surface are intentional
service boundaries, not SonarQube server parity.

## Releases

The release workflow publishes an optimized Linux archive containing both
executables, `hoonarqube` (CLI) and `hoonarqube-service` (optional persistent
service/dashboard), plus the SPDX SBOM, sorted SHA-256 checksums, keyless
Sigstore bundles, and GitHub artifact attestations from the immutable release
tag.

### Installing from a release archive

Download the Linux x86_64 archive and its matching assets from the official
[GitHub release page](https://github.com/openhoo/hoonarqube/releases). The archive
contains both `hoonarqube` and `hoonarqube-service`; do not extract or install it
until its checksum and keyless signatures verify. This mirrors the repository's
[release installer checks](actions/setup/install.sh). With `cosign` installed from
a trusted source, run:

```bash
set -euo pipefail
command -v cosign >/dev/null 2>&1 || {
  echo "cosign is required; install it from a trusted source." >&2
  exit 1
}

read -r -p 'Release version without the leading v: ' VERSION
test -n "$VERSION"
STEM="hoonarqube-${VERSION}-x86_64-unknown-linux-gnu"
ARCHIVE="${STEM}.tar.gz"
CHECKSUMS="SHA256SUMS"
BASE_URL="https://github.com/openhoo/hoonarqube/releases/download/v${VERSION}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 \
  --output "$ARCHIVE" "$BASE_URL/$ARCHIVE"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 \
  --output "$CHECKSUMS" "$BASE_URL/$CHECKSUMS"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 \
  --output "${ARCHIVE}.sigstore.json" "$BASE_URL/${ARCHIVE}.sigstore.json"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 \
  --output "${CHECKSUMS}.sigstore.json" "$BASE_URL/${CHECKSUMS}.sigstore.json"

SIGNATURE_IDENTITY="https://github.com/openhoo/hoonarqube/.github/workflows/release.yml@refs/heads/main"
SIGNATURE_ISSUER="https://token.actions.githubusercontent.com"
cosign verify-blob "$ARCHIVE" --bundle "${ARCHIVE}.sigstore.json" \
  --certificate-identity "$SIGNATURE_IDENTITY" \
  --certificate-oidc-issuer "$SIGNATURE_ISSUER"
cosign verify-blob "$CHECKSUMS" --bundle "${CHECKSUMS}.sigstore.json" \
  --certificate-identity "$SIGNATURE_IDENTITY" \
  --certificate-oidc-issuer "$SIGNATURE_ISSUER"
sha256sum --ignore-missing --check "$CHECKSUMS"

tar -xzf "$ARCHIVE"
install -d "$HOME/.local/bin"
install -m 0755 "$STEM/hoonarqube" "$HOME/.local/bin/hoonarqube"
install -m 0755 "$STEM/hoonarqube-service" "$HOME/.local/bin/hoonarqube-service"
export PATH="$HOME/.local/bin:$PATH"
"$HOME/.local/bin/hoonarqube" --version
```

The release page is authoritative for the version and asset names; keep the
downloaded archive, checksum manifest, and Sigstore bundles from the same release.

## Development

```bash
cargo test --locked --workspace --all-targets --all-features  # full suite, including benches/examples
cargo run --locked -q -p xtask -- catalog coverage --strict --allow-infra
python3 -m unittest discover -s tools/oracle -p 'test_*.py' -v
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
cargo fmt --all --check
cargo deny check
ruff check tools/oracle --exclude tools/oracle/fixtures --extend-select C90,PLR0911,PLR0912,PLR0915,PERF,SIM,B
ruff format --check tools/oracle --exclude tools/oracle/fixtures
```

Conventions: one rule per file under `rules/`, its tests co-located in the same file; shared logic
in `support`/`engine`; explicit registries in `rules/mod.rs`; no lint suppressions.
