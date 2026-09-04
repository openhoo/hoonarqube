# Hoonarqube

Rust-native SonarQube-compatible static analyzer for Python, JavaScript/TypeScript,
C#, Go, and Rust. It combines a frozen Sonar-parity catalog with a separate,
provenance-rich native catalog and emits text, JSON, or SonarQube Generic Issue
Import JSON.

## Workspace

| Crate | Purpose |
|---|---|
| `hoonarqube` | Public facade crate: re-exports `analyze`, `Language`, `AnalyzerOptions`, catalog, IR |
| `hoonarqube-core` | Language dispatch by extension and end-to-end `analyze()` orchestration |
| `hoonarqube-catalog` | Frozen Sonar catalog plus separate native metadata/provenance catalog and cumulative profiles |
| `hoonarqube-ir` | Findings, execution/data-flow locations, and fix IR: `Issue`, `IssueFlow`, `Fix`, reports and metrics |
| `hoonarqube-python` | Python analyzer (ruff parser) |
| `hoonarqube-jsts` | JavaScript/TypeScript/JSX/TSX analyzer (oxc) |
| `hoonarqube-csharp` | C# analyzer (tree-sitter-c-sharp) |
| `hoonarqube-go` | Go analyzer (tree-sitter-go) |
| `hoonarqube-rust` | Rust analyzer (tree-sitter-rust with Clippy-compatible contracts) |
| `hoonarqube-dataflow` | Generic intra-procedural engine: CFG builder, worklist solvers, dominators; consumed by Go's native decompression-flow rule |
| `hoonarqube-cli` | `analyze` (text / JSON / SonarQube generic-issue), `fix`, plus `rules`/`snapshot` catalog queries |
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
- Parsing is tolerant everywhere: partial syntax trees are analyzed, broken files never abort a run,
  and parse errors emit no findings unless a catalog rule exists for them.
- Positions follow the SonarQube convention (1-based line, 0-based column); issues are sorted.
- Flow-aware findings can carry ordered `IssueFlow` locations. Generic Issue Import output
  exports non-primary flow steps as `secondaryLocations` because that schema has no code-flow group.
- Metrics (`lines`, `code_lines`, `comment_lines`) are computed per file and preserved through every
  refactor.

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

The latest public C# analyzer (`SonarAnalyzer.CSharp` 10.33.0.1635) certifies
302 exact full-corpus contracts. Another 106 rules match their designated
bad/good fixtures exactly but diverge on cross-fixture interactions, so remain
failing `BAD_MISMATCH` rows. Forty-two rows remain direct-oracle infrastructure
gaps; 17 implemented commercial rules are explicitly `enterprise-unverified`
because Community cannot execute them. They remain shipped and locally tested,
but no Enterprise parity claim is made.

Go Community parity is 36/36 exact. Rust Community parity is 80/85 exact;
five implemented rules are upstream-unverified because SonarQube 26.8 requests
removed or invalid Clippy contracts. They still require bad-fire/good-clean
local evidence and are not counted as exact passes.

A fresh SonarQube 26.8 run certifies 117 Python, 119 JavaScript, and 115
TypeScript full-corpus contracts. Those projects still have 833 fail-closed
rows spanning finding mismatches, misses, good-control fires, catalog drift,
legacy/configuration skips, and approved infrastructure boundaries. Local
coverage therefore does not imply analyzer parity.

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
The source-by-source adoption and deferral record is maintained in
[RULE_RESEARCH.md](RULE_RESEARCH.md).

## Usage

```bash
cargo run -p hoonarqube-cli -- analyze <paths...>              # text report
cargo run -p hoonarqube-cli -- analyze --profile recommended <paths>
cargo run -p hoonarqube-cli -- analyze --profile extended <paths>
cargo run -p hoonarqube-cli -- analyze --format sonar <paths>  # Generic Issue Import JSON
cargo run -p hoonarqube-cli -- rules native                    # native provenance catalog
cargo run -p hoonarqube-cli -- rules native --profile recommended --lang go
cargo run -p hoonarqube-cli -- rules info hoonarqube-go:G110
cargo run -p hoonarqube-cli -- fix <paths>                     # dry-run automatic fixes
cargo run -p hoonarqube-cli -- fix --diff <paths>              # preview unified diff
cargo run -p hoonarqube-cli -- fix --apply <paths>             # write and verify
cargo run -p hoonarqube-bench -- --iterations N                # throughput table
cargo run -p xtask -- catalog coverage                         # parity audit
```

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
and retains flow evidence as `relatedLocations`. Coordinate-dependent partial
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
finding-backed coverage starts with the syntax-checked `python:S1721` redundant-
parentheses remedy. See [QUICKFIX.md](QUICKFIX.md) for the parity inventory.

## Releases

The release workflow publishes the optimized Linux archive, SPDX SBOM, sorted
SHA-256 checksums, keyless Sigstore bundles, and GitHub artifact attestations
from the immutable release tag.

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
