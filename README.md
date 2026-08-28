# Hoonarqube

Rust-native SonarQube-compatible static analyzer for Python, JavaScript/TypeScript, and C#, with a
frozen rule catalog and a CLI that walks source trees and emits findings either as text or as
SonarQube Generic Issue Import JSON.

## Workspace

| Crate | Purpose |
|---|---|
| `hoonarqube` | Public facade crate: re-exports `analyze`, `Language`, `AnalyzerOptions`, catalog, IR |
| `hoonarqube-core` | Language dispatch by extension and end-to-end `analyze()` orchestration |
| `hoonarqube-catalog` | Frozen, embedded rule catalog (severity/type/parameters) — the single source of truth for rule metadata |
| `hoonarqube-ir` | Findings and fix IR: `Pos`, `Range`, `Issue`, `Fix`, `TextEdit`, reports and metrics |
| `hoonarqube-python` | Python analyzer (ruff parser) |
| `hoonarqube-jsts` | JavaScript/TypeScript/JSX/TSX analyzer (oxc) |
| `hoonarqube-csharp` | C# analyzer (tree-sitter-c-sharp) |
| `hoonarqube-dataflow` | Generic intra-procedural engine: CFG builder, worklist solvers, dominators (not yet wired into any analyzer; reserved for future Tier-B adoption) |
| `hoonarqube-cli` | `analyze` (text / JSON / SonarQube generic-issue), `fix`, plus `rules`/`snapshot` catalog queries |
| `hoonarqube-bench` | Multi-language throughput benchmark over seeded synthetic fixtures |
| `xtask` | Catalog audit + implemented-rule coverage reporting |

## Analyzer architecture

The Python and JS/TS analyzers follow this shared per-rule layout; `hoonarqube-csharp` mirrors
it with `cst.rs` (tree-sitter helpers), `metrics.rs` and `symbol_table.rs` in place of
`context.rs`, `support/` and `engine/`:

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

- Rule keys are `<repository>:<key>` strings that resolve severity/type through the frozen catalog;
  analyzers never duplicate rule metadata.
- Parsing is tolerant everywhere: partial syntax trees are analyzed, broken files never abort a run,
  and parse errors emit no findings unless a catalog rule exists for them.
- Positions follow the SonarQube convention (1-based line, 0-based column); issues are sorted.
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

### Documented gaps

The uncovered keys require out-of-repository infrastructure or reflect deliberate
parser-fidelity limits; each is recorded as a skip note next to the nearest related
implementation:

- External deprecated-API database — `javascript:S1874`, `typescript:S1874`.
- Cross-file module resolution — `javascript:S6627`, `typescript:S4328`,
  `typescript:S6627`.
- TypeScript-checker-grade type semantics — `typescript:S4325`, `S6606`.
- Roslyn-grade type lattice / inheritance coupling graphs — `csharpsquid:S110`, `S1200`,
  `S1944`, `S3242`, `S3246`, `S4047`.
- Razor component surface (.razor files are not ingested) — `csharpsquid:S6802`.
- Production runtime configuration introspection — `python:S6786`.
- ASI reconstruction from a tolerant parse — `javascript:S1438`, `typescript:S1438`.

All 1,603 actionable implementations now have direct, repository-qualified test
evidence. The strict audit remains deliberately red because 17
infrastructure-classified rows are still parity gaps. Direct tests and
implementation markers do not prove SonarQube-equivalent behavior. See
[PARITY.md](PARITY.md) for the exact oracle contract and current failures.

The frozen Community C# base analyzer can certify 408 of 467 catalog rows.
Forty-two rows remain infrastructure gaps; 17 implemented commercial rules are
explicitly `enterprise-unverified` because Community cannot execute them. They
remain shipped and locally tested, but no Enterprise parity claim is made.

## Usage

```bash
cargo run -p hoonarqube-cli -- analyze <paths...>              # text report
cargo run -p hoonarqube-cli -- analyze --format sonar <paths>  # Generic Issue Import JSON
cargo run -p hoonarqube-cli -- fix <paths>                     # dry-run automatic fixes
cargo run -p hoonarqube-cli -- fix --diff <paths>              # preview unified diff
cargo run -p hoonarqube-cli -- fix --apply <paths>             # write and verify
cargo run -p hoonarqube-bench -- --iterations N                # throughput table
cargo run -p xtask -- catalog coverage                         # parity audit
```

### Automatic fixes

`fix` combines quick fixes attached to catalog findings with safe mechanical
repairs for trailing whitespace, missing final newlines, and leading tabs. It
never writes by default. Use `--diff` to inspect the projected rewrite and
`--apply` to write it. `--rule <prefix>` limits finding-backed fixes (repeatable
or comma-separated); mechanical repairs remain enabled.

Each multi-edit rule fix is atomic. If fixes overlap, deterministic earlier
fixes win and complete later fixes are skipped and reported. Apply mode rejects
a file changed since planning, then re-analyzes written content: targeted rule
counts must decrease by the number of applied fixes and no rule count may
increase. Failed verification returns a nonzero exit status.

Global `--json` keeps stdout as one JSON document, including requested diffs as
per-file `diff` fields instead of mixing human text into machine output. Current
finding-backed coverage starts with the syntax-checked `python:S1721` redundant-
parentheses remedy. See [QUICKFIX.md](QUICKFIX.md) for the parity inventory.

## Development

```bash
cargo test --workspace            # full suite
cargo run -q -p xtask -- catalog coverage --strict --allow-infra
python3 -m unittest discover -s tools/oracle -p 'test_*.py' -v
cargo clippy --workspace --all-targets   # zero-warning policy (pedantic)
cargo fmt --all --check
```

Conventions: one rule per file under `rules/`, its tests co-located in the same file; shared logic
in `support`/`engine`; explicit registries in `rules/mod.rs`; no lint suppressions.
