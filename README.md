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
| `hoonarqube-ir` | Findings IR: `Pos`, `Range`, `Issue`, `FileMetrics`, `FileReport` |
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

Audited by `cargo run -p xtask -- catalog coverage [--lang <id>] [--strict]`
against the frozen catalog:

| Language | Implemented | Infra gaps | Total | Actionable coverage |
|---|---|---|---|---|
| JavaScript | 403 | 3 | 406 | 100% |
| TypeScript | 406 | 6 | 412 | 100% |
| Python | 333 | 1 | 335 | 99.7% |
| C# | 460 | 7 | 467 | 100% |

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

Open gap (not infra): `python:S112` (`Exception`/`BaseException` should not be raised) is
not yet implemented; `catalog coverage --strict` reports it as the single actionable miss.

## Usage

```bash
cargo run -p hoonarqube-cli -- analyze <paths...>              # text report
cargo run -p hoonarqube-cli -- analyze --format sonar <paths>  # Generic Issue Import JSON
cargo run -p hoonarqube-cli -- fix <paths>                     # safe mechanical fixes
cargo run -p hoonarqube-bench -- --iterations N                # throughput table
cargo run -p xtask -- catalog coverage                         # parity audit
```

## Development

```bash
cargo test --workspace            # full suite
cargo clippy --workspace --all-targets   # zero-warning policy (pedantic)
cargo fmt --all --check
```

Conventions: one rule per file under `rules/`, its tests co-located in the same file; shared logic
in `support`/`engine`; explicit registries in `rules/mod.rs`; no lint suppressions.
