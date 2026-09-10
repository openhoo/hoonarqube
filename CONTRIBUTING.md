# Contributing

Open an issue before changing rule identity, analyzer semantics, catalog
evidence, fixes, or oracle contracts. Small fixes may go directly to a pull
request.

## Development

Use the repository Rust toolchain and Python 3.
The full workspace test suite also requires the .NET 10 SDK (CI uses 10.0.111).
The compiler-backed C# regression restores and builds isolated fixture projects.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
python3 -m unittest discover -s tools/oracle -p 'test_*.py' -v
```

Analyzer changes need bad and clean controls. Parity claims need normalized
rule, file, message, and range evidence from the documented oracle; test counts
alone are insufficient.

Commits use Conventional Commits. Pull requests must explain compatibility,
false-positive, security, and oracle impact. Maintainers squash-merge using the
Conventional Commit pull request title. Catalog and lockfile changes must
accompany their provenance.
