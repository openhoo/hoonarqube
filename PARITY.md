# SonarQube Parity Contract and Evidence

## Claim boundary

Hoonarqube ships the frozen 1,741-rule catalog:

- C#: 467.
- JavaScript: 406.
- TypeScript: 412.
- Python: 335.
- Go: 36.
- Rust: 85.

Seventeen C# rules are owned by SonarQube's Enterprise analyzer. Hoonarqube
keeps their implementations, fixtures, and local tests, but the Community
oracle cannot certify their upstream behavior. These rules carry the explicit
`enterprise-unverified` classification. They must pass local bad/good controls,
but routine Community gates report them separately instead of requiring a
commercial license. They are never counted as Community passes.

The remaining rule records carry `community-base`. Development and Community
oracle runs need no commercial license. Full SonarQube parity cannot be claimed
without valid Enterprise oracle evidence for the 17 commercial rules.

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

Enterprise-unverified rules still require local evidence. If Hoonarqube misses
their bad fixture or fires on their good control, the result is `OURS_MISS` or
`GOOD_FIRE`, not `ENTERPRISE_UNVERIFIED`.

Oracle artifacts use schema version 2 and retain complete messages/ranges.
Legacy line-only artifacts are rejected. `--quick` validates cached artifacts;
a full run refreshes scanner results.

## Current evidence — 2026-08-28

Current state is **not full parity**.

- Coverage audit finds direct repository tests for all 1,724 actionable
  implementations: 460 C#, 403 JavaScript, 406 TypeScript, 334 Python,
  36 Go, and 85 Rust.
  Seventeen additional rules remain `INFRA`; strict coverage exits 1.
- Go's current Community oracle has 36 exact passes. Rust has 80 exact passes
  and five upstream-unverified rows (`S1858`, `S3723`, `S3807`, `S4275`,
  `S7450`); all 85 Rust bad/good fixture contracts pass locally.
- Forty-two oracle/import harness tests pass, including fail-closed Rust Clippy
  report generation and upstream-unverified semantics.
- Seventeen Enterprise C# rules remain implemented and locally tested. Their
  exact keys and analyzer ownership are integrity-checked in
  `catalog/community-artifact-resolution.json`.
- Community C# direct-oracle evidence has 408 exact passes, zero observed
  mismatches, 42 infrastructure gaps, and 17 Enterprise-unverified rows.
- Commercial analyzer execution is not part of routine development or CI.
  Enterprise parity for those 17 rows remains intentionally unverified.
- Expectation manifests cover all 1,741 catalog keys. Tracked corpus contains
  3,436 language source files, including 72 Go and 170 Rust bad/good fixtures.

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -q -p xtask -- catalog audit --require-pages-complete
cargo run -q -p xtask -- catalog coverage --strict --allow-infra
PYTHONPATH=tools/oracle python3 -m unittest discover -s tools/oracle -p 'test_*.py' -v
python3 tools/oracle/csharp_direct_oracle.py \
  --analyzer /path/to/SonarAnalyzer.CSharp.dll \
  --result .oracle/sonar/results/oracle-cs.community-base-direct.sq.json
SONAR_ORACLE_RESULT_TAG=community-base-direct \
  python3 tools/oracle/parity_suite.py --project oracle-cs --quick
python3 tools/oracle/parity_suite.py \
  --project oracle-go --project oracle-rust
```

A full Community server refresh requires `SONAR_DOTNET_SCANNER` and a .NET 10
SDK for C#. Generic scans fall back to Podman; Rust fallback builds the tracked
scanner image and mounts the local Rustup toolchain so SonarQube runs Clippy
itself. Token remains outside repository in
`.oracle/sonar/token` or `SONAR_ORACLE_TOKEN`.

GitHub workflow runs reproducible local gates. Routine Community certification
can be green with explicit unverified rows; exact full parity remains unclaimed
while Enterprise, upstream, or infrastructure gaps exist.
