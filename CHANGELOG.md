# Changelog

## 0.6.0 (2026-09-08)

### Features

- **cli:** add native GitLab Code Quality reports (a47fcf7)

## 0.5.1 (2026-09-08)

### Performance

- **hoonarqube:** optimize duplication coverage and benchmark scaling (3dd0d68)

## 0.5.0 (2026-09-08)

### Features

- **hoonarqube:** add project metrics and duplicate-code detection (#27) (a515757)

### Bug Fixes

- correct analyzer data flow and oracle validation (#24) (d305104)

## 0.4.2 (2026-09-04)

### Performance

- **hoonarqube:** parallelize file analysis (#22) (48d89b5)

### Other Changes

- **release:** add immutable asset recovery (#21) (82a1f39)

## 0.4.1 (2026-09-04)

### Bug Fixes

- **hoonarqube:** harden CodeQL parity and validation (#19) (50ca924)

## 0.4.0 (2026-09-04)

### Features

- **github-quality:** add CodeQL analysis profile (#15) (90357d9)

### Bug Fixes

- **hoonarqube:** align GitHub CodeQL parity (68058d3)
- **release:** repair version synchronization (4b01d0a)

## Unreleased

### Performance

- Add opt-in `analyze --cache-dir` content-addressed caching of successful
  per-file findings and source facts while rebuilding complete project metrics
  and cross-file duplication on every run.
- Add optional cache-directory inputs to both GitHub Actions integrations and
  document trusted pipeline cache restore/save.

### Features

- **analysis:** add versioned project reports with consistent source size,
  explicit source/test/generated/vendor/excluded scope, and incomplete-scan
  diagnostics.
- **duplication:** detect repeated code within and across files in all eight
  supported language families; report exact byte/line locations, unique
  duplicated lines and blocks, affected files, and weighted density.
- **cli:** expose classification/exclusion globs and duplication thresholds;
  keep Sonar/SARIF issue schemas unchanged and exit 2 for incomplete analysis.

### Bug Fixes

- **github-quality:** align conservative CodeQL detectors, scope and dataflow
  semantics, registry coverage, Sonar/SARIF locations, path handling, and
  action gating; add adversarial regression coverage across every analyzer
- **release:** synchronize `xtask` path dependencies during version bumps while
  keeping CI dogfood pinned to an already-published binary

### Performance

- **analyzers:** parallelize file analysis across available CPUs with
  deterministic output and serial fallback; remove redundant parsing, semantic
  indexing, and tree walks across every language while reducing each
  JavaScript/TypeScript analyzer stack from 128 MiB to 16 MiB

- **ci:** shard quality tests, pin dogfood analysis to the released binary,
  replace the 2.2 GB mixed target cache with dependency-aware Rust caching,
  and remove a duplicate full-repository analysis pass
- **rust:** keep the deep macro-token regression without making the normal
  suite an extreme third-party parser stress benchmark

## 0.3.1 (2026-09-03)

### Bug Fixes

- **analyzers:** harden language semantics (0074f69)

### Other Changes

- **ci:** update Hoostack tool pins (9e13ab1)
- **ci:** pin HooNeedsUpdates to v0.3.0 (#12) (887c2a9)

## 0.3.0 (2026-09-01)

### Features

- **analyzer:** add native quality profiles (#7) (d87bb03)

### Bug Fixes

- **release:** recover protected branch finalization (#9) (98c0975)

## 0.2.4 (2026-08-31)

### Bug Fixes

- align Hoostack policy and release supply chain (#4) (e53f772)
- **release:** honor protected main branch (d59fb05)

## 0.2.3 (2026-08-30)

### Bug Fixes

- **security:** harden oracle scanner workspace (#3) (c3a90d3)

## 0.2.2 (2026-08-30)

### Bug Fixes

- **release:** upload only release files (86333e4)

### Other Changes

- standardize Hoostack dogfood (1f0a8ae)

## 0.2.1 (2026-08-30)

### Bug Fixes

- harden analyzers and clear code smells (94560de)
- **cli:** make Hoostack dogfood reliable (b00cbc5)

### Other Changes

- use released Hoostack actions (75fcca7)
- test pull request head commits (cb93963)

## 0.2.0 (2026-08-29)

- Harden analyzer behavior, verified quick fixes, parity evidence, and oracle failure handling.

## 0.1.0 (2026-08-28)

- Publish initial frozen-catalog analyzers for Python, JavaScript/TypeScript, C#, Go, and Rust.
