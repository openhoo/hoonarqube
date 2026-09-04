# Changelog

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

### Bug Fixes

- **github-quality:** align conservative CodeQL detectors, scope and dataflow
  semantics, registry coverage, Sonar/SARIF locations, path handling, and
  action gating; add adversarial regression coverage across every analyzer
- **release:** synchronize `xtask` path dependencies during version bumps while
  keeping CI dogfood pinned to an already-published binary

### Performance

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
