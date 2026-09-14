# Changelog

## 0.9.0 (2026-09-14)

### Features

- **jsts:** add S7719, S7722, S7723, S7724, S7726 detectors for pinned anchors (#308) (dad91fe)

### Bug Fixes

- **javascript:** prevent SQL alias resolution stack overflows (#254) (1f1a21f)
- **csharp:** correct field visibility and readonly diagnostics (#256) (bb841c7)
- **go:** resolve receiver, flow, tag, and literal rule boundaries (#257) (7c7cdcc)
- **oracle:** reject non-hex repository revisions (#258) (0f843d1)
- **actions:** root nested-cwd reports and SARIF URIs (#141, #142) (#261) (8cbba3d)
- **agents:** bound issue work and persist verified handoffs (#263) (1645a6f)
- **assessment:** validate OpenCover hashes by file UID (#265) (e4846f0)
- **java:** preserve qualified constants interface identity (#266) (22d3f21)
- **rust:** resolve Rust rule-boundary defects and preserve typed trait identity (#262) (f654284)
- **python:** resolve imported IO exception ancestry (#267) (365cda8)
- **typescript:** detect safe object nullish alternatives (#268) (4ba2b63)
- **csharp:** preserve literal types when removing casts (#269) (0e437f8)
- **typescript:** reject unsafe nullish references and falsy BigInt (#271) (45d60b3)
- **assessment:** preserve baseline completeness and empty counts (#270) (29bc547)
- **java:** bind Javadoc parameter tags precisely (#273) (6cfef39)
- **python:** preserve comment and quickfix semantics (#272) (c67e91f)
- **csharp:** preserve live code when removing inline comments (#274) (14580cd)
- **jsts:** refuse symlinked helper writes and report missing compiler references (#275) (9df4ded)
- **export:** align Sonar and assessment lines with ECMAScript terminators (#276) (4e3cfcf)
- **python:** exclude docstrings from S1313/S5332 and accept tuple percent-formatting in S5607 (#278) (d9113bc)
- **java:** compose nested signature units structurally (#277) (b520c9b)
- **csharp:** preserve adjacent code and type identity in quickfix removals (#279) (13e9d6a)
- **python:** model definition contexts for S5720 and S5722 (#280) (5dcd9f2)
- **jsts:** refuse unsafe S1125 constant folds and group S1940 inversions (#281) (5ec2115)
- **ruby:** tie uninitialized-receiver guard reasoning to the receiver binding (#282) (123cd87)
- **csharp:** score static locals separately and pair hidden base methods by signature (#284) (28a4ab1)
- **jsts:** resolve alias provenance and nested-chain identities for S6571, S1523, and S1871 (#285) (11a565d)
- **python:** gate S6795 on real aliases and honor S905 reportOnStrings (#283) (2bc86df)
- **csharp:** exempt initializers, interface signatures, and increment reads (#288) (c0f1000)
- **ruby:** stop receiver, join, and indexed-key local-flow false positives (#286) (d71ecd0)
- **python:** complete shared traversal and rebinding events for S1523 (#289) (9609c2b)
- **jsts:** close regex-literal and proto ownership false negatives (#290) (60ed6fe)
- **java:** treat enum constant bodies as distinct declaring types (#291) (be65a73)
- **metrics:** normalize both sides of new-code inventory joins (#292) (e416e87)
- **python:** close store, unused-name, and complexity false negatives (#293) (a38bb5b)
- **csharp:** resolve S6966 receivers, S1939 arity, partial shadows, and coalescing writes (#294) (f9b88f5)
- **cli:** enforce the source-size bound before reading whole sources (#295) (608fca4)
- **jsts:** parse TypeScript variance modifiers for complete source facts (#296) (13cfad7)
- **python:** report aliased typing forms, parameter shadows, and comment-insensitive duplication (#298) (4f38559)
- **jsts:** parse JSX natively, scope census, honor labels, report branch dead stores (#301) (8bc03c4)
- **python:** repair module scope, override, complexity, and literal rules (#300) (e5293f1)
- **python:** propagate S5797 local constants and accept tab escapes in S5856 classes (#303) (9c6567b)
- **jsts:** report S905 member reads, S6582 negated-OR guards, S4138 indexed loops, S6557 indexes (#304) (d599f3a)
- **jsts:** report S6666 nonliteral apply arrays and S2486 multi-statement catches (#252, #253) (#305) (50fabbb)

### Performance

- **hoonarqube:** reduce profile runtime and report footprint (3b3c642)

### Other Changes

- integrate agent issue workflow (#235) (6c274a2)
- **hoonarqube:** require PR templates and regression coverage (#255) (3b1b1fa)
- **actions:** fix immutable action revision (#264) (23ac99e)
- **security:** document quality-only GitHub Code Quality boundary (#148, #149, #175) (#306) (e531483)

## 0.8.2 (2026-09-11)

### Bug Fixes

- **hoonarqube:** harden analysis boundaries and quick fixes (e7add58)

## 0.8.1 (2026-09-10)

### Bug Fixes

- **hoonarqube:** qualify remaining parity and guarded fixes (e71a7e6)

## 0.8.0 (2026-09-10)

### Features

- **hoonarqube:** complete analysis capabilities and evidence boundaries (d6048e6)

## 0.7.1 (2026-09-09)

### Bug Fixes

- **hoonarqube:** correct real-project analyzer findings (#84) (cf6a668)

## 0.7.0 (2026-09-08)

### Features

- **cli:** cache unchanged file analysis (#33) (036baa2)

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
