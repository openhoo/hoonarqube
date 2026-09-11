# Performance and footprint qualification

The current review compares a locally rebuilt, immutable v0.8.2 baseline
(`5ea3135`) with the integrated performance PR #25 on the same host/toolchain.
The older `d305104` (0.4.2) versus `f032103` comparison is retained in explicitly
historical sections below; those numbers are not current-release claims.

## Current qualification — 2026-09-11

Both binaries were built locally with Rust 1.96.0, without `RUSTFLAGS` or
release-profile environment overrides. Measurements used Python 3.14.7 on
Linux x86_64, two warmups and six measured runs per binary, balanced AB/BA
order, and a 300-second per-run timeout. No builds or tests ran concurrently.

The generated mixed workload contains 4,641 complete files. Every measured
profile/export combination below passed exit, complete-output, full
stdout/stderr equality, input-fingerprint, and executable-hash checks.
Each RSS median has six usable samples per binary, above the supervisor floor.
Times are CLI elapsed medians; RSS columns are median per-run peaks in KiB.

| Workload / profile / export | CPUs | Before ms | After ms | Speedup | RSS before / after KiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Mixed / default / JSON | 0-31 | 227.55 | 197.51 | 1.15x | 142156 / 135346 |
| Mixed / GitHub Code Quality / SARIF | 0-31 | 203.19 | 130.37 | 1.56x | 97338 / 78890 |
| Tiny JS / default / JSON | 0 | 163.22 | 107.78 | 1.51x | 27586 / 27928 |
| Ruby / default / JSON | 0 | 61.33 | 26.69 | 2.30x | 19066 / 18514 |
| Array-heavy Rust / default / JSON | 0 | 66.96 | 40.61 | 1.65x | 16620 / 16626 |
| Report-heavy Python / default / Sonar | 0 | 645.51 | 511.92 | 1.26x | 439096 / 274934 |
| Mixed / recommended / JSON | 0-31 | 255.48 | 224.25 | 1.14x | 142674 / 135230 |
| Mixed / extended / JSON | 0-31 | 264.68 | 229.17 | 1.15x | 142202 / 135182 |
| Mixed / strict / JSON | 0-31 | 255.22 | 219.53 | 1.16x | 141272 / 134704 |
| Mixed / default / GitLab Code Quality | 0-31 | 395.80 | 361.77 | 1.09x | 328210 / 321690 |

The executable shrank from 38,538,856 to 35,117,984 bytes (8.9%). Report-heavy
Sonar peak RSS fell 37.4%; tiny-JS and array-heavy Rust RSS did not improve.
These are workload-specific local measurements, not a universal speedup or a
published-release-archive size claim.

Binary SHA-256:

```text
baseline  9ada87745b297fd9f749b3340ff35c62198a3563033a16c5dea9f581858e965d
candidate cfec1f1ee07932118fbd70411042f85d33ba267016cafd34c0acc925404e39f1
```

Correctness qualification passed 3,603 Rust tests, 136 oracle-harness tests,
26 script tests, all 16 local qualification steps, dependency policy, and the
pinned v0.3.1 `rust:S3776` gate with zero findings. Seven CLI regression groups
passed, including 640 parser/profile cases, 100 randomized duplication cases,
and compiler-backed quick-fix controls. The one-CPU CLI matrix also passed.
Four real-corpus exports/profiles (3,432 reported files) retained identical
stdout, stderr, and exit codes. That corpus intentionally remains incomplete
with exit 2; it was a correctness comparison, not a successful-run benchmark.

Harness regressions cover timeout and interruption cleanup of TERM-ignoring
children, decoder recursion errors, and RSS independence from a large parent
heap. Real harness probes also checked differing command exits, native
signals, failed launches, and unavailable RSS at the inherited floor.

## Historical changes in the original PR

The original PR reported these implementation changes:

- GitHub Code Quality dispatch now runs the selected queries directly. It
  previously ran every Sonar rule, discarded those findings, and parsed again.
  Python, C#, Go, and Java share their parse with metric collection. JS/TS
  retains separate path-sensitive metric parsing and strict query parsing
  because their grammars differ. Both run on one guarded worker stack.
- Rust files in that profile compute metrics without running Rust rules.
- Ruby's ordinary report computes lexical metrics directly, avoiding unused
  syntax, scope, CFG, and dataflow construction. Its lexical scanner counts
  rows without allocating sets. Malformed Ruby quality input exits before
  constructing flow facts.
- Single-CPU JS/TS analysis reuses one guarded worker instead of starting a
  new parser thread for each file and profile pass. Parallel warning/report
  ordering and worker-start fallback behavior remain covered by tests.
- Rust's macro-array fallback indexes bindings and accesses once with cached
  regexes. It no longer compiles two regexes and scans the remaining source
  for every array. Shadowing, Unicode boundaries, and recovered keyword
  bindings retain regression coverage.
- Sonar and SARIF assembly move completed JSON trees into their documents
  instead of cloning every finding. Sonar collection borrows paths and keys.
  Serialization still completes before stdout is written, preserving the
  no-partial-document behavior on serialization errors.
- The generic dataflow solver compares the previous fact by reference,
  avoiding a full lattice clone on every block visit.
- Release builds use thin LTO and strip symbols. Panic unwinding remains
  enabled. No dependencies or parser versions changed in that historical
  comparison.

## Historical measurements

The old mixed-corpus run contained 4,671 files: 922 C#, 72 Go, 802 JavaScript,
662 Python, 1,405 Rust, and 808 TypeScript files. It combined the six checked-in
Sonar fixture projects, `tools/oracle/fixtures`, `crates`, and `xtask` from
that historical checkout. Synthetic workloads were generated by
[`scripts/benchmark_fixtures.py`](scripts/benchmark_fixtures.py).

The historical harness used one warmup and five measured runs per build. Its
pair order was alternated but five runs cannot balance AB and BA order exactly;
the current harness requires even counts and records every pair order. Each old
run was required to succeed, emit parseable JSON, and match stdout/stderr bytes.

The table is retained for provenance only:

| Workload | CPUs | Before (d305104) | After (f032103) | Speedup |
|---|---:|---:|---:|---:|
| Mixed corpus, default JSON | 8 | 6.897 s | 6.808 s | 1.01× |
| Mixed corpus, GitHub SARIF | 8 | 6.869 s | 0.445 s | 15.43× |
| Mixed corpus, Sonar import | 8 | 7.003 s | 6.885 s | 1.02× |
| 300 Rust array declarations | 1 | 0.141 s | 0.084 s | 1.68× |
| 64 Ruby files, 30 methods each | 1 | 0.086 s | 0.010 s | 9.00× |
| 4,096 tiny JavaScript files | 1 | 0.205 s | 0.109 s | 1.88× |
| 400 Python files with many findings, Sonar import | 1 | 0.739 s | 0.535 s | 1.38× |

The old default mixed-corpus throughput was effectively unchanged. The
reported improvements were concentrated in profile selection, Ruby metrics,
Rust arrays, worker reuse, and report construction. They were not general
repository speedup claims and do not predict the v0.8.2-parent candidate. The
workstation also had unrelated background workloads.

The old six-language in-memory benchmark was run three times per build at 100
iterations per language. Finding totals matched in every run. C# remained the
slowest synthetic analyzer: median throughput increased from 7.10 to 7.30
files/s. This is historical-only evidence, not a current profile benchmark.

| Footprint (historical only) | Before (d305104) | After (f032103) | Change |
|---|---:|---:|---:|
| Release executable | 28,391,328 B | 25,806,400 B | −9.1% |
| Executable compressed with gzip level 6 | 6,802,105 B | 6,424,223 B | −5.6% |
| Mixed GitHub SARIF median peak RSS | 69,060 KiB | 56,260 KiB | −18.5% |
| Mixed Sonar import median peak RSS | 138,308 KiB | 109,820 KiB | −20.6% |
| Report-heavy Sonar import median peak RSS | 421,372 KiB | 255,896 KiB | −39.3% |
| Mixed default JSON median peak RSS | 74,604 KiB | 77,124 KiB | +3.4% |

The gzip row measured the executable payload, not a published release archive.
Thin LTO increased linking work; no clean-build-time improvement was claimed.
The old local `target` inventory was 65 GB, dominated by accumulated debug
dependencies, incremental builds, and coverage artifacts. That was neither a
clean-build measurement nor shipped footprint. Existing transitive duplicates
were accepted by `cargo deny` with warnings.

## Historical correctness evidence

For the original PR only, all four complete-corpus output documents and their
warnings were byte-identical to its pristine baseline. The default JSON
included 13,548 findings and every file's metrics. Strict JSON included 13,546
findings after its existing deduplication. The equality check covered full
locations, messages, fixes, and flows, not just finding counts.

| Output | SHA-256, identical before and after |
|---|---|
| Default JSON | `5479551ec35562ef726aee4eeb3513caa2d1366e07febf937545607251d4e17e` |
| Strict JSON | `b0e6ccf725fa8c9a6ad7e417a9d3c13a634bf4af6769013991d2316fa1a916ac` |
| Sonar import | `8fbf26f92275620de9f8a101ddfc1c692cdc1c3f66d108d16f6da7eeb89c2fc8` |
| GitHub SARIF | `8bbfcda63a8e6a26fd3a937e10db62559de68ea587bc6f04c27ca41e826eae2f` |

Additional historical controls compared strict quality results and tolerant
metrics for all eight languages, including empty files, malformed input,
Unicode, CRLF, CommonJS, TypeScript assertions, JSX/TSX, declaration files,
and uppercase extensions. Worker counts 0, 1, 2, and 4 preserved complete
results and warning order. An 80-file generated Rust control corpus also
produced identical output before and after.

## Historical validation (original PR only)

The original run recorded 3,176 workspace tests, two doctests, 89 Python
oracle-harness tests, 15 release/shell-script tests, strict workspace Clippy,
rustdoc with warnings denied, formatting, catalog integrity/coverage, GitHub
registry coverage, release-version synchronization, and dependency policy.
Those counts are not a qualification of the rebased candidate. The catalog's
existing infrastructure and implementation-coverage boundaries remained
explicit.

## Reproduce current qualification

Build both binaries once, from separate clean/immutable trees, before running
the harness. Record each source commit, toolchain, build profile, executable
SHA-256, and relevant environment. The baseline for this qualification is
origin/main v0.8.2 at `5ea3135`; the candidate must be the exact integrated
source under review. Do not build, test, or mutate either tree during timed
runs. Run both binaries against the same unchanged fixture tree. Each
`--output` must be a new path outside analyzed inputs; the harness refuses to
overwrite an existing result or benchmark binary.

The fixture generator refuses to reuse an existing root. It also varies
identifiers/literals in the larger repeated workloads so normal project
metrics and duplication stay within their bounded completeness budget; no
`--duplication-exclude` or other analysis gate is used:

```bash
PROOF=/tmp/hoonarqube-perf-review-proof-_hehqz01
FIXTURE_PARENT="$(mktemp -d /tmp/hoonarqube-perf-fixtures.XXXXXX)"
FIXTURES="$FIXTURE_PARENT/fixtures"
python3 scripts/benchmark_fixtures.py "$FIXTURES"
BASELINE="$PROOF/baseline-v0.8.2"
CANDIDATE=/path/to/hoonarqube-candidate
CHECKOUT="$FIXTURES"
```

`CHECKOUT` deliberately points at the generated fixture root itself. GitHub
SARIF rejects analyzed paths outside `--cwd`; do not point `--cwd` at a parent
checkout while passing the fixture root as a sibling absolute path.

The current harness performs two balanced warmups and six measured runs per
binary. Each pair is AB then BA (or BA then AB), so even counts balance first
and second positions; the recorded `comparisons[].order` is the audit trail.
Omitting `--cpus` preserves every CPU in the current process affinity. Passing
`--cpus 1` pins both children to the first allowed CPU and is the one-CPU
control. The selected affinity is recorded in each result's `cpus` field;
do not infer it from the host or shell outside that evidence.

Run the default profile with the host's current affinity:

```bash
python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --warmups 2 --runs 6 --timeout 300 \
  --profile sonar-parity --format json \
  --output "$PROOF/fresh-sonar-json-default-affinity.json" \
  -- "$FIXTURES"
```

Run the same default profile as an explicit one-CPU control:

```bash
python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --cpus 1 --warmups 2 --runs 6 --timeout 300 \
  --profile sonar-parity --format json \
  --output "$PROOF/fresh-sonar-json-one-cpu.json" \
  -- "$FIXTURES"
```

Repeat with every supported profile/output contract needed for the claim.
At minimum, retain separate result files for the cumulative native profiles,
Sonar import, GitLab Code Quality, and GitHub SARIF:

```bash
python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --cpus 1 --warmups 2 --runs 6 --timeout 300 \
  --profile recommended --format json \
  --output "$PROOF/fresh-recommended.json" \
  -- "$FIXTURES"

python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --cpus 1 --warmups 2 --runs 6 --timeout 300 \
  --profile extended --format json \
  --output "$PROOF/fresh-extended.json" \
  -- "$FIXTURES"

python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --cpus 1 --warmups 2 --runs 6 --timeout 300 \
  --profile strict --format json \
  --output "$PROOF/fresh-strict.json" \
  -- "$FIXTURES"

python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --cpus 1 --warmups 2 --runs 6 --timeout 300 \
  --profile sonar-parity --format sonar \
  --output "$PROOF/fresh-sonar-import.json" \
  -- "$FIXTURES"

python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --cpus 1 --warmups 2 --runs 6 --timeout 300 \
  --profile sonar-parity --format gitlab-codequality \
  --output "$PROOF/fresh-gitlab-codequality.json" \
  -- "$FIXTURES"

python3 scripts/benchmark_cli.py \
  --before "$BASELINE" --after "$CANDIDATE" \
  --cwd "$CHECKOUT" --cpus 1 --warmups 2 --runs 6 --timeout 300 \
  --profile github-code-quality --format sarif \
  --output "$PROOF/fresh-github-sarif.json" \
  -- "$FIXTURES"
```

A result is usable only when every warmup and measured command exits 0, every
machine-readable stdout is one complete strict JSON document, before/after
exit outcomes match, stdout and stderr byte streams are identical and stable,
the input fingerprint is unchanged, and both executable hashes remain fixed.
The harness writes JSON evidence even for a failed launch, nonzero exit,
signal, malformed output, input mutation, or timeout. Timeouts send SIGTERM to
the child process group, wait a one-second grace period, then send SIGKILL and
reap the child; the result records the command, exit code/signal, timeout flag,
complete stdout/stderr hashes and sizes, plus a bounded stderr preview.

A fresh minimal Python supervisor measures the actual CLI child with `wait4`.
Successful elapsed/CPU samples exclude supervisor startup, output validation,
input-fingerprint scans, and result serialization. These operations still
consume host resources, so run measurements without concurrent builds/tests.

Linux `ru_maxrss` can inherit a launcher's pre-exec heap, including when using
`posix_spawn`. The supervisor records its own fresh post-spawn `VmHWM` floor.
`peak_rss_kib` is available only when the child's raw peak exceeds that floor;
otherwise it is `null`, not zero. Raw peaks and floors remain in each sample.
RSS is not a concurrent process-tree total or an allocation attribution.
Summaries report the number of usable `rss_samples`; nullable RSS is not
evidence of a memory reduction.

Summaries use only successful measured rows whose input fingerprint stayed
equal to the initial one. Failed or mutated-input rows remain as evidence but
never enter medians.

The harness validates JSON formats (`json`, `sonar`, `gitlab-codequality`, and
`sarif`) to EOF and rejects non-standard constants. Text output is compared as
complete bytes but is not parsed as JSON. It compares the full SHA-256 digest
and byte count rather than a prefix, while the stderr preview is intentionally
bounded for diagnostics. The profile/format combinations are still subject to
the CLI's own compatibility checks; an invalid combination is evidence of an
invalid benchmark, not a performance result.

Fresh measurements need to report the exact source/binary hashes, selected CPU
affinity, profile and format, warmup/run/timeout settings, all completeness and
equivalence flags, medians and maxima for elapsed time/CPU time/RSS, and any
failed rows. Do not infer a clean-build-time, release-archive-size, SonarQube
parity, or general repository speedup claim from these process benchmarks.
