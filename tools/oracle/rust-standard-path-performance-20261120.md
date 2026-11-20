# Rust scanner: avoiding impossible standard-library path searches

An ordinary method call such as `arg.configure()` and a scoped call such as `Builder::finish()` previously triggered searches for standard-library names. Resolving shadowed names walks from the call through its syntax-tree ancestors and checks bindings in each scope. Several rules repeated this work on the same calls. On the pre-change release, scanning Clap's `clap_builder/src/builder/command.rs` alone took about 30 seconds. Its full 56-file scope took about the same wall time in the [preceding native study](https://github.com/openhoo/hoonarqube/pull/978), where files were analyzed concurrently.

A symbolized optimized build on the same pinned source produced the same full Clap report as the reference release. In a seven-second macOS sample, `ts_node_child_iterator_next` and `ts_node_child_with_descendant` headed 7,682 and 2,721 collapsed thread samples. The stacks trace the lookups from `canonical_callable` and `is_transmute_function` through `standard_import_matches` into `standard_name_is_shadowed`. These are thread samples, not wall-time percentages. One branch on a single sampled worker shows where the repeated searches spend their time (counts are inclusive and cannot be added):

```text
1771 check_semantic_rust_rules                  lib.rs:5643
  1771 canonical_callable                      lib.rs:5893
    1765 standard_import_matches               lib.rs:4906
      1431 standard_name_is_shadowed           lib.rs:4955
        1239 ts_node_parent
           926 ts_node_child_with_descendant
             731 ts_node_child_with_descendant
               731 ts_node_child_iterator_next
```

An import alias in a qualified path replaces its prefix. It cannot change the last member. After checking exact paths, the resolver now skips searches for non-bare expressions whose last member cannot match any expected path (including expressions without a path separator). For bare identifiers, renamed and wildcard imports remain eligible; qualified candidates that pass the filter still undergo the full lexical check. A regression test exercises the two calls above through the public file analyzer: four shadow lookups before, zero after.

## Paired release measurements

Wall and user CPU columns are medians, in seconds. The ratio is the baseline wall median divided by the candidate wall median. Each row uses six runs per build after one separate warm-up. All 98 completed processes, including the warm-ups, produced exactly the expected stdout and stderr.

| Public input | Files | Wall before | Wall after | Median ratio | User CPU before / after |
|---|---:|---:|---:|---:|---:|
| clap | 56 | 30.123 | 2.001 | 15.06× | 89.271 / 8.166 |
| serde-json | 37 | 9.451 | 2.249 | 4.20× | 23.620 / 5.642 |
| rayon | 99 | 17.339 | 1.155 | 15.01× | 37.217 / 4.178 |
| bytes | 19 | 8.295 | 1.484 | 5.59× | 20.389 / 3.374 |
| log | 9 | 9.965 | 2.889 | 3.45× | 11.801 / 3.191 |
| ripgrep | 20 | 31.809 | 15.623 | 2.04× | 40.498 / 16.296 |
| clap-format | 1 | 0.430 | 0.106 | 4.07× | 0.427 / 0.102 |

The candidate was faster in 42 of the 42 individual measured pairs. The smallest paired ratio was 2.01× (ripgrep, round 2). Each input had three measured pairs with the baseline first and three with the candidate first.

The six repository inputs are all Rust scopes with complete, identical files and source bytes in the two captured corpus waves. The final input, `clap-format`, is the unchanged `clap_builder/src/error/format.rs` file from the pinned Clap tree. In an exploratory pass over every one of Clap's 56 files, it was the smallest by bytes among those that took over 0.35 s alone. That pass selected a short reproduction; it is not part of the paired measurements.

Both timed executables used Rust 1.96.0, the same locked dependencies and the normal release profile (thin LTO, stripped symbols). No public project was built. Every input had the same arguments and pinned source bytes for both builds. The expected full report and empty stderr for each repository came from its earlier integrated replay; for the single-file case the expected bytes came from its initial standalone scan. The table covers a shared Apple M4 Max (16 logical CPUs, 48 GiB, macOS 26.6.2). Across 461 host probes, non-scanner CPU was 191.3% at p50, 887.8% at p95 and 1206.3% at maximum (100% is one logical core). Recognized builds and services reached one core in 76/461 probes. These serial paired observations support a scanner comparison on the recorded inputs and host, not an SLA or a SonarQube comparison.

The [portable receipt](rust-standard-path-performance-20261120.json) contains the source, executable and output hashes, scanner arguments, all 98 individual wall/user/system/peak-RSS records, input order, and host-load information. Per-run host probe counts show when recognized builds or services reached one logical core; short scans can finish between probes. RSS is the Darwin `wait4` high-water mark of the waited CLI; it does not add the memory of simultaneous processes. We retained the complete reports and local sampling trace outside Git.

## Repeat

Use separate Hoonarqube checkouts for the receipt's parent commit and this change; in each run `cargo build --locked --offline --release -p hoonarqube-cli --bin hoonarqube` and retain each resulting executable. If the Cargo cache is empty, run `cargo fetch --locked` for Hoonarqube before building offline. Clone each upstream repository in the receipt into its own directory and check out its exact commit, with no local changes or generated dependencies. The `clap-format` input uses the same Clap checkout. Rebuilding from source on a different system can produce different executable hashes; record them as a new experiment.

On macOS, use the [published macOS harness](https://github.com/openhoo/hoonarqube/blob/7b2d4975f4c4bb28c64d88e85c0308b4941b91da/tools/oracle/public_native_load.py) with Python 3.11 or newer. Its `timed_scan(binary, argv, cwd, folder, 240)` takes absolute paths and a new output directory for each invocation. Use the ordered input arguments and build sequence from the receipt; round -1 is the excluded warm-up. After each run, compare SHA-256 on both output streams, retain the four numeric fields, and compute medians using rounds 0–5. Validation runs outside the timed interval.

For example, use a fresh output directory and set `PYTHONPATH` to `tools/oracle` in a checkout of the linked harness commit. Place the two binaries in `BIN_DIR` as `baseline-cli` and `candidate-cli`; `SOURCES` should contain the six input directories named in the receipt.

```python
import hashlib, json, os, statistics
from collections import defaultdict
from pathlib import Path
from public_native_load import timed_scan

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

receipt = json.loads(Path(os.environ["RECEIPT"]).read_bytes())
binaries, sources, out = [Path(os.environ[k]).resolve() for k in ("BIN_DIR", "SOURCES", "OUT")]
out.mkdir(exist_ok=False)
walls = defaultdict(list)
for name, run, build, *_ in receipt["observations"]:
    row = receipt["inputs"][name]
    root = sources / ("clap" if name == "clap-format" else name)
    dest = out / f"{run}-{name}-{build}"
    obs = timed_scan(binaries / f"{build}-cli", row["argv"], root, dest, 240)
    for stream in ("stdout", "stderr"):
        assert digest(dest / stream) == row[f"{stream}_sha256"], (name, run, build, stream)
    (dest / "observation.json").write_text(json.dumps(obs) + "\n")
    if run >= 0:
        walls[name, build].append(obs["wall_s"])
for key, values in walls.items():
    print(*key, statistics.median(values))
```
