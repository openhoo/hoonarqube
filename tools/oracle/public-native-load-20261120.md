# Native scanner time and resource use on five public codebases

We timed the macOS arm64 release CLI from Hoonarqube commit `b8411407357d1eabf8d2bce59035d7343996e6ec`. Each input is the largest by physical lines in its language among the completed captures with identical native and reference file inventories in two corpus waves. The five scopes contain 662 files and 185,089 physical lines. Each of the 110 fresh scanner processes produced a successful, complete JSON report with exactly the same stdout and stderr bytes as the earlier integrated replay of that input.

| Pinned source scope | Files | Lines | Wall s p50 / p95 | User CPU s p50 / p95 | System CPU s p50 / p95 | Peak RSS MiB p50 / p95 |
|---|---:|---:|---:|---:|---:|---:|
| Clap Builder (Rust) | 56 | 28,701 | 30.030 / 30.404 | 89.085 / 89.709 | 0.279 / 0.430 | 71.4 / 72.3 |
| Trio (Python) | 78 | 25,588 | 0.233 / 0.260 | 0.959 / 1.004 | 0.020 / 0.025 | 57.8 / 58.3 |
| Rails Active Support (Ruby) | 281 | 29,681 | 0.086 / 0.091 | 0.346 / 0.354 | 0.045 / 0.053 | 51.0 / 52.2 |
| Apache Commons Lang (Java) | 215 | 88,301 | 0.226 / 0.250 | 1.270 / 1.296 | 0.045 / 0.057 | 49.7 / 50.6 |
| Yjs (JavaScript) | 32 | 12,818 | 0.065 / 0.069 | 0.172 / 0.175 | 0.010 / 0.012 | 32.7 / 33.7 |

On this machine, the Clap Builder scan took the longest. These measurements do not explain which analysis stage consumed the time. Different scopes have different rules, syntax and report sizes; line counts alone do not predict latency.

## Measurement boundary

- We ran two warm-ups and 20 measured scans per scope, one process at a time. Each round rotated which scope came first. The OS file cache stayed warm. The scanner used the original `analyze` arguments, JSON format, `sonar-parity` profile and exclusions from each capture, with default threading and no explicit scan cache. We did not build or install dependencies in the public projects.
- Wall time starts immediately before `posix_spawn` and ends after `wait4` reaps the CLI. It includes scanner startup, analysis, JSON serialization and writing the report. The harness opens output files first; parsing and hashing after the scan are outside the clock. It sends no request to a service or database.
- User and system CPU seconds are OS accounting from `wait4` for the waited process. Threads can run on several cores, so CPU time can exceed wall time. RSS is the Darwin `ru_maxrss` high-water mark returned for that process, in bytes (MiB in the table). It is neither a sum of simultaneous memory across processes nor an estimate of heap allocations, OS cache or service memory.
- p50 is the median of the 20 measured results; p95 is the 19th sorted result (nearest rank). The maximum and both warm-ups are available in the evidence. These are sample quantiles from a serial run, not a capacity test or a production latency target.
- Only source files present at the pinned upstream commits were available. Yjs reported `typescript: missing`, as in its integrated baseline; C# was inapplicable, and TypeScript was inapplicable for the other four inputs. The earlier Commons Lang reference capture declared Java release 8. Its native scanner invocation passes no Java classpath. The source pins, exclusions, reported contexts, inventory hashes, expected stdout and stderr appear in the [input contract](public-native-load-contract-20261120.json). A reference inventory hash pins the earlier capture; it is not a performance measurement of that scanner.

## Machine and competing work

The run took place on November 20, 2026, on a shared Apple M4 Max (16 logical CPUs, 48 GiB RAM, macOS 26.6.2, Darwin 25.6.0). The first and last in-run host probes were at 21:40:59 and 21:52:14 UTC. There was no CPU affinity or dedicated-host reservation. The starting gate waited for three consecutive readings below 300% background and 25% recognized build/service CPU.

Across 332 host observations, background CPU was 151.6% at p50, 435.3% at p95 and 1105.2% at maximum; 215/332 readings reached at least one core. Recognized build/service processes reached 25% in 30/332 readings and 100% in 7/332 (maximum 311.4%). These figures describe the contention during this series on this host.

The host monitor sampled rolling per-process `ps` CPU percentages roughly every two seconds; 100% represents one logical CPU. “Background” sums processes other than those named `hoonarqube`, so a second process with that name is also excluded. A separate CLI correctness check on two Rust files overlapped the window for about two seconds; its CPU is not in the background total. The build/service subset recognizes `rustc`, `cargo`, `clang`, `clang++`, `javac`, `tested-service` and `hoonarqube-service`. Short jobs between samples may be missed. All runs after the starting gate were retained, regardless of host contention.

The [four-Go service pilot](public-go-pipeline-timing-20261120.md) timed both products through persistence and readback. This series measures only the native scanner, on different projects. It does not extend the Go comparison to these languages or establish a SonarQube speed ratio, throughput or analyzer parity.

## Review or repeat

The [110 individual observations](public-native-load-samples-20261120.csv) are in execution order; rounds -2 and -1 are warm-ups, and 0 through 19 were measured. The [summary](public-native-load-timing-20261120.json) includes full precision, minima, maxima, host samples in aggregate and checksums of the compact observations and retained raw files. Full stdout, stderr, per-process observations and the host log stay in the run directory.

On macOS arm64 with Python 3.11 or newer, use the same release executable identified by SHA-256 in the contract. It records the compiler, its host, the Cargo command and the source tree; a rebuild with different bytes is a separate experiment. The following commands make detached, source-only checkouts in a new directory. Run them from the Hoonarqube repository root, set `NATIVE` to the release binary, and choose a new `OUTPUT` directory outside the sources.

```sh
SOURCES="$(mktemp -d)"
python3 - "$SOURCES" <<'PY'
import json, pathlib, subprocess, sys
rows = json.loads(pathlib.Path("tools/oracle/public-native-load-contract-20261120.json").read_text())
for name, row in rows["projects"].items():
    dest = pathlib.Path(sys.argv[1]) / name
    url = "https://github.com/" + row["repository"] + ".git"
    subprocess.run(["git", "clone", "--no-checkout", url, dest], check=True)
    subprocess.run(["git", "-C", dest, "-c", "core.hooksPath=/dev/null",
                    "checkout", "--detach", row["commit"]], check=True)
PY
python3 tools/oracle/public_native_load.py --sources "$SOURCES" --native "$NATIVE" \
  --output "$OUTPUT" --warmups 2 --rounds 20
```

The harness refuses a changed executable, a dirty checkout, changed output, an incomplete analysis, or a changed source inventory or context. It checks the first and last inventory for each project and both output digests on every invocation. Each process has a 240-second timeout. Any failure stops the series and leaves the attempt for inspection.
