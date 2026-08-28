//! Multi-language throughput benchmark for the hoonarqube analyzers.
//!
//! Builds one deterministic synthetic fixture per language in memory,
//! analyzes it for `--iterations` runs, and prints files/s, MB/s and total
//! findings so analyzer regressions surface as throughput deltas.

use std::env;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use hoonarqube_csharp::{AnalyzerOptions as CsharpOptions, CsLanguage};
use hoonarqube_go::AnalyzerOptions as GoOptions;
use hoonarqube_jsts::{AnalyzerOptions as JstsOptions, JstsLanguage};
use hoonarqube_python::AnalyzerOptions as PythonOptions;
use hoonarqube_rust::AnalyzerOptions as RustOptions;

/// Iterations used when `--iterations` is absent.
const DEFAULT_ITERATIONS: u32 = 20;

/// Bytes per reported MB (1 MiB).
const BYTES_PER_MB: f64 = 1024.0 * 1024.0;

/// One-nanosecond floor keeping throughput finite on instant runs.
const MIN_SECONDS: f64 = 1.0 / 1_000_000_000.0;

/// One seeded source-fixture generator (test-only: names the generator tables).
#[cfg(test)]
type FixtureGenerator = fn(&mut Rng) -> String;

/// Short usage text printed for malformed command lines.
const USAGE: &str = "usage: hoonarqube-bench [--iterations N]";

/// Loss-enough widening for throughput math; benchmark counts stay tiny.
#[must_use]
fn to_f64(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

/// Loss-enough widening of an issue count.
#[must_use]
fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Tiny splitmix64 generator; enough entropy for synthetic fixtures.
struct Rng(u64);

impl Rng {
    #[must_use]
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Value in `[0, bound)`; `bound == 0` yields 0 instead of panicking.
    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }
}

/// Seeded identifier such as `compute_482`.
fn ident(rng: &mut Rng, prefix: &str) -> String {
    format!("{prefix}_{}", rng.below(1_000))
}

/// Deterministic ~220-line Python module exercising functions, classes,
/// loops, strings and comments, plus guaranteed rule triggers.
#[must_use]
fn python_fixture(rng: &mut Rng) -> String {
    let mut out = String::new();
    out.push_str("# Synthetic module generated for the hoonarqube benchmark.\n");
    out.push_str("\"\"\"Deterministic workload: functions, classes, loops, strings.\"\"\"\n");
    out.push('\n');
    out.push_str("import math\n");
    out.push('\n');
    out.push_str("SCALE = 3\n\n\n");
    for _ in 0..9 {
        let name = ident(rng, "compute");
        let bound = rng.below(50) + 5;
        writeln!(out, "def {name}(values):").unwrap();
        out.push_str("    \"\"\"Aggregate values with a seeded branch mix.\"\"\"\n");
        out.push_str("    total = 0\n");
        out.push_str("    for value in values:\n");
        out.push_str("        if value % 2 == 0:\n");
        out.push_str("            total += value * SCALE\n");
        out.push_str("        elif value % 3 == 0:\n");
        writeln!(out, "            total -= math.gcd(value, {bound})").unwrap();
        out.push_str("        else:\n");
        out.push_str("            total += value // 2\n");
        out.push_str("    return max(total, 0)\n\n\n");
    }
    for _ in 0..5 {
        let name = ident(rng, "Handler");
        let limit = rng.below(20) + 3;
        writeln!(out, "class {name}:").unwrap();
        out.push_str("    \"\"\"Small stateful helper over string batches.\"\"\"\n\n");
        out.push_str("    def __init__(self, label):\n");
        out.push_str("        self.label = label\n");
        out.push_str("        self.count = 0\n\n");
        out.push_str("    def process(self, items):\n");
        out.push_str("        kept = []\n");
        out.push_str("        for item in items:\n");
        writeln!(out, "            if len(item) > {limit}:").unwrap();
        out.push_str("                kept.append(item.upper())\n");
        out.push_str("        self.count += len(kept)\n");
        out.push_str("        return kept\n\n");
        out.push_str("    def describe(self):\n");
        out.push_str("        return f\"{{self.label}} x {{self.count}}\"\n\n\n");
    }
    out.push_str("# Deliberate rule triggers below.\n");
    writeln!(
        out,
        "PAYLOAD = \"{}\"  # exceeds the maximum line length",
        "p".repeat(130)
    )
    .unwrap();
    out.push_str("exec(\"hint = SCALE * 2\")  # dynamic execution\n");
    out.push_str("left = 1; right = 2  # two statements on one line\n");
    out
}

/// Deterministic ~220-line JavaScript module with the same workload shape.
#[must_use]
fn javascript_fixture(rng: &mut Rng) -> String {
    let mut out = String::new();
    out.push_str("// Synthetic module generated for the hoonarqube benchmark.\n");
    out.push_str("// Deterministic workload: functions, classes, loops, strings.\n\n");
    out.push_str("const SCALE = 3;\n\n");
    out.push_str("function gcd(a, b) {\n");
    out.push_str("  while (b !== 0) {\n");
    out.push_str("    const rest = a % b;\n");
    out.push_str("    a = b;\n");
    out.push_str("    b = rest;\n");
    out.push_str("  }\n");
    out.push_str("  return a;\n");
    out.push_str("}\n\n\n");
    for _ in 0..8 {
        let name = ident(rng, "compute");
        let bound = rng.below(40) + 5;
        writeln!(out, "function {name}(values) {{").unwrap();
        out.push_str("  let total = 0;\n");
        out.push_str("  for (const value of values) {\n");
        out.push_str("    if (value % 2 === 0) {\n");
        out.push_str("      total += value * SCALE;\n");
        out.push_str("    } else if (value % 3 === 0) {\n");
        writeln!(out, "      total -= gcd(value, {bound});").unwrap();
        out.push_str("    } else {\n");
        out.push_str("      total += Math.floor(value / 2);\n");
        out.push_str("    }\n");
        out.push_str("  }\n");
        out.push_str("  return Math.max(total, 0);\n");
        out.push_str("}\n\n\n");
    }
    for _ in 0..5 {
        let name = ident(rng, "Handler");
        let limit = rng.below(20) + 3;
        writeln!(out, "class {name} {{").unwrap();
        out.push_str("  constructor(label) {\n");
        out.push_str("    this.label = label;\n");
        out.push_str("    this.count = 0;\n");
        out.push_str("  }\n\n");
        out.push_str("  process(items) {\n");
        out.push_str("    const kept = [];\n");
        out.push_str("    for (const item of items) {\n");
        writeln!(out, "      if (item.length > {limit}) {{").unwrap();
        out.push_str("        kept.push(item.toUpperCase());\n");
        out.push_str("      }\n");
        out.push_str("    }\n");
        out.push_str("    this.count += kept.length;\n");
        out.push_str("    return kept;\n");
        out.push_str("  }\n");
        out.push_str("}\n\n\n");
    }
    out.push_str("// Deliberate rule triggers below.\n");
    out.push_str("eval(\"scaleHint = SCALE * 2\");\n");
    out.push_str("const legacy = new Function(\"return 42\");\n");
    out.push_str("let leftSide = 1; let rightSide = 2;\n");
    writeln!(
        out,
        "const PADDED = \"{}\"; // exceeds the maximum line length",
        "P".repeat(185)
    )
    .unwrap();
    out
}

/// Deterministic ~230-line TypeScript module: typed variant of the JS shape.
#[must_use]
fn typescript_fixture(rng: &mut Rng) -> String {
    let mut out = String::new();
    out.push_str("// Synthetic module generated for the hoonarqube benchmark.\n");
    out.push_str("// Deterministic workload: interfaces, classes, loops, strings.\n\n");
    out.push_str("interface ShapeSpec {\n");
    out.push_str("  kind: string;\n");
    out.push_str("  radius: number;\n");
    out.push_str("}\n\n");
    out.push_str("const SCALE: number = 3;\n\n");
    out.push_str("const origin: ShapeSpec = { kind: \"circle\", radius: 1.5 };\n\n\n");
    for _ in 0..8 {
        let name = ident(rng, "compute");
        let bound = rng.below(40) + 5;
        writeln!(out, "function {name}(values: number[]): number {{").unwrap();
        out.push_str("  let total: number = 0;\n");
        out.push_str("  for (const value of values) {\n");
        out.push_str("    if (value % 2 === 0) {\n");
        out.push_str("      total += value * SCALE;\n");
        out.push_str("    } else if (value % 3 === 0) {\n");
        writeln!(out, "      total -= value % {bound};").unwrap();
        out.push_str("    } else {\n");
        out.push_str("      total += Math.floor(value / 2);\n");
        out.push_str("    }\n");
        out.push_str("  }\n");
        out.push_str("  return Math.max(total, 0);\n");
        out.push_str("}\n\n\n");
    }
    for _ in 0..5 {
        let name = ident(rng, "Handler");
        let limit = rng.below(20) + 3;
        writeln!(out, "class {name} {{").unwrap();
        out.push_str("  private readonly label: string;\n");
        out.push_str("  private count: number = 0;\n\n");
        out.push_str("  constructor(label: string) {\n");
        out.push_str("    this.label = label;\n");
        out.push_str("  }\n\n");
        out.push_str("  process(items: string[]): string[] {\n");
        out.push_str("    const kept: string[] = [];\n");
        out.push_str("    for (const item of items) {\n");
        writeln!(out, "      if (item.length > {limit}) {{").unwrap();
        out.push_str("        kept.push(item.toUpperCase());\n");
        out.push_str("      }\n");
        out.push_str("    }\n");
        out.push_str("    this.count += kept.length;\n");
        out.push_str("    return kept;\n");
        out.push_str("  }\n");
        out.push_str("}\n\n\n");
    }
    out.push_str("// Deliberate rule triggers below.\n");
    out.push_str("eval(\"scaleHint = SCALE * 2\");\n");
    out.push_str("const legacy = new Function(\"return 42\");\n");
    out.push_str("let leftSide: number = 1; let rightSide: number = 2;\n");
    writeln!(
        out,
        "const PADDED: string = \"{}\"; // exceeds the maximum line length",
        "P".repeat(185)
    )
    .unwrap();
    out
}

/// Deterministic ~210-line C# module with the same workload shape.
#[must_use]
fn csharp_fixture(rng: &mut Rng) -> String {
    let mut out = String::new();
    out.push_str("// Synthetic module generated for the hoonarqube benchmark.\n");
    out.push_str("using System;\n");
    out.push_str("using System.Collections.Generic;\n\n");
    out.push_str("namespace Bench.Generated\n{\n");
    for _ in 0..4 {
        let name = ident(rng, "Compute");
        let bound = rng.below(40) + 5;
        writeln!(out, "    public static class {name}").unwrap();
        out.push_str("    {\n");
        out.push_str("        public static int Total(IEnumerable<int> values)\n");
        out.push_str("        {\n");
        out.push_str("            var total = 0;\n");
        out.push_str("            foreach (var value in values)\n");
        out.push_str("            {\n");
        out.push_str("                if (value % 2 == 0) { total += value * 3; }\n");
        out.push_str("                else if (value % 3 == 0)\n");
        out.push_str("                {\n");
        writeln!(out, "                    total -= value % {bound};").unwrap();
        out.push_str("                }\n");
        out.push_str("                else { total += value / 2; }\n");
        out.push_str("            }\n");
        out.push_str("            return Math.Max(total, 0);\n");
        out.push_str("        }\n");
        out.push_str("    }\n\n");
    }
    for _ in 0..6 {
        let name = ident(rng, "Handler");
        let limit = rng.below(20) + 3;
        writeln!(out, "    public sealed class {name}").unwrap();
        out.push_str("    {\n");
        out.push_str("        private int _count;\n\n");
        out.push_str("        public IReadOnlyList<string> Process(IReadOnlyList<string> items)\n");
        out.push_str("        {\n");
        out.push_str("            var kept = new List<string>();\n");
        out.push_str("            foreach (var item in items)\n");
        out.push_str("            {\n");
        writeln!(out, "                if (item.Length > {limit})").unwrap();
        out.push_str("                {\n");
        out.push_str("                    kept.Add(item.ToUpperInvariant());\n");
        out.push_str("                }\n");
        out.push_str("            }\n");
        out.push_str("            _count += kept.Count;\n");
        out.push_str("            return kept;\n");
        out.push_str("        }\n");
        out.push_str("    }\n\n");
    }
    out.push_str("    public static class Triggers\n");
    out.push_str("    {\n");
    out.push_str("        public static void Run()\n");
    out.push_str("        {\n");
    writeln!(
        out,
        "            var padded = \"{}\"; // exceeds the maximum line length",
        "P".repeat(205)
    )
    .unwrap();
    out.push_str("            var firstSide = 1; var secondSide = 2;\n");
    out.push_str("        }\n");
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// Deterministic Go module with declarations, loops, branches, and triggers.
#[must_use]
fn go_fixture(rng: &mut Rng) -> String {
    let mut out = String::from("package benchmark\n\nimport \"fmt\"\n\n");
    for _ in 0..24 {
        let name = ident(rng, "compute");
        let bound = rng.below(40) + 5;
        writeln!(out, "func {name}(values []int) int {{").unwrap();
        out.push_str("\ttotal := 0\n\tfor _, value := range values {\n");
        out.push_str("\t\tif value%2 == 0 { total += value } else { total -= value }\n");
        writeln!(out, "\t\ttotal %= {bound}").unwrap();
        out.push_str("\t}\n\treturn total\n}\n\n");
    }
    out.push_str("func report(value int) { fmt.Println(value) }\n");
    writeln!(out, "var padded = \"{}\"", "g".repeat(140)).unwrap();
    out
}

/// Deterministic Rust module with functions, iterators, branches, and triggers.
#[must_use]
fn rust_fixture(rng: &mut Rng) -> String {
    let mut out = String::new();
    for _ in 0..24 {
        let name = ident(rng, "compute");
        let bound = rng.below(40) + 5;
        writeln!(out, "fn {name}(values: &[i32]) -> i32 {{").unwrap();
        out.push_str("    let mut total = 0;\n    for value in values {\n");
        out.push_str("        if value % 2 == 0 { total += value; } else { total -= value; }\n");
        writeln!(out, "        total %= {bound};").unwrap();
        out.push_str("    }\n    total\n}\n\n");
    }
    out.push_str("fn report(value: i32) { println!(\"{value}\"); }\n");
    out.push_str("fn too_many(a:i32,b:i32,c:i32,d:i32,e:i32,f:i32,g:i32,h:i32) { let _ = (a,b,c,d,e,f,g,h); }\n");
    out
}

/// Throughput rates derived from one timed measurement.
struct Throughput {
    files_per_second: f64,
    megabytes_per_second: f64,
}

/// Computes files/s and MB/s; a zero elapsed time floors at one nanosecond.
#[must_use]
fn throughput(files: u64, bytes: u64, elapsed: Duration) -> Throughput {
    let seconds = if elapsed.is_zero() {
        MIN_SECONDS
    } else {
        elapsed.as_secs_f64()
    };
    Throughput {
        files_per_second: to_f64(files) / seconds,
        megabytes_per_second: to_f64(bytes) / BYTES_PER_MB / seconds,
    }
}

/// One result row of the benchmark table.
struct LanguageBenchmark {
    language: &'static str,
    iterations: u32,
    findings: u64,
    throughput: Throughput,
}

/// Times `iterations` runs of `analyze` over one in-memory fixture after an
/// untimed warmup pass, then converts the measurement into rates.
fn bench_language(
    language: &'static str,
    source: &str,
    iterations: u32,
    analyze: &mut dyn FnMut(&str) -> u64,
) -> LanguageBenchmark {
    analyze(source);
    let bytes_per_pass = to_u64(source.len());
    let start = Instant::now();
    let mut findings = 0_u64;
    for _ in 0..iterations {
        findings += analyze(source);
    }
    let elapsed = start.elapsed();
    let files = u64::from(iterations);
    let bytes = bytes_per_pass * files;
    LanguageBenchmark {
        language,
        iterations,
        findings,
        throughput: throughput(files, bytes, elapsed),
    }
}

/// Parses `--iterations N` / `--iterations=N`; defaults to 20; rejects 0.
fn parse_iterations(args: &[String]) -> Result<u32, String> {
    let mut iterations = DEFAULT_ITERATIONS;
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        let value = if argument == "--iterations" {
            index += 1;
            args.get(index)
                .ok_or_else(|| "--iterations requires a value".to_string())?
        } else {
            argument
                .strip_prefix("--iterations=")
                .ok_or_else(|| format!("unknown argument: {argument}"))?
        };
        iterations = parse_count(value)?;
        index += 1;
    }
    Ok(iterations)
}

/// Parses one positive iteration count.
fn parse_count(value: &str) -> Result<u32, String> {
    let parsed: u32 = value
        .parse()
        .map_err(|_| format!("--iterations expects a positive integer, got `{value}`"))?;
    if parsed == 0 {
        return Err("--iterations must be at least 1".to_string());
    }
    Ok(parsed)
}

/// Prints the aligned benchmark table to stdout.
fn print_table(results: &[LanguageBenchmark]) {
    println!(
        "{:<12} {:>10} {:>12} {:>10} {:>10}",
        "language", "iterations", "files/s", "mb/s", "findings"
    );
    for result in results {
        let rate = &result.throughput;
        println!(
            "{:<12} {:>10} {:>12.2} {:>10.2} {:>10}",
            result.language,
            result.iterations,
            rate.files_per_second,
            rate.megabytes_per_second,
            result.findings
        );
    }
}

/// Counts Python issues over one benchmark source.
fn python_issue_count(source: &str, options: &PythonOptions) -> u64 {
    to_u64(
        hoonarqube_python::analyze(PathBuf::from("bench_fixture.py"), source, options)
            .issues
            .len(),
    )
}

/// Counts JavaScript issues over one benchmark source.
fn javascript_issue_count(source: &str, options: &JstsOptions) -> u64 {
    jsts_issue_count(
        source,
        PathBuf::from("bench_fixture.js"),
        JstsLanguage::JavaScript,
        options,
    )
}

/// Counts TypeScript issues over one benchmark source.
fn typescript_issue_count(source: &str, options: &JstsOptions) -> u64 {
    jsts_issue_count(
        source,
        PathBuf::from("bench_fixture.ts"),
        JstsLanguage::TypeScript,
        options,
    )
}

/// Shared issue counting for both script-language variants.
fn jsts_issue_count(
    source: &str,
    path: PathBuf,
    language: JstsLanguage,
    options: &JstsOptions,
) -> u64 {
    to_u64(
        hoonarqube_jsts::analyze(path, source, language, options)
            .issues
            .len(),
    )
}

/// Counts C# issues over one benchmark source.
fn csharp_issue_count(source: &str, options: &CsharpOptions) -> u64 {
    to_u64(
        hoonarqube_csharp::analyze(
            PathBuf::from("bench_fixture.cs"),
            source,
            CsLanguage::CSharp,
            options,
        )
        .issues
        .len(),
    )
}

fn go_issue_count(source: &str, options: &GoOptions) -> u64 {
    to_u64(
        hoonarqube_go::analyze(PathBuf::from("bench_fixture.go"), source, options)
            .issues
            .len(),
    )
}

fn rust_issue_count(source: &str, options: &RustOptions) -> u64 {
    to_u64(
        hoonarqube_rust::analyze(PathBuf::from("bench_fixture.rs"), source, options)
            .issues
            .len(),
    )
}

/// Generates every seeded fixture and benchmarks all six language analyzers.
fn run_benchmarks(iterations: u32) -> Vec<LanguageBenchmark> {
    let python_options = PythonOptions::default();
    let jsts_options = JstsOptions::default();
    let csharp_options = CsharpOptions::default();
    let go_options = GoOptions::default();
    let rust_options = RustOptions::default();

    let python_source = python_fixture(&mut Rng::new(0x5059_5448_4F4E_0001));
    let javascript_source = javascript_fixture(&mut Rng::new(0x4A41_5641_5350_0001));
    let typescript_source = typescript_fixture(&mut Rng::new(0x5453_4A53_5243_0001));
    let csharp_source = csharp_fixture(&mut Rng::new(0x4353_4841_5250_0001));
    let go_source = go_fixture(&mut Rng::new(0x474F_4C41_4E47_0001));
    let rust_source = rust_fixture(&mut Rng::new(0x5255_5354_4C41_0001));

    vec![
        bench_language("python", &python_source, iterations, &mut |source| {
            python_issue_count(source, &python_options)
        }),
        bench_language(
            "javascript",
            &javascript_source,
            iterations,
            &mut |source| javascript_issue_count(source, &jsts_options),
        ),
        bench_language(
            "typescript",
            &typescript_source,
            iterations,
            &mut |source| typescript_issue_count(source, &jsts_options),
        ),
        bench_language("csharp", &csharp_source, iterations, &mut |source| {
            csharp_issue_count(source, &csharp_options)
        }),
        bench_language("go", &go_source, iterations, &mut |source| {
            go_issue_count(source, &go_options)
        }),
        bench_language("rust", &rust_source, iterations, &mut |source| {
            rust_issue_count(source, &rust_options)
        }),
    ]
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let iterations = match parse_iterations(&args) {
        Ok(iterations) => iterations,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let results = run_benchmarks(iterations);
    print_table(&results);

    if results.iter().any(|result| result.findings == 0) {
        eprintln!("error: a language reported zero findings; analyzers did not run");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1024 * 1024;

    #[test]
    fn rng_is_deterministic_per_seed() {
        let mut first = Rng::new(42);
        let mut second = Rng::new(42);
        for _ in 0..16 {
            assert_eq!(first.next_u64(), second.next_u64());
        }
    }

    #[test]
    fn rng_seeds_diverge_and_stay_in_bounds() {
        let mut first = Rng::new(1);
        let mut second = Rng::new(2);
        assert_ne!(first.next_u64(), second.next_u64());
        let mut rng = Rng::new(7);
        for _ in 0..32 {
            assert!(rng.below(10) < 10);
        }
        assert_eq!(rng.below(0), 0);
    }

    #[test]
    fn fixture_generators_are_deterministic() {
        let generators: [(&str, FixtureGenerator); 6] = [
            ("python", python_fixture),
            ("javascript", javascript_fixture),
            ("typescript", typescript_fixture),
            ("csharp", csharp_fixture),
            ("go", go_fixture),
            ("rust", rust_fixture),
        ];
        for (name, generator) in generators {
            let first = generator(&mut Rng::new(5));
            let second = generator(&mut Rng::new(5));
            assert_eq!(first, second, "{name}: generator is not deterministic");
        }
    }

    #[test]
    fn fixtures_have_expected_shape_and_triggers() {
        let cases: [(&str, FixtureGenerator, usize, &str, &str, &str); 6] = [
            ("python", python_fixture, 120, "def ", "for ", "#"),
            (
                "javascript",
                javascript_fixture,
                180,
                "function ",
                "for (",
                "//",
            ),
            (
                "typescript",
                typescript_fixture,
                180,
                "interface ",
                "for (",
                "//",
            ),
            ("csharp", csharp_fixture, 200, "class ", "foreach (", "//"),
            ("go", go_fixture, 120, "func ", "for ", "package"),
            ("rust", rust_fixture, 90, "fn ", "for ", "let "),
        ];
        for (name, generator, limit, construct, loop_marker, comment) in cases {
            let source = generator(&mut Rng::new(99));
            let lines = source.lines().count();
            assert!(
                (150..=260).contains(&lines),
                "{name}: unexpected line count {lines}"
            );
            assert!(source.contains(construct), "{name}: missing {construct}");
            assert!(
                source.contains(loop_marker),
                "{name}: missing {loop_marker}"
            );
            assert!(source.contains(comment), "{name}: missing comments");
            assert!(source.contains('"'), "{name}: missing string literals");
            let longest = source.lines().map(str::len).max().unwrap_or_default();
            assert!(longest > limit, "{name}: no line longer than {limit}");
        }
    }

    #[test]
    fn parse_iterations_defaults_without_arguments() {
        assert_eq!(parse_iterations(&[]).ok(), Some(DEFAULT_ITERATIONS));
    }

    #[test]
    fn parse_iterations_accepts_space_and_equals_forms() {
        let spaced = vec!["--iterations".to_string(), "5".to_string()];
        let joined = vec!["--iterations=7".to_string()];
        assert_eq!(parse_iterations(&spaced).ok(), Some(5));
        assert_eq!(parse_iterations(&joined).ok(), Some(7));
    }

    #[test]
    fn parse_iterations_rejects_bad_input() {
        let missing = vec!["--iterations".to_string()];
        let zero = vec!["--iterations".to_string(), "0".to_string()];
        let negative = vec!["--iterations".to_string(), "-3".to_string()];
        let non_numeric = vec!["--iterations".to_string(), "abc".to_string()];
        let unknown = vec!["--wat".to_string()];
        assert!(parse_iterations(&missing).is_err());
        assert!(parse_iterations(&zero).is_err());
        assert!(parse_iterations(&negative).is_err());
        assert!(parse_iterations(&non_numeric).is_err());
        assert!(parse_iterations(&unknown).is_err());
    }

    #[test]
    fn throughput_math_is_exact_for_known_durations() {
        let rate = throughput(2, 2 * MB, Duration::from_secs(1));
        assert!((rate.files_per_second - 2.0).abs() < 1e-9);
        assert!((rate.megabytes_per_second - 2.0).abs() < 1e-9);
    }

    #[test]
    fn throughput_survives_instant_durations() {
        let rate = throughput(1, MB, Duration::ZERO);
        assert!(rate.files_per_second.is_finite() && rate.files_per_second > 0.0);
        assert!(rate.megabytes_per_second.is_finite() && rate.megabytes_per_second > 0.0);
    }

    #[test]
    fn analyzers_find_issues_in_every_fixture() {
        let python_options = PythonOptions::default();
        let jsts_options = JstsOptions::default();
        let csharp_options = CsharpOptions::default();
        let go_options = GoOptions::default();
        let rust_options = RustOptions::default();

        let python = python_fixture(&mut Rng::new(11));
        let javascript = javascript_fixture(&mut Rng::new(12));
        let typescript = typescript_fixture(&mut Rng::new(13));
        let csharp = csharp_fixture(&mut Rng::new(14));
        let go = go_fixture(&mut Rng::new(15));
        let rust = rust_fixture(&mut Rng::new(16));

        let python_report =
            hoonarqube_python::analyze(PathBuf::from("bench.py"), &python, &python_options);
        assert!(!python_report.issues.is_empty());

        let javascript_report = hoonarqube_jsts::analyze(
            PathBuf::from("bench.js"),
            &javascript,
            JstsLanguage::JavaScript,
            &jsts_options,
        );
        assert!(!javascript_report.issues.is_empty());

        let typescript_report = hoonarqube_jsts::analyze(
            PathBuf::from("bench.ts"),
            &typescript,
            JstsLanguage::TypeScript,
            &jsts_options,
        );
        assert!(!typescript_report.issues.is_empty());

        let csharp_report = hoonarqube_csharp::analyze(
            PathBuf::from("bench.cs"),
            &csharp,
            CsLanguage::CSharp,
            &csharp_options,
        );
        assert!(!csharp_report.issues.is_empty());

        let go_report = hoonarqube_go::analyze(PathBuf::from("bench.go"), &go, &go_options);
        assert!(!go_report.issues.is_empty());

        let rust_report = hoonarqube_rust::analyze(PathBuf::from("bench.rs"), &rust, &rust_options);
        assert!(!rust_report.issues.is_empty());
    }
}
