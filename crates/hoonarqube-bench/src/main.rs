#![allow(clippy::print_stderr, clippy::print_stdout)]

//! Multi-language throughput benchmark for the hoonarqube analyzers.
//!
//! Builds one deterministic synthetic fixture per language in memory,
//! analyzes it for `--iterations` runs, and prints files/s, MB/s and total
//! findings so analyzer regressions surface as throughput deltas.

use std::env;
use std::fmt::Write as _;
use std::hint::black_box;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use hoonarqube_core::{
    DuplicationFile, DuplicationOptions, DuplicationResult, Language as CoreLanguage,
    NormalizedToken, SourceFacts, detect_duplications,
};
use hoonarqube_csharp::{AnalyzerOptions as CsharpOptions, CsLanguage};
use hoonarqube_go::AnalyzerOptions as GoOptions;
use hoonarqube_ir::{FileMetrics, Issue};
use hoonarqube_jsts::{AnalyzerOptions as JstsOptions, JstsLanguage};
use hoonarqube_python::AnalyzerOptions as PythonOptions;
use hoonarqube_rust::AnalyzerOptions as RustOptions;

/// Iterations used when `--iterations` is absent.
const DEFAULT_ITERATIONS: u32 = 20;

/// Fixture copies used when `--scale` is absent.
const DEFAULT_SCALE: u32 = 1;

/// Maximum fixture scale accepted from the command line.
const MAX_SCALE: u32 = 1_024;

/// Minimum source-facts units/lines used by duplication fixtures.
const DUPLICATION_MIN_TOKENS: usize = 32;
const DUPLICATION_MIN_LINES: u32 = 8;

/// Bytes per reported MB (1 MiB).
const BYTES_PER_MB: f64 = 1024.0 * 1024.0;

/// One-nanosecond floor keeping throughput finite on instant runs.
const MIN_SECONDS: f64 = 1.0 / 1_000_000_000.0;

/// One seeded source-fixture generator (test-only: names the generator tables).
#[cfg(test)]
type FixtureGenerator = fn(&mut Rng) -> String;

/// Short usage text printed for malformed command lines.
const USAGE: &str = concat!(
    "usage: hoonarqube-bench [--iterations N] [--language NAME] [--scale N] ",
    "[--workload duplication-same-diagonal|duplication-exact-clones|duplication-no-clones] ",
    "[--machine-readable]"
);

/// Widen an integer count for approximate throughput math.
///
/// Values above `2^53` may be rounded, as expected for an `f64`, but must not
/// be truncated: byte counts can exceed `u32::MAX` at high iteration counts.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn to_f64(value: u64) -> f64 {
    value as f64
}

/// Loss-enough widening of an issue count.
#[must_use]
fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchmarkLanguage {
    Python,
    JavaScript,
    TypeScript,
    CSharp,
    Go,
    Rust,
}

impl BenchmarkLanguage {
    const ALL: [Self; 6] = [
        Self::Python,
        Self::JavaScript,
        Self::TypeScript,
        Self::CSharp,
        Self::Go,
        Self::Rust,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::CSharp => "csharp",
            Self::Go => "go",
            Self::Rust => "rust",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "python" => Ok(Self::Python),
            "javascript" => Ok(Self::JavaScript),
            "typescript" => Ok(Self::TypeScript),
            "csharp" => Ok(Self::CSharp),
            "go" => Ok(Self::Go),
            "rust" => Ok(Self::Rust),
            _ => Err(format!(
                "unknown language `{value}` (expected python, javascript, typescript, csharp, go, or rust)"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DuplicationWorkload {
    SameDiagonal,
    ExactClones,
    NoClones,
}

impl DuplicationWorkload {
    const fn name(self) -> &'static str {
        match self {
            Self::SameDiagonal => "duplication-same-diagonal",
            Self::ExactClones => "duplication-exact-clones",
            Self::NoClones => "duplication-no-clones",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "duplication-same-diagonal" => Ok(Self::SameDiagonal),
            "duplication-exact-clones" => Ok(Self::ExactClones),
            "duplication-no-clones" => Ok(Self::NoClones),
            _ => Err(format!(
                "unknown workload `{value}` (expected duplication-same-diagonal, duplication-exact-clones, or duplication-no-clones)"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BenchmarkConfig {
    iterations: u32,
    language: Option<BenchmarkLanguage>,
    scale: u32,
    workload: Option<DuplicationWorkload>,
    machine_readable: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IssueSummary {
    findings: u64,
    checksum: u64,
}

/// Fixed FNV-1a state; unlike `DefaultHasher`, this is stable across processes.
#[derive(Clone, Copy)]
struct StableHasher(u64);

impl StableHasher {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;

    const fn new() -> Self {
        Self(Self::OFFSET)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.u64(u64::from(value));
    }

    fn string(&mut self, value: &str) {
        self.u64(to_u64(value.len()));
        self.bytes(value.as_bytes());
    }

    const fn finish(self) -> u64 {
        self.0
    }
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

fn fixture_seed(language: BenchmarkLanguage) -> u64 {
    match language {
        BenchmarkLanguage::Python => 0x5059_5448_4F4E_0001,
        BenchmarkLanguage::JavaScript => 0x4A41_5641_5350_0001,
        BenchmarkLanguage::TypeScript => 0x5453_4A53_5243_0001,
        BenchmarkLanguage::CSharp => 0x4353_4841_5250_0001,
        BenchmarkLanguage::Go => 0x474F_4C41_4E47_0001,
        BenchmarkLanguage::Rust => 0x5255_5354_4C41_0001,
    }
}

fn fixture_for_seed(language: BenchmarkLanguage, seed: u64) -> String {
    let mut rng = Rng::new(seed);
    match language {
        BenchmarkLanguage::Python => python_fixture(&mut rng),
        BenchmarkLanguage::JavaScript => javascript_fixture(&mut rng),
        BenchmarkLanguage::TypeScript => typescript_fixture(&mut rng),
        BenchmarkLanguage::CSharp => csharp_fixture(&mut rng),
        BenchmarkLanguage::Go => go_fixture(&mut rng),
        BenchmarkLanguage::Rust => rust_fixture(&mut rng),
    }
}

fn fixture_for(language: BenchmarkLanguage) -> String {
    fixture_for_seed(language, fixture_seed(language))
}

fn source_extension(language: BenchmarkLanguage) -> &'static str {
    match language {
        BenchmarkLanguage::Python => "py",
        BenchmarkLanguage::JavaScript => "js",
        BenchmarkLanguage::TypeScript => "ts",
        BenchmarkLanguage::CSharp => "cs",
        BenchmarkLanguage::Go => "go",
        BenchmarkLanguage::Rust => "rs",
    }
}

fn core_language(language: BenchmarkLanguage) -> CoreLanguage {
    match language {
        BenchmarkLanguage::Python => CoreLanguage::Python,
        BenchmarkLanguage::JavaScript => CoreLanguage::JavaScript,
        BenchmarkLanguage::TypeScript => CoreLanguage::TypeScript,
        BenchmarkLanguage::CSharp => CoreLanguage::CSharp,
        BenchmarkLanguage::Go => CoreLanguage::Go,
        BenchmarkLanguage::Rust => CoreLanguage::Rust,
    }
}

/// Repeats a deterministic source fixture without changing its spelling.
///
/// Go's package declaration is file-scoped, so it is kept only in the first
/// copy.  The other benchmark fixtures are valid when their top-level source
/// is repeated and all analyzers intentionally operate on syntax rather than
/// compilation/linking.
fn scaled_source(language: BenchmarkLanguage, source: &str, scale: u32) -> String {
    let copies = scale.max(1);
    if copies == 1 {
        return source.to_owned();
    }
    let capacity = source
        .len()
        .saturating_mul(usize::try_from(copies).unwrap_or(usize::MAX));
    let mut scaled = String::with_capacity(capacity);
    for copy in 0..copies {
        if copy > 0 && language == BenchmarkLanguage::Go {
            for line in source.lines() {
                if line.trim_start().starts_with("package ") {
                    continue;
                }
                scaled.push_str(line);
                scaled.push('\n');
            }
        } else {
            scaled.push_str(source);
            if !source.ends_with('\n') {
                scaled.push('\n');
            }
        }
    }
    scaled
}

/// Synthetic normalized units isolate matcher cost from parsing. Each token
/// occupies one byte on its own two-byte line. Shared runs use unique symbols,
/// so only the intended file-pair diagonal matches, even at large scales.
fn duplication_inputs(
    language: BenchmarkLanguage,
    workload: DuplicationWorkload,
    scale: u32,
) -> Result<(Vec<DuplicationFile>, DuplicationOptions, u64), String> {
    const RUN_LENGTH: u32 = 64;
    let runs = 100 * scale;
    let units = runs * (RUN_LENGTH + 1);
    let options = DuplicationOptions {
        min_tokens: DUPLICATION_MIN_TOKENS,
        min_lines: DUPLICATION_MIN_LINES,
        ..DuplicationOptions::default()
    };
    if u64::from(units) * 2 > to_u64(options.max_tokens) {
        return Err("fixture exceeds the default duplication token limit".to_owned());
    }
    let domain = core_language(language);
    let files = (0..2)
        .map(|side| {
            let mut symbols = Vec::new();
            let mut tokens = Vec::new();
            for index in 0..units {
                let shared = match workload {
                    DuplicationWorkload::ExactClones => true,
                    DuplicationWorkload::NoClones => false,
                    DuplicationWorkload::SameDiagonal => index % (RUN_LENGTH + 1) != RUN_LENGTH,
                };
                symbols.push(format!("{}:{index}", if shared { 0 } else { side + 1 }));
                tokens.push(NormalizedToken {
                    symbol: index,
                    start_byte: index * 2,
                    end_byte: index * 2 + 1,
                    start_line: index + 1,
                    end_line: index + 1,
                });
            }
            DuplicationFile {
                path: PathBuf::from(format!("duplication/{side}.{}", source_extension(language))),
                language: domain,
                facts: SourceFacts {
                    language: domain,
                    metrics: FileMetrics {
                        lines: units,
                        code_lines: units,
                        comment_lines: 0,
                    },
                    symbols,
                    tokens,
                    error: None,
                },
            }
        })
        .collect();
    Ok((files, options, u64::from(units) * 4))
}

fn hash_range(hasher: &mut StableHasher, range: &hoonarqube_ir::Range) {
    hasher.u32(range.start.line);
    hasher.u32(range.start.column);
    hasher.u32(range.end.line);
    hasher.u32(range.end.column);
}

/// Summarizes issue semantics without including elapsed time or allocator order.
fn summarize_issues(issues: &[Issue]) -> IssueSummary {
    let mut hasher = StableHasher::new();
    hasher.u64(to_u64(issues.len()));
    for issue in issues {
        hasher.string(&issue.rule_key);
        hasher.string(&issue.message);
        hash_range(&mut hasher, &issue.range);
        match &issue.fix {
            Some(fix) => {
                hasher.u32(1);
                hasher.string(&fix.message);
                hasher.u64(to_u64(fix.edits.len()));
                for edit in &fix.edits {
                    hash_range(&mut hasher, &edit.range);
                    hasher.string(&edit.replacement);
                }
            }
            None => hasher.u32(0),
        }
        hasher.u64(to_u64(issue.flows.len()));
        for flow in &issue.flows {
            hasher.u64(to_u64(flow.locations.len()));
            for location in &flow.locations {
                match &location.path {
                    Some(path) => {
                        hasher.u32(1);
                        hasher.string(&path.to_string_lossy());
                    }
                    None => hasher.u32(0),
                }
                hasher.string(&location.message);
                hash_range(&mut hasher, &location.range);
            }
        }
    }
    IssueSummary {
        findings: to_u64(issues.len()),
        checksum: hasher.finish(),
    }
}

fn duplication_checksum(result: &DuplicationResult) -> u64 {
    let mut hasher = StableHasher::new();
    hasher.u64(result.metrics.duplicated_lines);
    hasher.u64(result.metrics.duplicated_blocks);
    hasher.u64(result.metrics.duplicated_files);
    if let Some(density) = result.metrics.duplicated_lines_density {
        hasher.u32(1);
        hasher.u64(density.to_bits());
    } else {
        hasher.u32(0);
    }
    hasher.u64(to_u64(result.groups.len()));
    for group in &result.groups {
        hasher.string(&group.language);
        hasher.u64(to_u64(group.occurrences.len()));
        for occurrence in &group.occurrences {
            hasher.string(&occurrence.path.to_string_lossy());
            hasher.u32(occurrence.start_line);
            hasher.u32(occurrence.end_line);
            hasher.u32(occurrence.start_byte);
            hasher.u32(occurrence.end_byte);
        }
    }
    hasher.finish()
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

/// One result row of the analyzer benchmark table.
struct LanguageBenchmark {
    language: &'static str,
    iterations: u32,
    findings: u64,
    per_pass: IssueSummary,
    source_bytes: u64,
    elapsed_ns: u128,
    throughput: Throughput,
}

/// Times `iterations` runs of `analyze` over one in-memory fixture after an
/// untimed warmup pass, then converts the measurement into rates.
fn bench_language(
    language: &'static str,
    source: &str,
    iterations: u32,
    analyze: &mut dyn FnMut(&str) -> IssueSummary,
) -> LanguageBenchmark {
    let per_pass = black_box(analyze(source));
    let bytes_per_pass = to_u64(source.len());
    let start = Instant::now();
    let mut findings = 0_u64;
    for _ in 0..iterations {
        let summary = black_box(analyze(source));
        assert_eq!(
            summary, per_pass,
            "analyzer semantics changed between iterations"
        );
        findings = findings.saturating_add(summary.findings);
    }
    let elapsed = start.elapsed();
    let files = u64::from(iterations);
    let bytes = bytes_per_pass.saturating_mul(files);
    LanguageBenchmark {
        language,
        iterations,
        findings,
        per_pass,
        source_bytes: bytes_per_pass,
        elapsed_ns: elapsed.as_nanos(),
        throughput: throughput(files, bytes, elapsed),
    }
}

/// Returns the value following a flag, accepting both `--flag value` and
/// `--flag=value`.
fn flag_value(
    args: &[String],
    index: &mut usize,
    argument: &str,
    flag: &str,
) -> Result<String, String> {
    if argument == flag {
        *index = index.saturating_add(1);
        return args
            .get(*index)
            .cloned()
            .ok_or_else(|| format!("{flag} requires a value"));
    }
    if let Some(value) = argument
        .strip_prefix(flag)
        .and_then(|suffix| suffix.strip_prefix('='))
    {
        if value.is_empty() {
            return Err(format!("{flag} requires a value"));
        }
        return Ok(value.to_owned());
    }
    Err(format!("unknown argument: {argument}"))
}

fn parse_scale(value: &str) -> Result<u32, String> {
    let parsed: u32 = value
        .parse()
        .map_err(|_| format!("--scale expects a positive integer, got `{value}`"))?;
    if parsed == 0 {
        return Err("--scale must be at least 1".to_owned());
    }
    if parsed > MAX_SCALE {
        return Err(format!("--scale must not exceed {MAX_SCALE}"));
    }
    Ok(parsed)
}

/// Parses all benchmark flags while keeping each flag optional.
fn parse_config(args: &[String]) -> Result<BenchmarkConfig, String> {
    let mut config = BenchmarkConfig {
        iterations: DEFAULT_ITERATIONS,
        language: None,
        scale: DEFAULT_SCALE,
        workload: None,
        machine_readable: false,
    };
    let mut index = 0;
    while index < args.len() {
        parse_config_argument(args, &mut index, &mut config)?;
    }
    Ok(config)
}

/// Parses one benchmark flag and advances past its value when present.
fn parse_config_argument(
    args: &[String],
    index: &mut usize,
    config: &mut BenchmarkConfig,
) -> Result<(), String> {
    let argument = &args[*index];
    match argument.as_str() {
        "--machine-readable" => config.machine_readable = true,
        arg if arg == "--iterations" || arg.starts_with("--iterations=") => {
            let value = flag_value(args, index, arg, "--iterations")?;
            config.iterations = parse_count(&value)?;
        }
        arg if arg == "--language" || arg.starts_with("--language=") => {
            let value = flag_value(args, index, arg, "--language")?;
            config.language = Some(BenchmarkLanguage::parse(&value)?);
        }
        arg if arg == "--scale" || arg.starts_with("--scale=") => {
            let value = flag_value(args, index, arg, "--scale")?;
            config.scale = parse_scale(&value)?;
        }
        arg if arg == "--workload" || arg.starts_with("--workload=") => {
            let value = flag_value(args, index, arg, "--workload")?;
            config.workload = Some(DuplicationWorkload::parse(&value)?);
        }
        _ => return Err(format!("unknown argument: {argument}")),
    }
    *index += 1;
    Ok(())
}

/// Parses `--iterations N` / `--iterations=N`; defaults to 20; rejects 0.
#[cfg(test)]
fn parse_iterations(args: &[String]) -> Result<u32, String> {
    parse_config(args).map(|config| config.iterations)
}

/// Parses one positive iteration count.
fn parse_count(value: &str) -> Result<u32, String> {
    let parsed: u32 = value
        .parse()
        .map_err(|_| format!("--iterations expects a positive integer, got `{value}`"))?;
    if parsed == 0 {
        return Err("--iterations must be at least 1".to_owned());
    }
    Ok(parsed)
}

/// Prints the aligned analyzer benchmark table to stdout.
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

fn python_issue_summary(source: &str, options: &PythonOptions) -> IssueSummary {
    let report = hoonarqube_python::analyze(PathBuf::from("bench_fixture.py"), source, options);
    summarize_issues(&report.issues)
}

fn javascript_issue_summary(source: &str, options: &JstsOptions) -> IssueSummary {
    jsts_issue_summary(
        source,
        PathBuf::from("bench_fixture.js"),
        JstsLanguage::JavaScript,
        options,
    )
}

fn typescript_issue_summary(source: &str, options: &JstsOptions) -> IssueSummary {
    jsts_issue_summary(
        source,
        PathBuf::from("bench_fixture.ts"),
        JstsLanguage::TypeScript,
        options,
    )
}

fn jsts_issue_summary(
    source: &str,
    path: PathBuf,
    language: JstsLanguage,
    options: &JstsOptions,
) -> IssueSummary {
    let report = hoonarqube_jsts::analyze(path, source, language, options);
    summarize_issues(&report.issues)
}

fn csharp_issue_summary(source: &str, options: &CsharpOptions) -> IssueSummary {
    let report = hoonarqube_csharp::analyze(
        PathBuf::from("bench_fixture.cs"),
        source,
        CsLanguage::CSharp,
        options,
    );
    summarize_issues(&report.issues)
}

fn go_issue_summary(source: &str, options: &GoOptions) -> IssueSummary {
    let report = hoonarqube_go::analyze(PathBuf::from("bench_fixture.go"), source, options);
    summarize_issues(&report.issues)
}

fn rust_issue_summary(source: &str, options: &RustOptions) -> IssueSummary {
    let report = hoonarqube_rust::analyze(PathBuf::from("bench_fixture.rs"), source, options);
    summarize_issues(&report.issues)
}

/// Generates and benchmarks the requested language set.
fn run_language_benchmarks(
    iterations: u32,
    selected_language: Option<BenchmarkLanguage>,
    scale: u32,
) -> Vec<LanguageBenchmark> {
    let python_options = PythonOptions::default();
    let jsts_options = JstsOptions::default();
    let csharp_options = CsharpOptions::default();
    let go_options = GoOptions::default();
    let rust_options = RustOptions::default();
    let languages: Vec<BenchmarkLanguage> = selected_language.map_or_else(
        || BenchmarkLanguage::ALL.to_vec(),
        |language| vec![language],
    );
    let mut results = Vec::with_capacity(languages.len());
    for language in languages {
        let raw_source = fixture_for(language);
        let source = scaled_source(language, &raw_source, scale);
        let result = match language {
            BenchmarkLanguage::Python => {
                bench_language(language.name(), &source, iterations, &mut |value| {
                    python_issue_summary(value, &python_options)
                })
            }
            BenchmarkLanguage::JavaScript => {
                bench_language(language.name(), &source, iterations, &mut |value| {
                    javascript_issue_summary(value, &jsts_options)
                })
            }
            BenchmarkLanguage::TypeScript => {
                bench_language(language.name(), &source, iterations, &mut |value| {
                    typescript_issue_summary(value, &jsts_options)
                })
            }
            BenchmarkLanguage::CSharp => {
                bench_language(language.name(), &source, iterations, &mut |value| {
                    csharp_issue_summary(value, &csharp_options)
                })
            }
            BenchmarkLanguage::Go => {
                bench_language(language.name(), &source, iterations, &mut |value| {
                    go_issue_summary(value, &go_options)
                })
            }
            BenchmarkLanguage::Rust => {
                bench_language(language.name(), &source, iterations, &mut |value| {
                    rust_issue_summary(value, &rust_options)
                })
            }
        };
        results.push(result);
    }
    results
}

/// Compatibility wrapper for callers that used the original six-row runner.
fn run_benchmarks(iterations: u32) -> Vec<LanguageBenchmark> {
    run_language_benchmarks(iterations, None, DEFAULT_SCALE)
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                write!(escaped, "\\u{:04x}", character as u32).unwrap();
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

/// Emits stable semantic fields plus measured input/timing counts.
fn print_machine_summary(config: BenchmarkConfig, results: &[LanguageBenchmark]) {
    let language = config.language.map_or("all", BenchmarkLanguage::name);
    let mut output = String::from("{\"schema_version\":1,\"kind\":\"analysis\"");
    write!(
        output,
        ",\"iterations\":{},\"scale\":{},\"language\":{}",
        config.iterations,
        config.scale,
        json_string(language)
    )
    .unwrap();
    output.push_str(",\"results\":[");
    for (index, result) in results.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"language\":{},\"source_bytes\":{},\"iterations\":{},\"elapsed_ns\":{},\"findings\":{},\"per_pass_findings\":{},\"checksum\":{}}}",
            json_string(result.language),
            result.source_bytes,
            result.iterations,
            result.elapsed_ns,
            result.findings,
            result.per_pass.findings,
            result.per_pass.checksum
        )
        .unwrap();
    }
    output.push_str("]}");
    println!("{output}");
}

struct DuplicationBenchmark {
    language: &'static str,
    workload: &'static str,
    iterations: u32,
    files: u64,
    source_bytes: u64,
    elapsed_ns: u128,
    result: DuplicationResult,
    throughput: Throughput,
}

fn bench_duplication(
    language: BenchmarkLanguage,
    workload: DuplicationWorkload,
    files: &[DuplicationFile],
    options: &DuplicationOptions,
    source_bytes: u64,
    iterations: u32,
) -> Result<DuplicationBenchmark, String> {
    let warmup = detect_duplications(files, options)?;
    black_box(&warmup);
    let start = Instant::now();
    let mut result = warmup;
    for _ in 0..iterations {
        result = detect_duplications(files, options)?;
        black_box(&result);
    }
    let elapsed = start.elapsed();
    let file_count = to_u64(files.len());
    let measured_files = file_count.saturating_mul(u64::from(iterations));
    let measured_bytes = source_bytes.saturating_mul(u64::from(iterations));
    Ok(DuplicationBenchmark {
        language: language.name(),
        workload: workload.name(),
        iterations,
        files: file_count,
        source_bytes,
        elapsed_ns: elapsed.as_nanos(),
        result,
        throughput: throughput(measured_files, measured_bytes, elapsed),
    })
}

fn print_duplication_table(benchmark: &DuplicationBenchmark) {
    let metrics = &benchmark.result.metrics;
    println!(
        "workload={} language={} iterations={} files={} source_bytes={}",
        benchmark.workload,
        benchmark.language,
        benchmark.iterations,
        benchmark.files,
        benchmark.source_bytes
    );
    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "files/s",
        "mb/s",
        "groups",
        "occurrences",
        "duplicated_lines",
        "duplicated_blocks",
        "duplicated_files"
    );
    let occurrences = benchmark
        .result
        .groups
        .iter()
        .map(|group| to_u64(group.occurrences.len()))
        .sum::<u64>();
    println!(
        "{:<12.2} {:>12.2} {:>12} {:>12} {:>12} {:>12} {:>12}",
        benchmark.throughput.files_per_second,
        benchmark.throughput.megabytes_per_second,
        to_u64(benchmark.result.groups.len()),
        occurrences,
        metrics.duplicated_lines,
        metrics.duplicated_blocks,
        metrics.duplicated_files
    );
}

fn print_duplication_machine_summary(config: BenchmarkConfig, benchmark: &DuplicationBenchmark) {
    let metrics = &benchmark.result.metrics;
    let occurrences = benchmark
        .result
        .groups
        .iter()
        .map(|group| to_u64(group.occurrences.len()))
        .sum::<u64>();
    let mut output = String::from("{\"schema_version\":1,\"kind\":\"duplication\"");
    write!(
        output,
        ",\"iterations\":{},\"scale\":{},\"language\":{},\"workload\":{}",
        config.iterations,
        config.scale,
        json_string(benchmark.language),
        json_string(benchmark.workload)
    )
    .unwrap();
    write!(
        output,
        ",\"files\":{},\"source_bytes\":{},\"elapsed_ns\":{},\"groups\":{},\"occurrences\":{},\"duplicated_lines\":{},\"duplicated_blocks\":{},\"duplicated_files\":{}",
        benchmark.files,
        benchmark.source_bytes,
        benchmark.elapsed_ns,
        to_u64(benchmark.result.groups.len()),
        occurrences,
        metrics.duplicated_lines,
        metrics.duplicated_blocks,
        metrics.duplicated_files
    )
    .unwrap();
    match metrics.duplicated_lines_density {
        Some(density) => write!(output, ",\"duplicated_lines_density\":{density}").unwrap(),
        None => output.push_str(",\"duplicated_lines_density\":null"),
    }
    write!(
        output,
        ",\"checksum\":{}}}",
        duplication_checksum(&benchmark.result)
    )
    .unwrap();
    println!("{output}");
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = match parse_config(&args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    if let Some(workload) = config.workload {
        let language = config.language.unwrap_or(BenchmarkLanguage::CSharp);
        let (files, options, source_bytes) =
            match duplication_inputs(language, workload, config.scale) {
                Ok(value) => value,
                Err(message) => {
                    eprintln!("error: {message}");
                    return ExitCode::FAILURE;
                }
            };
        let benchmark = match bench_duplication(
            language,
            workload,
            &files,
            &options,
            source_bytes,
            config.iterations,
        ) {
            Ok(benchmark) => benchmark,
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::FAILURE;
            }
        };
        if config.machine_readable {
            print_duplication_machine_summary(config, &benchmark);
        } else {
            print_duplication_table(&benchmark);
        }
        return ExitCode::SUCCESS;
    }

    let results = if config.language.is_none() && config.scale == DEFAULT_SCALE {
        run_benchmarks(config.iterations)
    } else {
        run_language_benchmarks(config.iterations, config.language, config.scale)
    };
    if config.machine_readable {
        print_machine_summary(config, &results);
    } else {
        print_table(&results);
    }

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
    fn duplication_workloads_keep_expected_clone_boundaries() {
        for (workload, groups, lines) in [
            (DuplicationWorkload::SameDiagonal, 100, 12_800),
            (DuplicationWorkload::ExactClones, 1, 13_000),
            (DuplicationWorkload::NoClones, 0, 0),
        ] {
            let (files, options, _) =
                duplication_inputs(BenchmarkLanguage::Python, workload, 1).unwrap();
            let result = detect_duplications(&files, &options).unwrap();
            assert_eq!(result.groups.len(), groups);
            assert_eq!(result.metrics.duplicated_lines, lines);
            for group in result.groups {
                assert_eq!(group.occurrences.len(), 2);
            }
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
    fn throughput_does_not_truncate_counts_above_u32() {
        let count = u64::from(u32::MAX) + 1;
        let rate = throughput(count, count, Duration::from_secs(1));
        assert!((rate.files_per_second - 4_294_967_296.0).abs() < f64::EPSILON);
        assert!(rate.megabytes_per_second > 4_095.0);
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
