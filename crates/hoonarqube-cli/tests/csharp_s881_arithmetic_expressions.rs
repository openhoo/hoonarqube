use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S881";
// Sources and expectations were executed against the installed SonarAnalyzer.CSharp
// 10.33 analyzer (assembly SHA256 461b82be21a9e8f57c1312ff877f8276789eeec5e64678344e961a0a3edfd957).
// Full-document digests pin independently reviewed predictions: unrelated ordered
// issues, all metadata/metrics/parity values and Sonar descriptors are included.
const CONTROL: &str = r"using System;
namespace Scope;
class Cases
{
    static int Take(int x) => x;
    static void Consume(int x) { }
    static void Lazy(Func<string> f) { }
    void M(string text, int[] values, int i)
    {
        var indexCall = text[--i].ToString();
        var postfixIndexCall = text[i++].ToString();
        var directIndex = values[--i];
        Consume(values[--i]);
        var indexComparison = values[--i] > 0;
        var parenthesizedIndex = text[(--i)].ToString();
        var arithmeticIndex = values[--i + 1];
        var callIndex = values[Take(--i)];
        var arithmeticIndexCall = text[i++ + 1].ToString();
        var ordinaryArithmetic = i++ + 1;
        Consume(--i);
        Lazy(() => text[--i].ToString());
        var discarded = i++;
        i++;
        for (var j = 0; j < 1; j++) { }
    }
}
";

const CLEAN: &str = r"using System;
class Clean
{
    int M(string text, int[] values, int i)
    {
        var first = text[--i];
        var second = values[i++];
        var discarded = i++;
        i++;
        return --i;
    }
}
";

const BARRIERS: &str = r"using System;
class Barriers
{
    static int Take(int x) => x;
    static int Invoke(Func<int> f) => f();
    void M(string text, int[] values, int i)
    {
        var callThenArithmetic = Take(i++) + 1;
        var arithmeticArgument = Take(i++ + 1);
        var indexThenArithmetic = values[i++] + 1;
        var nestedArgumentArithmetic = values[Take(i++ + 1)];
        var conditionalArgument = Take(i++ > 0 ? 1 : 2);
        var conditionalIndex = values[i++ > 0 ? 1 : 2];
        var lambdaThenArithmetic = Invoke(() => i++) + 1;
        var nestedIndexThenArithmetic = values[values[i++]] + 1;
        var invokeThenIndex = values[Take(i++)] + 1;
        var explicitArithmetic = ((i++)) + 1;
        var lambdaIndex = Invoke(() => values[i++]) + 1;
    }
}
";

const OPERATORS: &str = r#"using System;
class Operators
{
    static int Take(int x) => x;
    int M(int i, int j, bool b)
    {
        var add = i++ + j;
        var subtract = i++ - j;
        var multiply = i++ * j;
        var divide = i++ / j;
        var remainder = i++ % j;
        var leftShift = i++ << j;
        var rightShift = i++ >> j;
        var unsignedShift = i++ >>> j;
        var bitAnd = i++ & j;
        var bitOr = i++ | j;
        var bitXor = i++ ^ j;
        var equal = i++ == j;
        var notEqual = i++ != j;
        var greater = i++ > j;
        var less = i++ < j;
        var greaterEqual = i++ >= j;
        var lessEqual = i++ <= j;
        var logicalAnd = i++ > 0 && b;
        var logicalOr = i++ > 0 || b;
        var condition = i++ > 0 ? 1 : 2;
        var conditionalArm = b ? i++ : j;
        var conditionalArithmetic = b ? i++ + 1 : j;
        var interpolation = $"{i++}";
        var cast = (long)i++;
        var negate = -(i++);
        var complement = ~(i++);
        i += j++;
        i = j++;
        Take(++i);
        return i;
    }
}
"#;

const ORIGINAL: &str = r"using System.Collections.Generic;
namespace Scope;
class Roman
{
    static readonly Dictionary<string, int> RomanNumerals = new();
    int M(string input, int i)
    {
        var digit = RomanNumerals[input[--i].ToString()];
        return digit;
    }
}
";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s881-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("owned fixture directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("cases.cs"), source).expect("fixture source");
    }

    fn source(&self) -> Vec<u8> {
        std::fs::read(self.0.join("cases.cs")).expect("source readback")
    }

    fn analyze(&self, format: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                "cases.cs",
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--cache-dir",
                "cache",
            ])
            .output()
            .expect("actual CLI")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output, exit: i32) -> Value {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("one complete JSON document")
}

fn targets(report: &Value, format: &str) -> Vec<Value> {
    if format == "json" {
        report["files"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|file| file["issues"].as_array().unwrap())
            .filter(|issue| issue["rule_key"] == KEY)
            .cloned()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
            .cloned()
            .collect()
    }
}

fn expected(format: &str, row: &(u32, u32, u32, bool)) -> Value {
    let &(line, scalar, utf16, decrement) = row;
    let operation = if decrement { "decrement" } else { "increment" };
    let message = format!("Extract this {operation} operation into a dedicated statement.");
    if format == "json" {
        json!({"rule_key":KEY,"message":message,"range":{"start":{"line":line,"column":scalar},"end":{"line":line,"column":scalar+2}}})
    } else {
        json!({"ruleId":KEY,"primaryLocation":{"filePath":"cases.cs","message":message,"textRange":{"startLine":line,"startColumn":utf16,"endLine":line,"endColumn":utf16+2}}})
    }
}

fn inventory(report: &Value, format: &str) {
    assert_eq!(
        report["parity"]["semantic_context"],
        json!({"typescript":"not_applicable","csharp":"missing"})
    );
    assert_eq!(report["parity"]["completeness"], "incomplete");
    assert_eq!(report["parity"]["rule_set_violations"], json!([]));
    assert_eq!(report["parity"]["scope"]["roots"], json!(["cases.cs"]));
    if format == "json" {
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["files"].as_array().unwrap().len(), 1);
        assert_eq!(report["files"][0]["path"], "cases.cs");
        assert_eq!(report["project"]["complete"], true);
        assert_eq!(report["project"]["warnings"], json!([]));
    } else {
        let rules: Vec<_> = report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        let emitted: BTreeSet<_> = report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["ruleId"].as_str().unwrap())
            .collect();
        assert_eq!(rules, emitted.into_iter().collect::<Vec<_>>());
    }
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), canonical(&object[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn full_document(report: &Value, expected_sha256: &str) -> Option<String> {
    let bytes =
        serde_json::to_vec(&canonical(report)).expect("canonical object keys, preserved arrays");
    let digest = format!("{:x}", Sha256::digest(bytes));
    (digest != expected_sha256)
        .then(|| format!("complete document: expected {expected_sha256}, actual {digest}"))
}

fn check(label: &str, source: &str, rows: &[(u32, u32, u32, bool)], hashes: [&str; 2]) {
    let fixture = Fixture::new(label);
    fixture.write(source.as_bytes());
    let mut failures = Vec::new();
    // Check both actual formats before reporting behavioral failure, so a JSON
    // regression cannot prevent the corresponding Sonar contract from running.
    for (format, hash) in ["json", "sonar"].into_iter().zip(hashes) {
        let output = fixture.analyze(format);
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = document(&output, 0);
        inventory(&report, format);
        let actual = targets(&report, format);
        let expected: Vec<_> = rows.iter().map(|r| expected(format, r)).collect();
        if actual != expected {
            failures.push(format!(
                "{format} target mismatch: expected {expected:?}, actual {actual:?}"
            ));
        }
        if let Some(failure) = full_document(&report, hash) {
            failures.push(format!("{format} {failure}"));
        }
    }
    assert_eq!(fixture.source(), source.as_bytes());
    assert!(
        failures.is_empty(),
        "regression assertions failed for {label}: {failures:#?}"
    );
}

fn unicode_control() -> String {
    format!("// 😀 café\n{CONTROL}")
        .replace(
            "var indexCall = text[--i]",
            "var indexCall = (\"😀\" + text)[--i]",
        )
        .replace('\n', "\r\n")
}

fn unicode_barriers() -> String {
    format!("// 😀 café\n{BARRIERS}")
        .replace(
            "var explicitArithmetic = ((i++))",
            "var explicitArithmetic = \"😀\".Length + ((i++))",
        )
        .replace('\n', "\r\n")
}

#[test]
fn csharp_s881_cli_original_minimized_humanizer() {
    check(
        "original-minimized",
        ORIGINAL,
        &[],
        [
            "5ce1559aec1ca30297bbf09c20632e9a62116fcc0d2ffa892ac1c72b964a4a1d",
            "1b4e6117ea121eaeae0a864cdfb64565cc243e9729deff3fe1ceacd3e7a3f514",
        ],
    );
}

#[test]
fn csharp_s881_cli_lf_call_index_and_arithmetic() {
    check(
        "lf",
        CONTROL,
        &[(16, 37, 37, true), (18, 40, 40, false), (19, 34, 34, false)],
        [
            "4c75349d75665462746a55a8ae2b45b259b7bf70518eec83673c4a49e897ab85",
            "0374ee62e0a1fefb55bfb0ebd841f650e50d7ce32b50d3ee739ff61772f94ad6",
        ],
    );
}

#[test]
fn csharp_s881_cli_unicode_crlf_call_index_and_arithmetic() {
    check(
        "unicode-crlf",
        &unicode_control(),
        &[(17, 37, 37, true), (19, 40, 40, false), (20, 34, 34, false)],
        [
            "d2409ded95ca05ff2740168077a214d5d3f4d7a8e41652a59a7519d736efc5b8",
            "095a2ce7eaaa0cf9834b5230cf706b40d78ad61d92555c308e41af0643e98bfc",
        ],
    );
}

#[test]
fn csharp_s881_cli_clean_index_assignment_and_return() {
    check(
        "clean",
        CLEAN,
        &[],
        [
            "0f6375dbf51633869be9620a1e870fc49174910e9eba580436dcaa2f67622046",
            "50935eade96ce04e9df1f8f79d8fe96cea51cdeab0ab2d724a31c5db0251287b",
        ],
    );
}

#[test]
fn csharp_s881_cli_arithmetic_crosses_calls_indexes_and_expression_lambdas() {
    check(
        "barriers",
        BARRIERS,
        &[
            (8, 39, 39, false),
            (9, 39, 39, false),
            (10, 42, 42, false),
            (11, 52, 52, false),
            (14, 49, 49, false),
            (15, 55, 55, false),
            (16, 43, 43, false),
            (17, 36, 36, false),
            (18, 47, 47, false),
        ],
        [
            "73e5144514e5d0c36ad42e9d5a5f67e20c04adeab50c9228f9c7eb99e044bb51",
            "3820ebd93aff91dc35b8ec05b9510bb9484354bb301b5482b8fec87b71c8d6e5",
        ],
    );
}

#[test]
fn csharp_s881_cli_unicode_crlf_retains_scalar_and_utf16_ranges() {
    check(
        "barriers-unicode-crlf",
        &unicode_barriers(),
        &[
            (9, 39, 39, false),
            (10, 39, 39, false),
            (11, 42, 42, false),
            (12, 52, 52, false),
            (15, 49, 49, false),
            (16, 55, 55, false),
            (17, 43, 43, false),
            (18, 49, 50, false),
            (19, 47, 47, false),
        ],
        [
            "f25739186158b5d346ca8c0ace71dd0a0985ff078651e144d57e39586511d70a",
            "ac1469d263535ace972b12d27d94c13d4e20c6c9fce2be8df4d427dcb9ed9f03",
        ],
    );
}

#[test]
fn csharp_s881_cli_operator_kinds_match_installed_analyzer() {
    check(
        "operators",
        OPERATORS,
        &[
            (7, 19, 19, false),
            (8, 24, 24, false),
            (9, 24, 24, false),
            (10, 22, 22, false),
            (11, 25, 25, false),
            (28, 41, 41, false),
        ],
        [
            "3828b1e5e61aa89194bc9fe3c206af4c534cb6328bc3f15a04fe97483d435827",
            "c84b47ead6182608fdc4057b3db439b3bb27ab5ff89717c8101ccecb6bc359ce",
        ],
    );
}

#[test]
fn csharp_s881_cli_cache_reanalysis_preserves_exact_complete_documents() {
    let fixture = Fixture::new("cache");
    for format in ["json", "sonar"] {
        fixture.write(CLEAN.as_bytes());
        let clean = document(&fixture.analyze(format), 0);
        inventory(&clean, format);
        assert!(targets(&clean, format).is_empty());
        fixture.write(CONTROL.as_bytes());
        let changed = document(&fixture.analyze(format), 0);
        inventory(&changed, format);
        assert_eq!(
            targets(&changed, format),
            [(16, 37, 37, true), (18, 40, 40, false), (19, 34, 34, false)]
                .iter()
                .map(|r| expected(format, r))
                .collect::<Vec<_>>()
        );
        assert_eq!(changed, document(&fixture.analyze(format), 0));
        fixture.write(CLEAN.as_bytes());
        assert_eq!(clean, document(&fixture.analyze(format), 0));
    }
    assert_eq!(fixture.source(), CLEAN.as_bytes());
}

#[test]
fn csharp_s881_cli_preserves_malformed_and_invalid_utf8_incompleteness() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"class Broken { void M( i++ + 1; }\n".as_slice(),
        b"class Broken {\xff}\n".as_slice(),
    ] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let report = document(&fixture.analyze(format), 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            assert!(targets(&report, format).is_empty());
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
                assert!(!report["project"]["warnings"].as_array().unwrap().is_empty());
            }
        }
        assert_eq!(fixture.source(), source);
    }
}
