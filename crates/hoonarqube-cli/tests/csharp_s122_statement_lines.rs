use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S122";
const MESSAGE: &str = "Reformat the code to have only one statement per line.";
// Exact installed SonarAnalyzer.CSharp 10.33 findings and independently reviewed
// complete report predictions preserve unrelated ordered duplicates and metadata.
const SYNTAX: &str = r"using System;
namespace Scope;
class Cases
{
    void Step() { }
    void if_inline(bool b)
    {
        if (b) Step();
    }
    void if_return(bool b)
    {
        if (b) return;
    }
    void if_multiline(bool b)
    {
        if (b)
            Step();
    }
    void if_inline_block(bool b)
    {
        if (b) { Step(); }
    }
    void if_empty_block(bool b)
    {
        if (b) { }
    }
    void if_else_inline(bool b)
    {
        if (b) Step(); else Step();
    }
    void if_else_multiline(bool b)
    {
        if (b)
            Step();
        else
            Step();
    }
    void else_inline(bool b)
    {
        if (b)
            Step();
        else Step();
    }
    void nested_if_inline(bool b)
    {
        if (b) if (b) Step();
    }
    void if_multiline_condition(bool b)
    {
        if (
            b) Step();
    }
    void if_trailing_sibling(bool b)
    {
        if (b) Step(); Step();
    }
    void if_block_sibling(bool b)
    {
        if (b) { } Step();
    }
    void two_siblings(bool b)
    {
        Step(); Step();
    }
    void one_statement(bool b)
    {
        Step();
    }
    void while_inline(bool b)
    {
        while (b) Step();
    }
    void while_multiline(bool b)
    {
        while (b)
            Step();
    }
    void for_inline(bool b)
    {
        for (int i = 0; i < 1; i++) Step();
    }
    void for_empty_block(bool b)
    {
        for (int i = 0; i < 1; i++) { }
    }
    void foreach_inline(bool b)
    {
        foreach (var x in new[] { 1 }) Step();
    }
    void do_inline(bool b)
    {
        do Step(); while (b);
    }
    void do_multiline(bool b)
    {
        do
            Step();
        while (b);
    }
    void lock_inline(bool b)
    {
        lock (this) Step();
    }
    void using_inline(bool b)
    {
        using (var s = new System.IO.MemoryStream()) Step();
    }
    void checked_inline(bool b)
    {
        checked { Step(); }
    }
    void unchecked_inline(bool b)
    {
        unchecked { Step(); }
    }
    void try_catch_inline(bool b)
    {
        try { Step(); } catch (Exception) { Step(); }
    }
    void local_function_inline(bool b)
    {
        void Local() { Step(); }
    }
    void lambda_inline(bool b)
    {
        Action f = () => { Step(); };
    }
    void unicode_if(bool b)
    {
        /* 😀 café */ if (b) Step();
    }
    void empty_statement_inline(bool b)
    {
        if (b) ;
    }
}
";

const CALLABLES: &str = r"using System;
namespace Scope;
class Callables
{
    void Step() { }
    void lambda_one(bool b)
    {
        Action f = () => { Step(); };
    }
    void lambda_two(bool b)
    {
        Action f = () => { Step(); Step(); };
    }
    void lambda_if(bool b)
    {
        Action f = () => { if (b) Step(); };
    }
    void anonymous_one(bool b)
    {
        Action f = delegate { Step(); };
    }
    void anonymous_two(bool b)
    {
        Action f = delegate { Step(); Step(); };
    }
    void lambda_outer_sibling(bool b)
    {
        Action f = () => { Step(); }; Step();
    }
    void lambda_multiline_two(bool b)
    {
        Action f = () =>
        {
            Step(); Step();
        };
    }
}
";

const ORIGINAL: &str = r#"using System;
class Cases
{
    string M(int number)
    {
        if (number == 11) return "ενδέκατος";
        return string.Empty;
    }
}
"#;

const BAD: &str = r"class Pipeline
{
    void Run()
    {
        Load();
        Save(); Archive();
        Purge();
    }
}
";

const GOOD: &str = r"class Pipeline
{
    void Run()
    {
        Load();
        Save();
        Archive();
        Purge();
    }
}
";
struct Fixture(PathBuf, String);

impl Fixture {
    fn new(label: &str, filename: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s122-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("owned fixture directory");
        Self(path, filename.into())
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join(&self.1), source).expect("fixture source");
    }

    fn source(&self) -> Vec<u8> {
        std::fs::read(self.0.join(&self.1)).expect("source readback")
    }

    fn analyze(&self, format: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                &self.1,
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

fn expected(format: &str, filename: &str, row: &(u32, u32, u32, u32, u32, u32)) -> Value {
    let &(sl, sc, el, ec, su, eu) = row;
    if format == "json" {
        json!({"rule_key":KEY,"message":MESSAGE,"range":{"start":{"line":sl,"column":sc},"end":{"line":el,"column":ec}}})
    } else {
        json!({"ruleId":KEY,"primaryLocation":{"filePath":filename,"message":MESSAGE,"textRange":{"startLine":sl,"startColumn":su,"endLine":el,"endColumn":eu}}})
    }
}

fn inventory(report: &Value, format: &str, filename: &str) {
    assert_eq!(
        report["parity"]["semantic_context"],
        json!({"typescript":"not_applicable","csharp":"missing"})
    );
    assert_eq!(report["parity"]["completeness"], "incomplete");
    assert_eq!(report["parity"]["rule_set_violations"], json!([]));
    assert_eq!(report["parity"]["scope"]["roots"], json!([filename]));
    if format == "json" {
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["files"].as_array().unwrap().len(), 1);
        assert_eq!(report["files"][0]["path"], filename);
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

fn check(
    label: &str,
    filename: &str,
    source: &str,
    rows: &[(u32, u32, u32, u32, u32, u32)],
    hashes: [&str; 2],
) {
    let fixture = Fixture::new(label, filename);
    fixture.write(source.as_bytes());
    // Execute both formats before any assertion, including the signed red run.
    let outputs = [fixture.analyze("json"), fixture.analyze("sonar")];
    let mut failures = Vec::new();
    for ((format, hash), output) in ["json", "sonar"].into_iter().zip(hashes).zip(&outputs) {
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = document(output, 0);
        inventory(&report, format, filename);
        let actual = targets(&report, format);
        let expected: Vec<_> = rows.iter().map(|r| expected(format, filename, r)).collect();
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

fn unicode(source: &str) -> String {
    format!("// 😀 café\n{source}").replace('\n', "\r\n")
}

#[test]
fn csharp_s122_cli_lf() {
    check(
        "lf",
        "cases.cs",
        SYNTAX,
        &[
            (8, 8, 8, 22, 8, 22),
            (12, 8, 12, 22, 8, 22),
            (21, 8, 21, 26, 8, 26),
            (29, 8, 29, 35, 8, 35),
            (46, 8, 46, 29, 8, 29),
            (55, 8, 55, 30, 8, 30),
            (59, 8, 59, 26, 8, 26),
            (63, 8, 63, 23, 8, 23),
            (71, 8, 71, 25, 8, 25),
            (80, 8, 80, 43, 8, 43),
            (88, 8, 88, 46, 8, 46),
            (92, 8, 92, 29, 8, 29),
            (102, 8, 102, 27, 8, 27),
            (106, 8, 106, 60, 8, 60),
            (110, 8, 110, 27, 8, 27),
            (114, 8, 114, 29, 8, 29),
            (118, 8, 118, 53, 8, 53),
            (122, 8, 122, 32, 8, 32),
            (130, 21, 130, 35, 22, 36),
            (134, 8, 134, 16, 8, 16),
        ],
        [
            "397ec02cf1e53883f57db9a6a86eec0a45f3bdd7531eeae1b435a87916c18bd9",
            "f40b683b042e88f034d5af4eab0d461ed51aec8f185815cdf182cd8014f29e80",
        ],
    );
}

#[test]
fn csharp_s122_cli_unicode_crlf() {
    check(
        "unicode-crlf",
        "cases.cs",
        &unicode(SYNTAX),
        &[
            (9, 8, 9, 22, 8, 22),
            (13, 8, 13, 22, 8, 22),
            (22, 8, 22, 26, 8, 26),
            (30, 8, 30, 35, 8, 35),
            (47, 8, 47, 29, 8, 29),
            (56, 8, 56, 30, 8, 30),
            (60, 8, 60, 26, 8, 26),
            (64, 8, 64, 23, 8, 23),
            (72, 8, 72, 25, 8, 25),
            (81, 8, 81, 43, 8, 43),
            (89, 8, 89, 46, 8, 46),
            (93, 8, 93, 29, 8, 29),
            (103, 8, 103, 27, 8, 27),
            (107, 8, 107, 60, 8, 60),
            (111, 8, 111, 27, 8, 27),
            (115, 8, 115, 29, 8, 29),
            (119, 8, 119, 53, 8, 53),
            (123, 8, 123, 32, 8, 32),
            (131, 21, 131, 35, 22, 36),
            (135, 8, 135, 16, 8, 16),
        ],
        [
            "f95181723fc255d1e45be8cf60c31dde71480d86d47e2bd6602f1aca7a9f3bc8",
            "8e60ce1f28f4894fcab6681cc7406c6f233192fc45a024c8636169e92855417c",
        ],
    );
}

#[test]
fn csharp_s122_cli_callables() {
    check(
        "callables",
        "cases.cs",
        CALLABLES,
        &[
            (12, 8, 12, 45, 8, 45),
            (16, 8, 16, 44, 8, 44),
            (24, 8, 24, 48, 8, 48),
            (28, 8, 28, 45, 8, 45),
            (34, 12, 34, 27, 12, 27),
        ],
        [
            "1bce60a6c1e0bad43ace1026971bbc3096fac213600951a86383e03cab967526",
            "cff1df0f2b87405b7b4fb7cc5a1acf3fc00b82ac2737a74990b6da3dfd575fe5",
        ],
    );
}

#[test]
fn csharp_s122_cli_callables_unicode_crlf() {
    check(
        "callables-unicode-crlf",
        "cases.cs",
        &unicode(CALLABLES),
        &[
            (13, 8, 13, 45, 8, 45),
            (17, 8, 17, 44, 8, 44),
            (25, 8, 25, 48, 8, 48),
            (29, 8, 29, 45, 8, 45),
            (35, 12, 35, 27, 12, 27),
        ],
        [
            "a675f8e7ff76defe84afa1b13ef89a78a42a781875b7027ae0721b5de60b3b2b",
            "e0a141e6099da7c771a8a215d3ab73707a9aae0bf3123f5c4e8fa07b94402cb8",
        ],
    );
}

#[test]
fn csharp_s122_cli_original_minimized() {
    check(
        "original-minimized",
        "cases.cs",
        ORIGINAL,
        &[(6, 8, 6, 45, 8, 45)],
        [
            "42a61cf719d19bf0a156c57818c93705864a68b2386f842da79ca049af045397",
            "18a44811e36647e1fbd742f53d29bea56b39093eec47640d32bbc9ab7a202fb7",
        ],
    );
}

#[test]
fn csharp_s122_cli_original_bad() {
    check(
        "original-bad",
        "s122_bad.cs",
        BAD,
        &[(6, 8, 6, 26, 8, 26)],
        [
            "ff77e2c3a7d5836c2eb00eec3ca183e04c0503e6fd8abf4949896e53bd3a6efa",
            "cadf9b14f2376b1fd0ce0eb50d36ee2fa408e47f0fe93f5e43d5f1db28399033",
        ],
    );
}

#[test]
fn csharp_s122_cli_original_good() {
    check(
        "original-good",
        "s122_good.cs",
        GOOD,
        &[],
        [
            "a5035ef24b1868a2d0621b0d81d4e0c723429b5257e2dd780372681511cf255b",
            "08a7dd90762c978da257f95608cd53f66a2d322b2e670607f958003383da5453",
        ],
    );
}

#[test]
fn csharp_s122_cli_cache_invalidation_and_reanalysis() {
    let fixture = Fixture::new("cache", "cases.cs");
    fixture.write(GOOD.as_bytes());
    let clean = [fixture.analyze("json"), fixture.analyze("sonar")];
    fixture.write(ORIGINAL.as_bytes());
    let changed = [fixture.analyze("json"), fixture.analyze("sonar")];
    let repeated = [fixture.analyze("json"), fixture.analyze("sonar")];
    fixture.write(GOOD.as_bytes());
    let restored = [fixture.analyze("json"), fixture.analyze("sonar")];
    for (index, format) in ["json", "sonar"].into_iter().enumerate() {
        let before = document(&clean[index], 0);
        let after = document(&changed[index], 0);
        inventory(&before, format, "cases.cs");
        inventory(&after, format, "cases.cs");
        assert!(targets(&before, format).is_empty());
        assert_eq!(
            targets(&after, format),
            vec![expected(format, "cases.cs", &(6, 8, 6, 45, 8, 45))]
        );
        assert_eq!(after, document(&repeated[index], 0));
        assert_eq!(before, document(&restored[index], 0));
    }
    assert_eq!(fixture.source(), GOOD.as_bytes());
}

#[test]
fn csharp_s122_cli_preserves_malformed_and_invalid_utf8_incompleteness() {
    let fixture = Fixture::new("incomplete", "cases.cs");
    for source in [
        b"class Broken { void M( if (b) Step(); }\n".as_slice(),
        b"class Broken {\xff}\n".as_slice(),
    ] {
        fixture.write(source);
        let outputs = [fixture.analyze("json"), fixture.analyze("sonar")];
        for (format, output) in ["json", "sonar"].into_iter().zip(&outputs) {
            let report = document(output, 2);
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
