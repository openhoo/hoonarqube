use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S6610";

// Installed SonarAnalyzer.CSharp 10.33 and independent root whole-report
// projections pin direct BMP additions and preserve the explicit literal gaps.

const CASES: &str = r####"using System;
namespace S6610Boundary;
public class Cases
{
    public bool ascii_StartsWith(string text)
    {
        return text.StartsWith("x");
    }
    public bool ascii_EndsWith(string text)
    {
        return text.EndsWith("x");
    }
    public bool farsi_StartsWith(string text)
    {
        return text.StartsWith("ی");
    }
    public bool farsi_EndsWith(string text)
    {
        return text.EndsWith("ی");
    }
    public bool romanian_StartsWith(string text)
    {
        return text.StartsWith("ă");
    }
    public bool romanian_EndsWith(string text)
    {
        return text.EndsWith("ă");
    }
    public bool cjk_StartsWith(string text)
    {
        return text.StartsWith("字");
    }
    public bool cjk_EndsWith(string text)
    {
        return text.EndsWith("字");
    }
    public bool standalone_combining_mark_StartsWith(string text)
    {
        return text.StartsWith("̆");
    }
    public bool standalone_combining_mark_EndsWith(string text)
    {
        return text.EndsWith("̆");
    }
    public bool empty_StartsWith(string text)
    {
        return text.StartsWith("");
    }
    public bool empty_EndsWith(string text)
    {
        return text.EndsWith("");
    }
    public bool multiple_ascii_StartsWith(string text)
    {
        return text.StartsWith("ab");
    }
    public bool multiple_ascii_EndsWith(string text)
    {
        return text.EndsWith("ab");
    }
    public bool multiple_bmp_StartsWith(string text)
    {
        return text.StartsWith("ăی");
    }
    public bool multiple_bmp_EndsWith(string text)
    {
        return text.EndsWith("ăی");
    }
    public bool supplementary_StartsWith(string text)
    {
        return text.StartsWith("😀");
    }
    public bool supplementary_EndsWith(string text)
    {
        return text.EndsWith("😀");
    }
    public bool combining_sequence_StartsWith(string text)
    {
        return text.StartsWith("ă");
    }
    public bool combining_sequence_EndsWith(string text)
    {
        return text.EndsWith("ă");
    }
    public bool escaped_ascii(string text)
    {
        return text.EndsWith("\u0078");
    }
    public bool escaped_romanian(string text)
    {
        return text.EndsWith("\u0103");
    }
    public bool escaped_farsi(string text)
    {
        return text.EndsWith("\u06CC");
    }
    public bool escaped_hex_bmp(string text)
    {
        return text.EndsWith("\x0103");
    }
    public bool escaped_big_u_bmp(string text)
    {
        return text.EndsWith("\U00000103");
    }
    public bool escaped_short_newline(string text)
    {
        return text.EndsWith("\n");
    }
    public bool escaped_supplementary(string text)
    {
        return text.EndsWith("\U0001F600");
    }
    public bool escaped_surrogate_pair(string text)
    {
        return text.EndsWith("\uD83D\uDE00");
    }
    public bool escaped_combining_sequence(string text)
    {
        return text.EndsWith("a\u0306");
    }
    public bool raw_ascii(string text)
    {
        return text.EndsWith("""x""");
    }
    public bool raw_romanian(string text)
    {
        return text.EndsWith("""ă""");
    }
    public bool raw_cjk(string text)
    {
        return text.EndsWith("""字""");
    }
    public bool verbatim_ascii(string text)
    {
        return text.EndsWith(@"x");
    }
    public bool verbatim_romanian(string text)
    {
        return text.EndsWith(@"ă");
    }
    public bool verbatim_farsi(string text)
    {
        return text.EndsWith(@"ی");
    }
    public bool char_ascii(string text)
    {
        return text.EndsWith('x');
    }
    public bool char_romanian(string text)
    {
        return text.EndsWith('ă');
    }
    public bool char_cjk(string text)
    {
        return text.EndsWith('字');
    }
    public bool comparison_two_StartsWith(string text)
    {
        return text.StartsWith("ă", StringComparison.Ordinal);
    }
    public bool comparison_three_StartsWith(string text)
    {
        return text.StartsWith("ă", false, System.Globalization.CultureInfo.InvariantCulture);
    }
    public bool comparison_two_EndsWith(string text)
    {
        return text.EndsWith("ă", StringComparison.Ordinal);
    }
    public bool comparison_three_EndsWith(string text)
    {
        return text.EndsWith("ă", false, System.Globalization.CultureInfo.InvariantCulture);
    }
}
"####;

struct Fixture(PathBuf, String);

impl Fixture {
    fn new(label: &str, filename: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s6610-{label}-{}-{id}",
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

const LF_JSON_TARGETS: &str = r####"[{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":7,"column":20},"end":{"line":7,"column":30}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":11,"column":20},"end":{"line":11,"column":28}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":15,"column":20},"end":{"line":15,"column":30}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":19,"column":20},"end":{"line":19,"column":28}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":23,"column":20},"end":{"line":23,"column":30}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":27,"column":20},"end":{"line":27,"column":28}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":31,"column":20},"end":{"line":31,"column":30}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":35,"column":20},"end":{"line":35,"column":28}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":39,"column":20},"end":{"line":39,"column":30}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":43,"column":20},"end":{"line":43,"column":28}}}]"####;

const LF_SONAR_TARGETS: &str = r####"[{"primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"endColumn":30,"endLine":7,"startColumn":20,"startLine":7}},"ruleId":"csharpsquid:S6610"},{"primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"endColumn":28,"endLine":11,"startColumn":20,"startLine":11}},"ruleId":"csharpsquid:S6610"},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":15,"startColumn":20,"endLine":15,"endColumn":30}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":19,"startColumn":20,"endLine":19,"endColumn":28}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":23,"startColumn":20,"endLine":23,"endColumn":30}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":27,"startColumn":20,"endLine":27,"endColumn":28}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":31,"startColumn":20,"endLine":31,"endColumn":30}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":35,"startColumn":20,"endLine":35,"endColumn":28}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":39,"startColumn":20,"endLine":39,"endColumn":30}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":43,"startColumn":20,"endLine":43,"endColumn":28}}}]"####;

const UNICODE_CRLF_JSON_TARGETS: &str = r####"[{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":8,"column":33},"end":{"line":8,"column":43}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":12,"column":33},"end":{"line":12,"column":41}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":16,"column":33},"end":{"line":16,"column":43}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":20,"column":33},"end":{"line":20,"column":41}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":24,"column":33},"end":{"line":24,"column":43}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":28,"column":33},"end":{"line":28,"column":41}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":32,"column":33},"end":{"line":32,"column":43}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":36,"column":33},"end":{"line":36,"column":41}}},{"rule_key":"csharpsquid:S6610","message":"\"StartsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":40,"column":33},"end":{"line":40,"column":43}}},{"rule_key":"csharpsquid:S6610","message":"\"EndsWith\" overloads that take a \"char\" should be used","range":{"start":{"line":44,"column":33},"end":{"line":44,"column":41}}}]"####;

const UNICODE_CRLF_SONAR_TARGETS: &str = r####"[{"primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"endColumn":44,"endLine":8,"startColumn":34,"startLine":8}},"ruleId":"csharpsquid:S6610"},{"primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"endColumn":42,"endLine":12,"startColumn":34,"startLine":12}},"ruleId":"csharpsquid:S6610"},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":16,"startColumn":34,"endLine":16,"endColumn":44}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":20,"startColumn":34,"endLine":20,"endColumn":42}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":24,"startColumn":34,"endLine":24,"endColumn":44}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":28,"startColumn":34,"endLine":28,"endColumn":42}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":32,"startColumn":34,"endLine":32,"endColumn":44}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":36,"startColumn":34,"endLine":36,"endColumn":42}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"StartsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":40,"startColumn":34,"endLine":40,"endColumn":44}}},{"ruleId":"csharpsquid:S6610","primaryLocation":{"filePath":"cases.cs","message":"\"EndsWith\" overloads that take a \"char\" should be used","textRange":{"startLine":44,"startColumn":34,"endLine":44,"endColumn":42}}}]"####;

fn check(label: &str, source: &str, targets_json: [&str; 2], hashes: [&str; 2]) {
    let fixture = Fixture::new(label, "cases.cs");
    fixture.write(source.as_bytes());
    // Both actual formats execute before assertions, including the signed red.
    let outputs = [fixture.analyze("json"), fixture.analyze("sonar")];
    let mut failures = Vec::new();
    for (((format, expected_targets), hash), output) in ["json", "sonar"]
        .into_iter()
        .zip(targets_json)
        .zip(hashes)
        .zip(&outputs)
    {
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = document(output, 0);
        inventory(&report, format, "cases.cs");
        let expected: Vec<Value> = serde_json::from_str(expected_targets).unwrap();
        let actual = targets(&report, format);
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
        "all 42 boundaries for {label}: {failures:#?}"
    );
}

fn unicode_crlf() -> String {
    let source = CASES.replace("        return ", "        /* 😀 café */ return ");
    format!("// 😀 astral header; inline prefixes also test UTF16 columns\n{source}")
        .replace('\n', "\r\n")
}

#[test]
fn csharp_s6610_cli_all_42_boundaries_lf() {
    check(
        "lf",
        CASES,
        [LF_JSON_TARGETS, LF_SONAR_TARGETS],
        [
            "3af1fe81a8ca15361fcf57405dadc3fc8d2840ab28714946bc2a711c4aae72b7",
            "943d51542ec46439a91901e61f51c1d34578f2bb8429d35115ebb390e4c278bf",
        ],
    );
}

#[test]
fn csharp_s6610_cli_all_42_boundaries_unicode_crlf() {
    check(
        "unicode-crlf",
        &unicode_crlf(),
        [UNICODE_CRLF_JSON_TARGETS, UNICODE_CRLF_SONAR_TARGETS],
        [
            "daa69576925e2eed7cc84713c0c650dbb915a5119eadc508ada2ff3bf2e2a84f",
            "678684736fe6cfc728810036b991e8672ff76eb9fe87640546d4ebf311f9829d",
        ],
    );
}

const CLEAN: &str =
    "class C\n{\n    bool M(string text)\n    {\n        return text.EndsWith(\"ab\");\n    }\n}\n";

#[test]
fn csharp_s6610_cli_complete_cache_transition_and_restoration() {
    let fixture = Fixture::new("cache", "cases.cs");
    fixture.write(CLEAN.as_bytes());
    let clean = [fixture.analyze("json"), fixture.analyze("sonar")];
    fixture.write(CASES.as_bytes());
    let changed = [fixture.analyze("json"), fixture.analyze("sonar")];
    let repeated = [fixture.analyze("json"), fixture.analyze("sonar")];
    fixture.write(CLEAN.as_bytes());
    let restored = [fixture.analyze("json"), fixture.analyze("sonar")];
    for (index, format) in ["json", "sonar"].into_iter().enumerate() {
        let before = document(&clean[index], 0);
        let after = document(&changed[index], 0);
        inventory(&before, format, "cases.cs");
        inventory(&after, format, "cases.cs");
        assert!(targets(&before, format).is_empty());
        let expected: Vec<Value> =
            serde_json::from_str([LF_JSON_TARGETS, LF_SONAR_TARGETS][index]).unwrap();
        assert_eq!(targets(&after, format), expected);
        assert_eq!(after, document(&repeated[index], 0));
        assert_eq!(before, document(&restored[index], 0));
    }
    assert_eq!(fixture.source(), CLEAN.as_bytes());
}

#[test]
fn csharp_s6610_cli_preserves_malformed_and_invalid_utf8_diagnostics() {
    let fixture = Fixture::new("incomplete", "cases.cs");
    for source in [
        b"class Broken { bool M( return text.EndsWith(\"x\"); }\n".as_slice(),
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
