use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S1067";
// The installed-analyzer controls qualify these complete component roots.
// Four opaque-descendant count overfires remain deliberately outside this fix.
const CONTROL: &str = r#"using System;
public static class Cases
{
    private static bool Id(bool value) => value;
    private static bool Eval(Func<bool> value) => value();
    public static bool PlainFour(bool a, bool b, bool c, bool d, bool e, bool f) => a && b && c && d && e;
    public static bool LogicalThree(bool a, bool b, bool c, bool d, bool e, bool f) => a && b && c && d;
    public static bool DuplicateFive(bool a, bool b, bool c, bool d, bool e, bool f) => a || (b && c && d && e && f);
    public static bool OuterParentheses(bool a, bool b, bool c, bool d, bool e, bool f) => (a || (b && c && d && e && f));
    public static bool TripleParentheses(bool a, bool b, bool c, bool d, bool e, bool f) => (((a && b && c && d && e)));
    public static bool LogicalNot(bool a, bool b, bool c, bool d, bool e, bool f) => !(a || (b && c && d && e && f));
    public static bool Comparison(bool a, bool b, bool c, bool d, bool e, bool f) => (a && b && c && d && e) == f;
    public static bool Bitwise(bool a, bool b, bool c, bool d, bool e, bool f) => ((a && b && c) & (d && e)) || f;
    public static bool SeparateCalls(bool a, bool b, bool c, bool d, bool e, bool f) => Id(a && b && c && d && e) | Id(a && b && c && d && e);
    public static bool CallLeak(bool a, bool b, bool c, bool d, bool e, bool f) => a || Id(b && c && d && e && f);
    public static bool LambdaLeak(bool a, bool b, bool c, bool d, bool e, bool f) => a || Eval(() => (b && c && d && e && f));
    public static bool CastLeak(bool a, bool b, bool c, bool d, bool e, bool f) => a || (bool)(b && c && d && e && f);
    public static bool CleanCallComponents(bool a, bool b, bool c, bool d, bool e, bool f) => Id(a && b && c) || Id(d && e && f);
    public static bool RomanianShape(bool feminine, string words) => feminine && (!words.EndsWith("zece") && (words.EndsWith("a") || words.EndsWith("ă") || words.EndsWith("e") || words.EndsWith("i")));
    public static bool ConditionalControl(bool a, bool b, bool c, bool d, bool e, bool f) => a && b || c ? d && e : false;
    public static bool ParenthesizedThree(bool a, bool b, bool c, bool d, bool e, bool f) => (a || (b && c && d));
    public static bool NegatedThree(bool a, bool b, bool c, bool d, bool e, bool f) => !(a && b && c && d);
    public static bool LexicalDecoy() => "&& || ? : && ||" != "";
}
"#;
const EXTRA: &str = r"public static class Extra
{
    public static bool EqualityFour(bool a, bool b, bool c, bool d, bool e, bool f) => (a && b && c) == (d && e && f);
    public static bool BitwiseFour(bool a, bool b, bool c, bool d, bool e, bool f) => (a && b && c) & (d && e && f);
    public static bool NegatedEqualityFour(bool a, bool b, bool c, bool d, bool e, bool f) => !((a && b && c) == (d && e && f));
    public static bool CleanEqualityTwo(bool a, bool b, bool c, bool d) => (a && b) == (c && d);
}
";
const EXPECTED: &[(u32, u32, u32, u32)] = &[
    (6, 84, 105, 4),
    (8, 88, 116, 5),
    (9, 91, 121, 5),
    (10, 92, 119, 4),
    (11, 85, 116, 5),
    (12, 85, 113, 4),
    (13, 82, 113, 4),
    (14, 91, 112, 4),
    (14, 119, 140, 4),
    (15, 83, 113, 5),
    (15, 91, 112, 4),
    (16, 85, 125, 5),
    (16, 101, 124, 4),
    (17, 83, 117, 5),
    (17, 94, 117, 4),
    (18, 94, 128, 5),
    (19, 69, 200, 5),
    (20, 93, 121, 4),
];

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1067-logical-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("owned fixture directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("Control.cs"), source).expect("fixture source");
    }

    fn read(&self) -> Vec<u8> {
        std::fs::read(self.0.join("Control.cs")).expect("source readback")
    }

    fn cli(&self, argv: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(argv)
            .output()
            .expect("actual CLI")
    }

    fn analyze(&self, format: &str) -> Output {
        self.cli(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            format,
            "--",
            "Control.cs",
        ])
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

fn expected(format: &str, line: u32, start: u32, end: u32, count: u32) -> Value {
    let message = format!(
        "Reduce the number of conditional operators ({count}) used in the expression (maximum allowed 3)."
    );
    if format == "json" {
        json!({"rule_key":KEY,"message":message,"range":{"start":{"line":line,"column":start},"end":{"line":line,"column":end}}})
    } else {
        json!({"ruleId":KEY,"primaryLocation":{"filePath":"Control.cs","message":message,"textRange":{"startLine":line,"startColumn":start,"endLine":line,"endColumn":end}}})
    }
}

fn expected_controls(format: &str, unicode: bool) -> Vec<Value> {
    EXPECTED
        .iter()
        .map(|&(line, start, end, count)| {
            let shift = if unicode && line == 8 {
                if format == "sonar" { 9 } else { 8 }
            } else {
                0
            };
            expected(format, line, start + shift, end + shift, count)
        })
        .collect()
}

fn complete_inventory(report: &Value, format: &str) {
    if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        assert_eq!(report["files"].as_array().unwrap().len(), 1);
        assert_eq!(report["files"][0]["path"], "Control.cs");
    }
    assert_eq!(report["parity"]["semantic_context"]["csharp"], "missing");
    assert_eq!(report["parity"]["completeness"], "incomplete");
    assert_eq!(report["parity"]["rule_set_violations"], json!([]));
}

#[test]
fn csharp_s1067_logical_cli_matches_complete_roots_and_preserves_opaque_count_residuals() {
    let fixture = Fixture::new("roots");
    fixture.write(CONTROL.as_bytes());
    for format in ["json", "sonar"] {
        let output = fixture.analyze(format);
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = document(&output, 0);
        complete_inventory(&report, format);
        assert_eq!(targets(&report, format), expected_controls(format, false));
    }
    assert_eq!(fixture.read(), CONTROL.as_bytes());
}

#[test]
fn csharp_s1067_logical_cli_detects_joined_equality_and_bitwise_components() {
    let fixture = Fixture::new("joined");
    fixture.write(EXTRA.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_inventory(&report, format);
        assert_eq!(
            targets(&report, format),
            vec![
                expected(format, 3, 87, 117, 4),
                expected(format, 4, 86, 115, 4),
                expected(format, 5, 94, 127, 4),
            ]
        );
        if format == "sonar" {
            let descriptor = report["rules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|rule| rule["id"] == KEY)
                .unwrap();
            assert_eq!(
                descriptor,
                &json!({"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `csharpsquid:S1067`.","engineId":"hoonarqube","id":KEY,"impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":KEY,"severity":"CRITICAL","type":"CODE_SMELL"})
            );
        }
    }
    assert_eq!(fixture.read(), EXTRA.as_bytes());
}

#[test]
fn csharp_s1067_logical_cli_preserves_scalar_and_utf16_columns_with_bom_and_crlf() {
    let fixture = Fixture::new("unicode");
    let source = format!(
        "\u{feff}{}",
        CONTROL
            .replace(
                "    public static bool DuplicateFive",
                "    /* 😀 */ public static bool DuplicateFive"
            )
            .replace('\n', "\r\n")
    );
    assert!(source.as_bytes().starts_with(b"\xef\xbb\xbf"));
    assert!(source.contains("\r\n"));
    fixture.write(source.as_bytes());
    let mut duplicate_columns = Vec::new();
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_inventory(&report, format);
        let actual = targets(&report, format);
        assert_eq!(actual, expected_controls(format, true));
        let column = if format == "json" {
            actual[1]["range"]["start"]["column"].as_u64().unwrap()
        } else {
            actual[1]["primaryLocation"]["textRange"]["startColumn"]
                .as_u64()
                .unwrap()
        };
        duplicate_columns.push(column);
    }
    assert_eq!(duplicate_columns, vec![96, 97]);
    assert_eq!(fixture.read(), source.as_bytes());
}

#[test]
fn csharp_s1067_logical_cli_keeps_below_threshold_and_lexical_controls_clean() {
    let fixture = Fixture::new("clean");
    let source = r#"class C {
    bool Plain(bool a, bool b, bool c, bool d) => a && b && c && d;
    bool Parentheses(bool a, bool b, bool c, bool d) => (a || (b && c && d));
    bool Negated(bool a, bool b, bool c, bool d) => !(a && b && c && d);
    bool Equality(bool a, bool b, bool c, bool d) => (a && b) == (c && d);
    bool Decoy() => "&& || ? : && ||" != "";
}
"#;
    fixture.write(source.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_inventory(&report, format);
        assert!(targets(&report, format).is_empty());
    }
    assert_eq!(fixture.read(), source.as_bytes());
}

#[test]
fn csharp_s1067_logical_cli_cache_reanalysis_uses_changed_component_roots() {
    let fixture = Fixture::new("cache");
    let analyze = || {
        fixture.cli(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            "--cache-dir",
            "cache",
            "Control.cs",
        ])
    };
    fixture.write(EXTRA.as_bytes());
    let first = document(&analyze(), 0);
    assert_eq!(targets(&first, "json").len(), 3);
    fixture.write(CONTROL.as_bytes());
    let changed = document(&analyze(), 0);
    assert_eq!(targets(&changed, "json"), expected_controls("json", false));
    assert_eq!(changed, document(&analyze(), 0));
    assert_eq!(fixture.read(), CONTROL.as_bytes());
}

#[test]
fn csharp_s1067_logical_cli_keeps_malformed_and_invalid_utf8_incomplete() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"public class Broken { bool M(bool a) => a || (a && ; }\n".as_slice(),
        b"\xffpublic class Broken { }\n".as_slice(),
    ] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let report = document(&fixture.analyze(format), 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
            }
            assert!(targets(&report, format).is_empty());
        }
        assert_eq!(fixture.read(), source);
    }
}

#[test]
fn csharp_s1067_logical_cli_unavailable_edits_preserve_source_and_complete_reports() {
    let fixture = Fixture::new("no-edit");
    fixture.write(CONTROL.as_bytes());
    let before = fixture.analyze("json");
    let report = document(&before, 0);
    for mode in ["--diff", "--apply"] {
        let output = fixture.cli(&[
            "fix",
            "--profile",
            "sonar-parity",
            "--rule",
            KEY,
            "--suggestion",
            "csharpsquid:S1067=extract-condition",
            mode,
            "--json",
            "Control.cs",
        ]);
        let refused = document(&output, 1);
        assert_eq!(refused["applied"], 0);
        assert_eq!(refused["mechanical"], 0);
        assert_eq!(refused["files"], json!([]));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "selected suggestion csharpsquid:S1067=extract-condition is unavailable\n"
        );
        let after = fixture.analyze("json");
        assert_eq!(document(&after, 0), report);
        assert_eq!(after.stderr, before.stderr);
        assert_eq!(fixture.read(), CONTROL.as_bytes());
    }
}
