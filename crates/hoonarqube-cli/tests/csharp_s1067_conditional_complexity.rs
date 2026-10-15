use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S1067";
// Exact source used by the retained installed-analyzer driver. The eight
// ternary-bearing expectations come from its actual diagnostics; the extra
// pure-logical inner finding remains an explicitly out-of-package residual.
const BOUNDARY: &str = r"namespace S1067BoundaryProbes
{
    public static class Cases
    {
        public static int TernaryThree(bool a, bool b, bool c) => (a ? 1 : 0) + (b ? 1 : 0) + (c ? 1 : 0);
        public static int TernaryFour(bool a, bool b, bool c, bool d) => (a ? 1 : 0) + (b ? 1 : 0) + (c ? 1 : 0) + (d ? 1 : 0);
        public static bool MixedFour(bool a, bool b, bool c, bool d, bool e) => a && b || c ? d && e : false;
        public static int NestedCondition(bool a, bool b, bool c, bool d, bool e) => (a ? b : c) ? (d ? 1 : 0) : (e ? 1 : 0);
        public static int NestedTrue(bool a, bool b, bool c, bool d) => a ? b ? 1 : c ? 2 : 3 : d ? 4 : 5;
        public static int NestedFalse(bool a, bool b, bool c, bool d) => a ? 1 : b ? 2 : c ? 3 : d ? 4 : 5;
        public static int ParenthesizedFour(bool a, bool b, bool c, bool d) => (((a ? 1 : 0) + (b ? 1 : 0)) + ((c ? 1 : 0) + (d ? 1 : 0)));
        public static bool ParenthesizedMixed(bool a, bool b, bool c, bool d, bool e) => (a && b || c) ? (d && e) : false;
        public static bool LogicalThree(bool a, bool b, bool c, bool d) => a && b && c && d;
        public static bool LogicalFour(bool a, bool b, bool c, bool d, bool e) => a && b && c && d && e;
        public static bool MixedFive(bool a, bool b, bool c, bool d, bool e) => a && b && c && d && e ? a : b;
        public static bool ParenthesizedLogicalFive(bool a, bool b, bool c, bool d, bool e, bool f) => a || (b && c && d && e && f);
    }
}
";
const BOUNDARY_EXPECTED: &[(u32, u32, u32, u32)] = &[
    (6, 73, 126, 4),
    (7, 80, 108, 4),
    (8, 85, 124, 4),
    (9, 72, 105, 4),
    (10, 73, 106, 4),
    (11, 79, 138, 4),
    (12, 89, 121, 4),
    (14, 82, 103, 4),
    (15, 80, 109, 5),
    (16, 103, 131, 5),
    (16, 109, 130, 4),
];

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1067-{label}-{}-{id}",
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
            .expect("native files")
            .iter()
            .flat_map(|file| file["issues"].as_array().expect("native issues"))
            .filter(|issue| issue["rule_key"] == KEY)
            .cloned()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .expect("Generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
            .cloned()
            .collect()
    }
}

fn expected(format: &str, line: u32, start: u32, end_line: u32, end: u32, count: u32) -> Value {
    let message = format!(
        "Reduce the number of conditional operators ({count}) used in the expression (maximum allowed 3)."
    );
    if format == "json" {
        json!({"rule_key":KEY,"message":message,"range":{"start":{"line":line,"column":start},"end":{"line":end_line,"column":end}}})
    } else {
        json!({"ruleId":KEY,"primaryLocation":{"filePath":"Control.cs","message":message,"textRange":{"startLine":line,"startColumn":start,"endLine":end_line,"endColumn":end}}})
    }
}

fn full_span(source: &str, expression: &str, format: &str, count: u32) -> Value {
    let start = source
        .find(expression)
        .expect("independent expected source span");
    let position = |byte: usize| {
        let prefix = &source[..byte];
        let line = u32::try_from(prefix.bytes().filter(|&byte| byte == b'\n').count() + 1).unwrap();
        let last = prefix.rsplit('\n').next().unwrap();
        let column = if format == "sonar" {
            last.encode_utf16().count()
        } else {
            last.chars().count()
        };
        (line, u32::try_from(column).unwrap())
    };
    let (line, start_column) = position(start);
    let (end_line, end_column) = position(start + expression.len());
    expected(format, line, start_column, end_line, end_column, count)
}

fn complete_native_inventory(report: &Value, format: &str) {
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
fn csharp_s1067_conditional_cli_matches_exact_local_reference_and_keeps_logical_residual() {
    let fixture = Fixture::new("boundary");
    fixture.write(BOUNDARY.as_bytes());
    for format in ["json", "sonar"] {
        let output = fixture.analyze(format);
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = document(&output, 0);
        complete_native_inventory(&report, format);
        let expected = BOUNDARY_EXPECTED
            .iter()
            .map(|&(line, start, end, count)| expected(format, line, start, line, end, count))
            .collect::<Vec<_>>();
        assert_eq!(targets(&report, format), expected);
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
    assert_eq!(fixture.read(), BOUNDARY.as_bytes());
}

#[test]
fn csharp_s1067_conditional_cli_preserves_humanizer_concatenation_and_mixed_ranges() {
    let fixture = Fixture::new("humanizer");
    let japanese = "UnitsMap1[n3] + (n3 == 0 ? \"\" : UnitsMap2[3])\n + UnitsMap1[n2] + (n2 == 0 ? \"\" : UnitsMap2[2])\n + UnitsMap1[n1] + (n1 == 0 ? \"\" : UnitsMap2[1])\n + (n0 == 1 ? \"一\" : UnitsMap1[n0])\n + (groupNumber == 0 ? \"\" : UnitsMap3[groupLevel])";
    let mixed = "match.Value.ToCharArray().All(char.IsUpper) &&\n (match.Value.Length > 1 || (match.Index > 0 && input[match.Index - 1] == ' ') || match.Value == \"I\")\n ? match.Value\n : match.Value.ToLower()";
    for expression in [japanese, mixed] {
        let source = format!("class C {{ object M() => {expression}; }}\n");
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let report = document(&fixture.analyze(format), 0);
            complete_native_inventory(&report, format);
            assert_eq!(
                targets(&report, format),
                vec![full_span(&source, expression, format, 5)]
            );
        }
        assert_eq!(fixture.read(), source.as_bytes());
    }
}

#[test]
fn csharp_s1067_conditional_cli_preserves_unicode_columns_crlf_and_bom() {
    let fixture = Fixture::new("unicode");
    let expression =
        "(a ? \"一\" : \"\") + (b ? \"二\" : \"\")\r\n + (c ? \"三\" : \"\") + (d ? \"四\" : \"\")";
    let source = format!(
        "\u{feff}// header\r\nclass C {{ /* 😀 */ object M(bool a, bool b, bool c, bool d) => {expression}; }}\r\n"
    );
    fixture.write(source.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_native_inventory(&report, format);
        assert_eq!(
            targets(&report, format),
            vec![full_span(&source, expression, format, 4)]
        );
    }
    assert_eq!(fixture.read(), source.as_bytes());
}

#[test]
fn csharp_s1067_conditional_cli_does_not_join_invocation_lambda_or_cast_components() {
    let fixture = Fixture::new("separate");
    let source = "class C { object M(bool a, bool b, bool c, bool d) => F(a ? 1 : 0, b ? 1 : 0, c ? 1 : 0, d ? 1 : 0); object L(bool a, bool b, bool c, bool d) => a && b ? F(() => (c ? 1 : 0) + (d ? 1 : 0)) : 0; object K(bool a, bool b, bool c, bool d) => a && b ? (int)((c ? 1 : 0) + (d ? 1 : 0)) : 0; }";
    fixture.write(source.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_native_inventory(&report, format);
        assert!(targets(&report, format).is_empty());
    }
    assert_eq!(fixture.read(), source.as_bytes());
}

#[test]
fn csharp_s1067_conditional_cli_cached_reanalysis_observes_changed_source() {
    let fixture = Fixture::new("cache");
    fixture.write(b"class C { int M(bool a) => a ? 1 : 0; }");
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
    assert!(targets(&document(&analyze(), 0), "json").is_empty());
    fixture.write(BOUNDARY.as_bytes());
    let first = document(&analyze(), 0);
    let expected = BOUNDARY_EXPECTED
        .iter()
        .map(|&(line, start, end, count)| expected("json", line, start, line, end, count))
        .collect::<Vec<_>>();
    assert_eq!(targets(&first, "json"), expected);
    assert_eq!(first, document(&analyze(), 0));
    assert_eq!(fixture.read(), BOUNDARY.as_bytes());
}

#[test]
fn csharp_s1067_conditional_cli_keeps_malformed_and_invalid_utf8_incomplete() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"class C { int Broken(".as_slice(),
        b"class C { int M(bool a) => a ? 1 : ; }".as_slice(),
        b"\xffclass C { }".as_slice(),
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
fn csharp_s1067_conditional_cli_unavailable_edit_preserves_source_and_complete_report() {
    let fixture = Fixture::new("no-edit");
    fixture.write(BOUNDARY.as_bytes());
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
        assert_eq!(fixture.read(), BOUNDARY.as_bytes());
    }
}
