use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S2190";
const MESSAGE: &str = "Add a way to break out of this method's recursion.";
const REFERENCE_CONTROLS: &str = r"public static class ExtensionControls
{
    public static int OptionalForward(this int value, int a = 0, int b = 0,
        int c = 0, int d = 0, int e = 0, int f = 0)
    {
        return OptionalForward(value, a, b, c, d, e, f, 0);
    }

    public static int OptionalForward(int value, int a, int b, int c,
        int d, int e, int f, int g)
    {
        return value + a + b + c + d + e + f + g;
    }

    public static int ArityForward(this int value, int repeat)
    {
        return ArityForward(value, repeat, 0, 0);
    }

    public static int ArityForward(int value, int repeat, int a, int b)
    {
        return value + repeat + a + b;
    }

    public static int TrueSelf(this int value)
    {
        return TrueSelf(value);
    }

    public static int OptionalSelf(this int value, int repeat = 0)
    {
        return OptionalSelf(value);
    }

    public static int ExplicitOptionalSelf(this int value, int repeat = 0)
    {
        return ExplicitOptionalSelf(value, repeat);
    }

    public static int SameTypeSelf(this int value)
    {
        return SameTypeSelf(value + 1);
    }

    public static int Finite(this int value, int count)
    {
        if (count <= 0) return value;
        return Finite(value, count - 1);
    }
}
";
const HUMANIZER_SHAPES: &str = r#"using System;
using System.Globalization;
public static class HumanizerShapes
{
    public static string Humanize(this TimeSpan timeSpan, int precision = 1, CultureInfo culture = null, TimeUnit maxUnit = TimeUnit.Week, TimeUnit minUnit = TimeUnit.Millisecond, string collectionSeparator = ", ", bool toWords = false)
    {
        return Humanize(timeSpan, precision, false, culture, maxUnit, minUnit, collectionSeparator, toWords);
    }
    public static string Humanize(this TimeSpan timeSpan, int precision, bool countEmptyUnits, CultureInfo culture = null, TimeUnit maxUnit = TimeUnit.Week, TimeUnit minUnit = TimeUnit.Millisecond, string collectionSeparator = ", ", bool toWords = false) { return string.Empty; }
    public static string ToQuantity(this string input, double quantity)
    {
        return ToQuantity(input, quantity, null, null);
    }
    public static string ToQuantity(this string input, double quantity, string format = null, IFormatProvider formatProvider = null) { return input; }
}
"#;

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-csharp-s2190-extension-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("ExtensionControls.cs"), source).expect("fixture source");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI")
    }

    fn read(&self) -> Vec<u8> {
        std::fs::read(self.0.join("ExtensionControls.cs")).expect("unchanged source")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output, exit: i32) -> serde_json::Value {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("CLI JSON")
}

fn targets<'a>(report: &'a serde_json::Value, format: &str) -> Vec<&'a serde_json::Value> {
    let (issues, key) = if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        (
            report["files"][0]["issues"]
                .as_array()
                .expect("native issues"),
            "rule_key",
        )
    } else {
        (
            report["issues"].as_array().expect("generic issues"),
            "ruleId",
        )
    };
    issues.iter().filter(|issue| issue[key] == KEY).collect()
}

fn assert_compiled_reference_report(report: &serde_json::Value, format: &str) {
    let issues = targets(report, format);
    assert_eq!(issues.len(), 4, "{issues:?}");
    for (issue, (line, end)) in issues.iter().zip([(25, 30), (30, 34), (35, 42), (40, 34)]) {
        if format == "json" {
            assert_eq!(issue["message"], MESSAGE);
            assert_eq!(
                issue["range"],
                serde_json::json!({"start":{"line":line,"column":22},"end":{"line":line,"column":end}})
            );
            for absent in ["fix", "alternatives", "flows"] {
                assert!(issue.get(absent).is_none());
            }
        } else {
            assert_eq!(issue["primaryLocation"]["filePath"], "ExtensionControls.cs");
            assert_eq!(issue["primaryLocation"]["message"], MESSAGE);
            assert_eq!(
                issue["primaryLocation"]["textRange"],
                serde_json::json!({"startLine":line,"startColumn":22,"endLine":line,"endColumn":end})
            );
            assert!(issue.get("secondaryLocations").is_none());
        }
    }
}

#[test]
fn csharp_s2190_extension_cli_matches_compiled_reference_in_all_profiles() {
    let fixture = Fixture::new("typed");
    fixture.write(REFERENCE_CONTROLS.as_bytes());
    for profile in [
        "default",
        "sonar-parity",
        "recommended",
        "extended",
        "strict",
    ] {
        for format in ["json", "sonar"] {
            let mut argv = vec!["analyze", "--format", format];
            if profile != "default" {
                argv.extend(["--profile", profile]);
            }
            argv.extend(["--", "ExtensionControls.cs"]);
            let report = document(&fixture.run(&argv), 0);
            assert_compiled_reference_report(&report, format);
        }
    }
    assert_eq!(fixture.read(), REFERENCE_CONTROLS.as_bytes());
}

#[test]
fn csharp_s2190_extension_cli_removes_both_humanizer_forwarders() {
    let fixture = Fixture::new("humanizer");
    fixture.write(HUMANIZER_SHAPES.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(
            &fixture.run(&[
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--",
                "ExtensionControls.cs",
            ]),
            0,
        );
        assert!(targets(&report, format).is_empty(), "{report}");
    }
    assert_eq!(fixture.read(), HUMANIZER_SHAPES.as_bytes());
}

#[test]
fn csharp_s2190_extension_cli_preserves_recursion_and_refusal_boundaries() {
    let fixture = Fixture::new("boundaries");
    for source in [
        "static class C { static int Loop(this int value) { return Loop(value); } }",
        "static class C { static int Loop(this int value, int repeat = 0) { return Loop(value); } }",
        "static class C { static int Loop(this int value, int repeat = 0) { return Loop(value, repeat); } }",
        "static class C { static int Loop(this int value) { return Loop((int)value); } }",
        "static class C { static double Loop(this double value) { return Loop((int)value); } }",
        "static class C { static int Loop(this ref int value) { return Loop(value, 0); } }",
        "static class C { static int Loop(this in int value) { return Loop(value, 0); } }",
        "static class C { static int Loop(this scoped ref int value) { return Loop(value, 0); } }",
        "static class C { static int Loop([A] this int value) { return Loop(value, 0); } }",
        "static class C { static int Loop(this /* receiver */ int value) { return Loop(value, 0); } }",
        "static class C { static int Loop(this int /* parameter */ value) { return Loop(value, 0); } }",
        "static class C { static int Loop(this int value, [A] int repeat = 0) { return Loop(value, 0, 0); } }",
        "static class C { static int Loop(this int value, params int[] rest) { return Loop(value, 0, 0); } }",
        "static class C { static int Loop(this int value) { return Loop(ref value, 0); } }",
        "static class C { static int Loop(this int value) { return Loop(out value, 0); } }",
        "static class C { static int Loop(this int value) { return Loop(/* argument */ value, 0); } }",
        "static class C { static int Loop(int value, this int other) { return Loop(value, other, 0); } }",
        "static class C { static int Loop(this int value = 0) { return Loop(value, 0); } }",
        "static class C { static int Loop(this System.Collections.Generic.List</* type */ int> value) { return Loop(value, 0); } }",
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let report = document(
                &fixture.run(&[
                    "analyze",
                    "--profile",
                    "sonar-parity",
                    "--format",
                    format,
                    "--",
                    "ExtensionControls.cs",
                ]),
                0,
            );
            assert_eq!(targets(&report, format).len(), 1, "{source:?}: {report}");
        }
        assert_eq!(fixture.read(), source.as_bytes());
    }
}

#[test]
fn csharp_s2190_extension_cli_keeps_unicode_crlf_and_nested_ownership() {
    let fixture = Fixture::new("coordinates");
    let source =
        "static class C { /* 😀 */ static int Vélo(this int value) { return Vélo(value); } }\r\n";
    fixture.write(source.as_bytes());
    let prefix = &source[..source.find("Vélo").unwrap()];
    for format in ["json", "sonar"] {
        let report = document(
            &fixture.run(&[
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--",
                "ExtensionControls.cs",
            ]),
            0,
        );
        let issues = targets(&report, format);
        assert_eq!(issues.len(), 1);
        let start = if format == "json" {
            prefix.chars().count()
        } else {
            prefix.encode_utf16().count()
        };
        if format == "json" {
            assert_eq!(
                issues[0]["range"],
                serde_json::json!({"start":{"line":1,"column":start},"end":{"line":1,"column":start+4}})
            );
        } else {
            assert_eq!(
                issues[0]["primaryLocation"]["textRange"],
                serde_json::json!({"startLine":1,"startColumn":start,"endLine":1,"endColumn":start+4})
            );
        }
    }
    assert_eq!(fixture.read(), source.as_bytes());
    let source = b"static class C { static int Guarded(this int value) { if (value <= 0) return 0; return Guarded(value - 1); } static void Spin() { while (true) { void Local() { return; } Local(); } } }";
    fixture.write(source);
    let report = document(
        &fixture.run(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            "--",
            "ExtensionControls.cs",
        ]),
        0,
    );
    assert_eq!(targets(&report, "json").len(), 1);
    assert_eq!(fixture.read(), source);
}

#[test]
fn csharp_s2190_extension_cli_malformed_recovery_and_utf8_stay_incomplete() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"static class C { static int Broken(".as_slice(),
        b"\xffclass C { }".as_slice(),
        b"static class C { static int Loop(this int value) { return Loop(value); } @ }".as_slice(),
    ] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let report = document(
                &fixture.run(&[
                    "analyze",
                    "--profile",
                    "sonar-parity",
                    "--format",
                    format,
                    "--",
                    "ExtensionControls.cs",
                ]),
                2,
            );
            assert_eq!(report["parity"]["completeness"], "incomplete");
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
            }
        }
        assert_eq!(fixture.read(), source);
    }
}

#[test]
fn csharp_s2190_extension_cli_unavailable_fix_keeps_whole_report_and_source() {
    let fixture = Fixture::new("fix");
    fixture.write(REFERENCE_CONTROLS.as_bytes());
    let args = [
        "analyze",
        "--profile",
        "strict",
        "--format",
        "json",
        "--",
        "ExtensionControls.cs",
    ];
    let before = fixture.run(&args);
    let report = document(&before, 0);
    for mode in ["--diff", "--apply"] {
        let output = fixture.run(&[
            "fix",
            "--profile",
            "strict",
            "--rule",
            KEY,
            "--suggestion",
            "csharpsquid:S2190=extract-shared-code",
            mode,
            "--json",
            "ExtensionControls.cs",
        ]);
        let refusal = document(&output, 1);
        assert_eq!(refusal["applied"], 0);
        assert_eq!(refusal["mechanical"], 0);
        assert_eq!(refusal["files"], serde_json::json!([]));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "selected suggestion csharpsquid:S2190=extract-shared-code is unavailable\n"
        );
        let after = fixture.run(&args);
        assert_eq!(document(&after, 0), report);
        assert_eq!(after.stderr, before.stderr);
        assert_eq!(fixture.read(), REFERENCE_CONTROLS.as_bytes());
    }
}

#[test]
fn csharp_s2190_extension_cli_named_arity_migrates_prior_boundary() {
    let fixture = Fixture::new("named-migration");
    let source = "static class C { static int Loop(this int value) { return Loop(value: value, repeat: 0); } }";
    fixture.write(source.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(
            &fixture.run(&[
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--",
                "ExtensionControls.cs",
            ]),
            0,
        );
        assert!(targets(&report, format).is_empty(), "{source:?}: {report}");
    }
    assert_eq!(fixture.read(), source.as_bytes());
}
