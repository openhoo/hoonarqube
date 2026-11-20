use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S2190";
const MESSAGE: &str = "Add a way to break out of this method's recursion.";
const REFERENCE_CONTROLS: &str = r"public static class NamedControls
{
    public static int TooMany(int value)
    {
        return TooMany(value, repeat: 0);
    }

    public static int TooMany(int value, int repeat)
    {
        return value + repeat;
    }

    public static int OptionalTooMany(int value, int repeat = 0)
    {
        return OptionalTooMany(value, repeat, extra: 0);
    }

    public static int OptionalTooMany(int value, int repeat, int extra)
    {
        return value + repeat + extra;
    }

    public static int NamedFirst(int value)
    {
        return NamedFirst(value: value, 0);
    }

    public static int NamedFirst(int value, int repeat)
    {
        return value + repeat;
    }

    public static int TooFew(int value, int repeat)
    {
        return TooFew(value: value);
    }

    public static int TooFew(int value)
    {
        return value;
    }

    public static int TrueSelf(int value)
    {
        return TrueSelf(value: value);
    }

    public static int OptionalSelf(int value, int repeat = 0)
    {
        return OptionalSelf(value: value);
    }

    public static int ReorderedSelf(int value, int repeat)
    {
        return ReorderedSelf(repeat: repeat, value: value);
    }

    public static int MixedSelf(int value, int repeat)
    {
        return MixedSelf(value, repeat: repeat);
    }

    public static int Finite(int value)
    {
        if (value <= 0) return 0;
        return Finite(value: value - 1);
    }
}
";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-csharp-s2190-named-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("NamedControls.cs"), source).expect("fixture source");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI")
    }

    fn read(&self) -> Vec<u8> {
        std::fs::read(self.0.join("NamedControls.cs")).expect("unchanged source")
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

fn assert_reference_report(report: &serde_json::Value, format: &str) {
    let issues = targets(report, format);
    assert_eq!(issues.len(), 4, "{issues:?}");
    for (issue, (line, end)) in issues.iter().zip([(43, 30), (48, 34), (53, 35), (58, 31)]) {
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
            assert_eq!(issue["primaryLocation"]["filePath"], "NamedControls.cs");
            assert_eq!(issue["primaryLocation"]["message"], MESSAGE);
            assert_eq!(
                issue["primaryLocation"]["textRange"],
                serde_json::json!({"startLine":line,"startColumn":22,"endLine":line,"endColumn":end})
            );
            assert!(issue.get("secondaryLocations").is_none());
        }
    }
}

fn analyze(fixture: &Fixture, format: &str) -> Output {
    fixture.run(&[
        "analyze",
        "--profile",
        "sonar-parity",
        "--format",
        format,
        "--",
        "NamedControls.cs",
    ])
}

#[test]
fn csharp_s2190_named_cli_matches_compiled_reference_in_all_profiles() {
    let fixture = Fixture::new("reference");
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
            argv.extend(["--", "NamedControls.cs"]);
            let report = document(&fixture.run(&argv), 0);
            assert_reference_report(&report, format);
        }
    }
    assert_eq!(fixture.read(), REFERENCE_CONTROLS.as_bytes());
}

#[test]
fn csharp_s2190_named_cli_preserves_nested_values_and_arity_omission() {
    let fixture = Fixture::new("clean");
    for source in [
        r"class C { string ToString(string format, System.IFormatProvider provider) { return ToString(format, provider, toSymbol: true); } string ToString(string format, System.IFormatProvider provider, bool toSymbol) { return format; } }",
        r"class C { int Forward(int value) { return Forward(value: value, 0); } int Forward(int value, int repeat) { return value + repeat; } }",
        r"class C { int Forward(int value, int repeat) { return Forward(value: value); } int Forward(int value) { return value; } }",
        r"class C { int Forward(int value, int repeat = 0) { return Forward(value, repeat, extra: 0); } int Forward(int value, int repeat, int extra) { return value + repeat + extra; } }",
        r"class C { int Forward(int value) { return Forward(value: (true ? (value, 1).Item1 : 0), repeat: 0); } int Forward(int value, int repeat) { return value + repeat; } }",
        r"class C { int Forward(int value) { return Forward(value: (first: value, second: 0).first, repeat: 0); } int Forward(int value, int repeat) { return value + repeat; } }",
        r"class C { int Forward(int value) { return Forward(_value2: value, _extra3: 0); } }",
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let report = document(&analyze(&fixture, format), 0);
            assert!(targets(&report, format).is_empty(), "{source:?}: {report}");
        }
        assert_eq!(fixture.read(), source.as_bytes());
    }
}

#[test]
fn csharp_s2190_named_cli_preserves_unsupported_labels_values_and_signatures() {
    let fixture = Fixture::new("boundaries");
    for source in [
        r"class C { int Loop(int value) { return Loop(value: value); } }",
        r"class C { int Loop(int value = 0) { return Loop(value: value); } }",
        r"class C { int Loop(int value, int repeat = 0) { return Loop(value: value); } }",
        r"class C { int Loop(int value, int repeat) { return Loop(repeat: repeat, value: value); } }",
        r"class C { int Loop(int value, int repeat) { return Loop(value, repeat: repeat); } }",
        r"class C { int Loop(int value) { return Loop(other: value); } }",
        r"class C { int Loop(int value) { return Loop(value: (double)value); } }",
        r"class C { int Loop(int value) { return Loop(value: value, value: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: value, @value: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: value, v\u0061lue: 0); } }",
        r"class C { int Loop(int value) { return Loop(välue: value, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: ref value, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: out value, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: in value, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(ref value, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(out int other, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: out int other, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value /* name */: value, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: /* expression */ value, repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: (value /* nested */), repeat: 0); } }",
        r"class C { int Loop(int value) { return Loop(value: value, /* list */ repeat: 0); } }",
        r"class C { int Loop([A] int value) { return Loop(value: value, repeat: 0); } }",
        r"class C { int Loop(params int[] values) { return Loop(values: values, extra: 0); } }",
        r"class C { int Loop(ref int value) { return Loop(value: value, repeat: 0); } }",
        r"static class C { static int Loop(this ref int value) { return Loop(value: value, repeat: 0); } }",
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let report = document(&analyze(&fixture, format), 0);
            assert_eq!(targets(&report, format).len(), 1, "{source:?}: {report}");
        }
        assert_eq!(fixture.read(), source.as_bytes());
    }
}

#[test]
fn csharp_s2190_named_cli_keeps_coordinates_and_owned_escapes() {
    let fixture = Fixture::new("coordinates");
    let source = "class C { /* 😀 */ int Vélo(int value) { return Vélo(value: value); } }\r\n";
    fixture.write(source.as_bytes());
    let prefix = &source[..source.find("Vélo").unwrap()];
    for format in ["json", "sonar"] {
        let report = document(&analyze(&fixture, format), 0);
        let issues = targets(&report, format);
        assert_eq!(issues.len(), 1);
        if format == "json" {
            let start = prefix.chars().count();
            assert_eq!(
                issues[0]["range"],
                serde_json::json!({"start":{"line":1,"column":start},"end":{"line":1,"column":start+4}})
            );
        } else {
            let start = prefix.encode_utf16().count();
            assert_eq!(
                issues[0]["primaryLocation"]["textRange"],
                serde_json::json!({"startLine":1,"startColumn":start,"endLine":1,"endColumn":start+4})
            );
        }
    }
    assert_eq!(fixture.read(), source.as_bytes());
    let source = b"class C { int Guarded(int value) { if (value <= 0) return 0; return Guarded(value: value - 1); } void Spin() { while (true) { void Local() { return; } Local(); } } }";
    fixture.write(source);
    let report = document(&analyze(&fixture, "json"), 0);
    assert_eq!(targets(&report, "json").len(), 1);
    assert_eq!(fixture.read(), source);
}

#[test]
fn csharp_s2190_named_cli_keeps_malformed_recovery_and_utf8_incomplete() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"class C { int Broken(".as_slice(),
        b"\xffclass C { }".as_slice(),
        b"class C { int Loop(int value) { return Loop(value: , repeat: 0); } }".as_slice(),
        b"class C { int Loop(int value) { return Loop(value: value, repeat: 0; } }".as_slice(),
        b"class C { int Loop(int value) { return Loop(value: value); } @ }".as_slice(),
    ] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let report = document(&analyze(&fixture, format), 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
            }
        }
        assert_eq!(fixture.read(), source);
    }
}

#[test]
fn csharp_s2190_named_cli_unavailable_fix_keeps_full_report_and_source() {
    let fixture = Fixture::new("fix");
    fixture.write(REFERENCE_CONTROLS.as_bytes());
    let before = analyze(&fixture, "json");
    let report = document(&before, 0);
    for mode in ["--diff", "--apply"] {
        let output = fixture.run(&[
            "fix",
            "--profile",
            "sonar-parity",
            "--rule",
            KEY,
            "--suggestion",
            "csharpsquid:S2190=extract-shared-code",
            mode,
            "--json",
            "NamedControls.cs",
        ]);
        let refusal = document(&output, 1);
        assert_eq!(refusal["applied"], 0);
        assert_eq!(refusal["mechanical"], 0);
        assert_eq!(refusal["files"], serde_json::json!([]));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "selected suggestion csharpsquid:S2190=extract-shared-code is unavailable\n"
        );
        let after = analyze(&fixture, "json");
        assert_eq!(document(&after, 0), report);
        assert_eq!(after.stderr, before.stderr);
        assert_eq!(fixture.read(), REFERENCE_CONTROLS.as_bytes());
    }
}
