use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S2190";
const MESSAGE: &str = "Add a way to break out of this method's recursion.";
const REFERENCE_CONTROLS: &str = r"using System;
public static class NumericControls
{
    public static TimeSpan Extension(this byte value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this sbyte value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this short value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this ushort value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this int value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this uint value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this long value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this ulong value)
    {
        return Extension((double)value);
    }
    public static TimeSpan Extension(this double value)
    {
        return TimeSpan.FromSeconds(value);
    }
    public static TimeSpan Plain(byte value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(sbyte value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(short value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(ushort value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(int value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(uint value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(long value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(ulong value)
    {
        return Plain((double)value);
    }
    public static TimeSpan Plain(double value)
    {
        return TimeSpan.FromSeconds(value);
    }
    public static double TrueSelf(int value)
    {
        return TrueSelf(value + 1);
    }
    public static double SameTypeCastSelf(int value)
    {
        return SameTypeCastSelf((int)value);
    }
    public static double WideningSelf(double value)
    {
        return WideningSelf((int)value);
    }
    public static double FloatWideningSelf(double value)
    {
        return FloatWideningSelf((float)value);
    }
    public static int ExtensionSelf(this int value)
    {
        return ExtensionSelf((int)value);
    }
    public static void EndlessLoop()
    {
        while (true) { Tick(); }
    }
    public static int GuardedSelf(int value)
    {
        if (value <= 0) { return 0; }
        return GuardedSelf(value - 1);
    }
    private static void Tick() { }
}
";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-csharp-s2190-numeric-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("Controls.cs"), source).expect("fixture source");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI")
    }

    fn read(&self) -> Vec<u8> {
        std::fs::read(self.0.join("Controls.cs")).expect("unchanged source")
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

#[test]
fn csharp_s2190_numeric_cli_has_exact_typed_positives_and_clean_forwarders() {
    let fixture = Fixture::new("typed");
    fixture.write(REFERENCE_CONTROLS.as_bytes());
    let names = [
        "TrueSelf",
        "SameTypeCastSelf",
        "WideningSelf",
        "FloatWideningSelf",
        "ExtensionSelf",
        "EndlessLoop",
    ];
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
            argv.extend(["--", "Controls.cs"]);
            let report = document(&fixture.run(&argv), 0);
            let findings = targets(&report, format);
            assert_eq!(findings.len(), names.len());
            for (issue, name) in findings.into_iter().zip(names) {
                let (line_index, line) = REFERENCE_CONTROLS
                    .lines()
                    .enumerate()
                    .find(|(_, line)| {
                        line.contains(&format!(" {name}(")) && line.contains("public ")
                    })
                    .expect("declaration");
                let start = line.find(name).expect("method anchor");
                let line_number = line_index + 1;
                if format == "json" {
                    assert_eq!(issue["message"], MESSAGE);
                    assert_eq!(
                        issue["range"],
                        serde_json::json!({"start":{"line":line_number,"column":start},"end":{"line":line_number,"column":start+name.len()}})
                    );
                    assert!(issue.get("fix").is_none());
                    assert!(issue.get("alternatives").is_none());
                    assert!(issue.get("flows").is_none());
                } else {
                    assert_eq!(issue["primaryLocation"]["filePath"], "Controls.cs");
                    assert_eq!(issue["primaryLocation"]["message"], MESSAGE);
                    assert_eq!(
                        issue["primaryLocation"]["textRange"],
                        serde_json::json!({"startLine":line_number,"startColumn":start,"endLine":line_number,"endColumn":start+name.len()})
                    );
                    assert!(issue.get("secondaryLocations").is_none());
                }
            }
        }
    }
    assert_eq!(fixture.read(), REFERENCE_CONTROLS.as_bytes());
}

#[test]
fn csharp_s2190_numeric_cli_preserves_unsupported_and_genuine_self_calls() {
    let fixture = Fixture::new("boundary");
    for source in [
        "class C { int Loop(int value) { return Loop((int)value); } }\n",
        "class C { double Loop(double value) { return Loop((int)value); } }\n",
        "class C { int Loop(int value = 0) { return Loop((double)value); } }\n",
        "class C { int Loop(ref int value) { return Loop((double)value); } }\n",
        "class C { int Loop(int value) { return Loop(value: (double)value); } }\n",
        "class C { int Loop(System.Int32 value) { return Loop((double)value); } }\n",
        "class C { int Loop(int? value) { return Loop((double)value); } }\n",
        "class C { int Loop(int value) { return Loop((System.Double)value); } }\n",
        "class C { int Loop(int value) { return Loop((long)value); } }\n",
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
                    "Controls.cs",
                ]),
                0,
            );
            assert_eq!(targets(&report, format).len(), 1, "{source:?}");
        }
        assert_eq!(fixture.read(), source.as_bytes());
    }
}

#[test]
fn csharp_s2190_numeric_cli_malformed_and_invalid_utf8_remain_incomplete() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"class C { int Broken(".as_slice(),
        b"\xffclass C { }".as_slice(),
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
                    "Controls.cs",
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
