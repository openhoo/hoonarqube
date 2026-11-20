use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S2190";
const MESSAGE: &str = "Add a way to break out of this method's recursion.";
const REFERENCE_CONTROLS: &str = r#"public enum TimeUnit { Second, Minute }
public class OverloadControls
{
    public string Humanize(TimeUnit timeUnit = TimeUnit.Second)
    {
        return Humanize(null, timeUnit);
    }
    public string Humanize(string format, TimeUnit timeUnit = TimeUnit.Second, object culture = null)
    {
        return "complete";
    }
    public int FixedForward(int value)
    {
        return FixedForward(value, 0);
    }
    public int FixedForward(int value, int extra)
    {
        return value + extra;
    }
    public int FewerForward(int value, int extra)
    {
        return FewerForward(value);
    }
    public int FewerForward(int value)
    {
        return value;
    }
    public int TrueSelf(int value)
    {
        return TrueSelf(value + 1);
    }
    public int OptionalSelf(int value = 0)
    {
        return OptionalSelf();
    }
    public int VariadicSelf(params int[] values)
    {
        return VariadicSelf(1, 2);
    }
    public int NamedSelf(int value)
    {
        return NamedSelf(value: value);
    }
    public int RefSelf(ref int value)
    {
        return RefSelf(ref value);
    }
    public int GuardedSelf(int value)
    {
        if (value <= 0) { return 0; }
        return GuardedSelf(value - 1);
    }
    public void EndlessLoop()
    {
        while (true) { Tick(); }
    }
    public void EscapingLoop(bool done)
    {
        while (true) { if (done) { break; } Tick(); }
    }
    private void Tick() { }
}
"#;

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-csharp-s2190-{label}-{}-{id}",
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
fn csharp_s2190_cli_has_exact_typed_identities_and_clean_forwarders() {
    let fixture = Fixture::new("typed");
    fixture.write(REFERENCE_CONTROLS.as_bytes());
    let names = [
        "TrueSelf",
        "OptionalSelf",
        "VariadicSelf",
        "NamedSelf",
        "RefSelf",
        "EndlessLoop",
    ];
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let report = document(
                &fixture.run(&[
                    "analyze",
                    "--profile",
                    profile,
                    "--format",
                    format,
                    "--",
                    "Controls.cs",
                ]),
                0,
            );
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
fn csharp_s2190_cli_rejects_only_fixed_positional_self_arity_incompatibility() {
    let fixture = Fixture::new("forward");
    for source in [
        "class C { int Forward(int n) { return Forward(n, 0); } int Forward(int n, int extra) { return n + extra; } }\r\n",
        "class C { int Forward(int n, int extra) { return Forward(n); } int Forward(int n) { return n; } }\n",
        "class C { int Forward(int n = 0) { return Forward(n, (0, 1).Item1); } int Forward(int n, int extra) { return n + extra; } }\n",
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
            assert!(targets(&report, format).is_empty(), "{source:?}");
        }
        assert_eq!(fixture.read(), source.as_bytes());
    }
}

#[test]
fn csharp_s2190_cli_preserves_unresolved_overload_and_argument_boundaries() {
    let fixture = Fixture::new("boundary");
    for source in [
        "class C { int Loop(int n = 0) { return Loop(); } }\n",
        "class C { int Loop(int n, int extra = 0) { return Loop(n); } }\n",
        "class C { int Loop(params int[] values) { return Loop(1, 2); } }\n",
        "class C { int Forward(int n) { return Forward(extra: 0, n: n); } int Forward(int n, int extra) { return n + extra; } }\n",
        "class C { int Forward(ref int n) { return Forward(ref n, 0); } int Forward(ref int n, int extra) { return n + extra; } }\n",
        "class C { int Forward(int n) { return Forward((long)n); } int Forward(long n) { return (int)n; } }\n",
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
fn csharp_s2190_cli_malformed_and_invalid_utf8_remain_incomplete() {
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

#[test]
fn csharp_s2190_cli_unavailable_actions_refuse_without_writing() {
    let fixture = Fixture::new("actions");
    let source = b"class C { int Loop(int n) { return Loop(n + 1); } }\n";
    fixture.write(source);
    for mode in ["--diff", "--apply"] {
        let output = fixture.run(&[
            "fix",
            "Controls.cs",
            mode,
            "--json",
            "--suggestion",
            "csharpsquid:S2190=remove-recursion",
        ]);
        let report = document(&output, 1);
        assert!(String::from_utf8_lossy(&output.stderr).contains("is unavailable"));
        assert_eq!(report["files"], serde_json::json!([]));
        assert_eq!(fixture.read(), source);
    }
}
