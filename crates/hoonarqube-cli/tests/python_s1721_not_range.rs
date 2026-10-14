use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1721-not-range-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube")
    }

    fn analyze(&self, source: &str, profile: &str, format: &str) -> Value {
        std::fs::write(self.0.join("case.py"), source).expect("source");
        let output = self.run(&[
            "analyze",
            "case.py",
            "--profile",
            profile,
            "--format",
            format,
        ]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("report");
        if format == "json" {
            assert_eq!(report["project"]["complete"], true);
            assert_eq!(report["project"]["files"][0]["status"], "complete");
        }
        assert_eq!(
            std::fs::read_to_string(self.0.join("case.py")).expect("readback"),
            source
        );
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn targets(report: &Value, format: &str) -> Vec<Value> {
    let (issues, key) = if format == "json" {
        (&report["files"][0]["issues"], "rule_key")
    } else {
        (&report["issues"], "ruleId")
    };
    issues
        .as_array()
        .expect("issues")
        .iter()
        .filter(|issue| issue[key] == "python:S1721")
        .cloned()
        .collect()
}

fn range(line: u32, start: u32, end: u32) -> Value {
    json!({"start":{"line":line,"column":start},"end":{"line":line,"column":end}})
}

fn expected(format: &str, keyword: &str, line: u32, span: (u32, u32), pair: (u32, u32)) -> Value {
    let message = format!("Remove the parentheses after this \"{keyword}\" keyword.");
    if format == "json" {
        json!({"rule_key":"python:S1721","message":message,"range":range(line,span.0,span.1),
            "fix":{"message":"Remove redundant parentheses","edits":[
                {"range":range(line,pair.0,pair.0+1),"replacement":" "},
                {"range":range(line,pair.1-1,pair.1),"replacement":""}]}})
    } else {
        json!({"ruleId":"python:S1721","primaryLocation":{"filePath":"case.py","message":message,
            "textRange":{"startLine":line,"endLine":line,"startColumn":span.0,"endColumn":span.1}}})
    }
}

fn assert_not_ranges(format: &str) {
    let fixture = Fixture::new();
    // Exact installed SonarPython unwraps one parenthesized tree. These token
    // controls supplement the real Werkzeug/scanned-comparison witnesses.
    for (source, span, pair) in [
        ("ok = not (left == right)\n", (10, 23), (9, 24)),
        ("ok = not (value)\n", (10, 15), (9, 16)),
        ("ok = not ((value))\n", (10, 17), (9, 18)),
        ("ok = not (  left == right \t)\n", (12, 25), (9, 28)),
        ("ok = not(value)\n", (9, 14), (8, 15)),
        ("é = 0; ok = not (ü)\n", (17, 18), (16, 19)),
    ] {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(source, profile, format);
            assert_eq!(
                targets(&report, format),
                vec![expected(format, "not", 1, span, pair)],
                "{profile}/{format}/{source}"
            );
        }
    }
}

#[test]
fn native_not_primary_unwraps_one_pair_with_unchanged_fix() {
    assert_not_ranges("json");
}

#[test]
fn generic_not_primary_unwraps_one_pair() {
    assert_not_ranges("sonar");
}

#[test]
fn non_not_keyword_locations_and_unsafe_controls_stay_unchanged() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let report = fixture.analyze(
                "def total(entries):\n    return(sum(entries))\n",
                profile,
                format,
            );
            assert_eq!(
                targets(&report, format),
                vec![expected(format, "return", 2, (10, 24), (10, 24))]
            );
            for source in [
                "ok = not (ready and able)\n",
                "ok = not (ready or able)\n",
                "ok = not (value := 1)\n",
                "ok = not ()\n",
                "ok = not (x for x in values)\n",
                "ok = not (\n    value\n)\n",
                "ok = not (value,)\n",
                "def total(entries):\n    return sum(entries)\n",
            ] {
                assert!(
                    targets(&fixture.analyze(source, profile, format), format).is_empty(),
                    "{source}"
                );
            }
        }
    }
}

#[test]
fn selected_not_fix_diff_apply_and_reanalysis_preserve_runtime_types_and_effects() {
    let fixture = Fixture::new();
    let source = "events = []\nclass Probe:\n    def __bool__(self):\n        events.append('bool')\n        return False\n    def __eq__(self, other):\n        events.append(('eq', other))\n        return True\nvalue = not (Probe())\ncomparison = not (Probe() == 7)\nprint(repr((value, type(value).__name__, comparison, type(comparison).__name__, events)))\n";
    let projected = "events = []\nclass Probe:\n    def __bool__(self):\n        events.append('bool')\n        return False\n    def __eq__(self, other):\n        events.append(('eq', other))\n        return True\nvalue = not  Probe()\ncomparison = not  Probe() == 7\nprint(repr((value, type(value).__name__, comparison, type(comparison).__name__, events)))\n";
    let runtime = || {
        Command::new("python3")
            .current_dir(&fixture.0)
            .args(["-B", "case.py"])
            .output()
            .expect("Python 3 runtime qualification")
    };
    let before = fixture.analyze(source, "strict", "json");
    assert_eq!(targets(&before, "json").len(), 2);
    let original_runtime = runtime();
    assert!(original_runtime.status.success(), "{original_runtime:?}");
    assert_eq!(
        String::from_utf8_lossy(&original_runtime.stdout),
        "(True, 'bool', False, 'bool', ['bool', ('eq', 7)])\n"
    );
    for mode in ["--diff", "--apply"] {
        let result = fixture.run(&[
            "fix",
            "--profile",
            "strict",
            "--rule",
            "python:S1721",
            mode,
            "--json",
            "case.py",
        ]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        let report: Value = serde_json::from_slice(&result.stdout).expect("fix JSON");
        assert_eq!(report["mechanical"], 2);
        assert_eq!(report["warnings"], json!([]));
        assert_eq!(
            std::fs::read_to_string(fixture.0.join("case.py")).expect("readback"),
            if mode == "--diff" { source } else { projected }
        );
    }
    let fixed_runtime = runtime();
    assert!(fixed_runtime.status.success(), "{fixed_runtime:?}");
    assert_eq!(fixed_runtime.stdout, original_runtime.stdout);
    assert_eq!(fixed_runtime.stderr, original_runtime.stderr);
    let compile = Command::new("python3")
        .current_dir(&fixture.0)
        .args([
            "-B",
            "-c",
            "from pathlib import Path; compile(Path('case.py').read_text(), 'case.py', 'exec')",
        ])
        .output()
        .expect("compile fixed Python");
    assert!(compile.status.success(), "{compile:?}");
    let after = fixture.analyze(projected, "strict", "json");
    let retained: Vec<_> = before["files"][0]["issues"]
        .as_array()
        .expect("before issues")
        .iter()
        .filter(|i| i["rule_key"] != "python:S1721")
        .cloned()
        .collect();
    assert_eq!(after["files"][0]["issues"], json!(retained));
    assert_eq!(fixture.analyze(projected, "strict", "json"), after);
    let again = fixture.run(&[
        "fix",
        "--profile",
        "strict",
        "--rule",
        "python:S1721",
        "--apply",
        "--json",
        "case.py",
    ]);
    assert!(again.status.success(), "{again:?}");
    let again: Value = serde_json::from_slice(&again.stdout).expect("repeat fix JSON");
    assert_eq!(again["mechanical"], 0);
    assert_eq!(again["applied"], 0);
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("case.py")).expect("readback"),
        projected
    );
}

#[test]
fn unsafe_not_fix_and_unavailable_suggestion_preserve_source() {
    let fixture = Fixture::new();
    for source in [
        "ok = not (ready and able)\n",
        "ok = not (value := 1)\n",
        "ok = not ()\n",
        "ok = not (x for x in values)\n",
        "ok = not (\n    value\n)\n",
        "ok = not (value,)\n",
    ] {
        let before = fixture.analyze(source, "strict", "json");
        for mode in ["--diff", "--apply"] {
            for unavailable in [false, true] {
                let mut args = vec![
                    "fix",
                    "--profile",
                    "strict",
                    "--rule",
                    "python:S1721",
                    mode,
                    "--json",
                ];
                if unavailable {
                    args.extend(["--suggestion", "python:S1721=unavailable"]);
                }
                args.push("case.py");
                let output = fixture.run(&args);
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(unavailable)),
                    "{output:?}"
                );
                let report: Value = serde_json::from_slice(&output.stdout).expect("fix JSON");
                assert_eq!(report["mechanical"], 0);
                assert_eq!(report["applied"], 0);
                assert_eq!(report["files"], json!([]));
                assert_eq!(
                    report["warnings"],
                    if unavailable {
                        json!(["selected suggestion python:S1721=unavailable is unavailable"])
                    } else {
                        json!([])
                    }
                );
                assert_eq!(
                    std::fs::read_to_string(fixture.0.join("case.py")).expect("readback"),
                    source
                );
                assert_eq!(fixture.analyze(source, "strict", "json"), before);
            }
        }
    }
}
