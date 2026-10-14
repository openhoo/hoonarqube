use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s104-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube")
    }

    fn analyze(&self, path: &str, format: &str, profile: Option<&str>, exit: i32) -> Value {
        let mut args = vec!["analyze", "--format", format];
        if let Some(profile) = profile {
            args.extend(["--profile", profile]);
        }
        args.extend(["--", path]);
        let output = self.run(&args);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("analysis JSON")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn shapes() -> Vec<(&'static str, String, bool)> {
    let prefix = "tick();\n".repeat(997);
    [
        ("over", "tick();\ntick();\ntick();\ntick();\n", true),
        ("within", "tick();\ntick();\ntick();\n", false),
        (
            "block_blank",
            "function example() {\n\n// comment\nreturn 1;\n}\n",
            false,
        ),
        (
            "header",
            "/* comment\n * comment\n */\ntick();\ntick();\n",
            false,
        ),
        (
            "inline",
            "tick(); // one\ntick(); // two\ntick(); // three\ntick(); // four\n",
            true,
        ),
        (
            "block_only",
            "/* comment\n * comment\n */\ntick();\n",
            false,
        ),
        ("template", "const text = `first\n\nmiddle\nlast`;\n", false),
        (
            "multiple_comments",
            "/*one*/ /*two*/\ntick();\ntick();\ntick();\n",
            true,
        ),
        (
            "crlf",
            "const café = 1;\r\n\r\n// comment\r\ntick();\r\ntick();\r\ntick();\r\n",
            true,
        ),
    ]
    .into_iter()
    .map(|(name, suffix, finding)| (name, prefix.clone() + suffix, finding))
    .collect()
}

fn assert_target(report: &Value, format: &str, file: &str, key: &str, expected: bool) {
    let message = "This file has 1001 lines, which is greater than 1000 authorized. Split it into smaller files.";
    let (findings, wanted): (Vec<&Value>, Value) = if format == "json" {
        let entry = report["files"]
            .as_array()
            .expect("files")
            .iter()
            .find(|f| f["path"] == file)
            .expect("selected file");
        (
            entry["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .filter(|i| i["rule_key"] == key)
                .collect(),
            json!({"rule_key":key,"message":message,"range":{"start":{"line":0,"column":0},"end":{"line":0,"column":0}}}),
        )
    } else {
        (
            report["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .filter(|i| i["ruleId"] == key && i["primaryLocation"]["filePath"] == file)
                .collect(),
            json!({"ruleId":key,"primaryLocation":{"filePath":file,"message":message}}),
        )
    };
    assert_eq!(
        findings,
        if expected { vec![&wanted] } else { Vec::new() },
        "{file}/{format}"
    );
}

fn assert_reference_shapes(format: &str) {
    let fixture = Fixture::new();
    for extension in ["js", "ts"] {
        for (name, source, _) in shapes() {
            std::fs::write(fixture.0.join(format!("{name}.{extension}")), source).expect("source");
        }
    }
    for profile in [
        None,
        Some("sonar-parity"),
        Some("recommended"),
        Some("extended"),
        Some("strict"),
    ] {
        let report = fixture.analyze(".", format, profile, 0);
        if format == "json" {
            assert_eq!(report["project"]["complete"], true);
            assert_eq!(report["files"].as_array().expect("files").len(), 18);
            assert_eq!(
                report["project"]["files"]
                    .as_array()
                    .expect("inventory")
                    .len(),
                18
            );
        }
        for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
            for (name, source, finding) in shapes() {
                let file = format!("{name}.{extension}");
                assert_target(&report, format, &file, &format!("{language}:S104"), finding);
                assert_eq!(
                    std::fs::read(fixture.0.join(file)).expect("readback"),
                    source.as_bytes()
                );
            }
        }
    }
}

#[test]
fn s104_cli_native_matches_real_reference_shapes_in_all_profiles() {
    assert_reference_shapes("json");
}

#[test]
fn s104_cli_generic_matches_real_reference_shapes_in_all_profiles() {
    assert_reference_shapes("sonar");
}

#[test]
fn s104_cli_ecmascript_terminators_and_unicode_have_file_level_identity() {
    let fixture = Fixture::new();
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        for separator in ["\n", "\r\n", "\r", "\u{2028}", "\u{2029}"] {
            let source = format!(
                "{}const café = 1;{separator}",
                format!("tick();{separator}").repeat(1000)
            );
            std::fs::write(fixture.0.join(&file), &source).expect("source");
            for format in ["json", "sonar"] {
                let report = fixture.analyze(&file, format, Some("sonar-parity"), 0);
                assert_target(&report, format, &file, &format!("{language}:S104"), true);
                assert_eq!(
                    std::fs::read(fixture.0.join(&file)).expect("readback"),
                    source.as_bytes()
                );
            }
        }
    }
}

#[test]
fn s104_cli_malformed_and_invalid_utf8_remain_incomplete_without_writes() {
    let fixture = Fixture::new();
    for extension in ["js", "ts"] {
        let file = format!("invalid.{extension}");
        for source in [
            b"function broken(\n".as_slice(),
            b"\xfftick();\n".as_slice(),
        ] {
            std::fs::write(fixture.0.join(&file), source).expect("source");
            for format in ["json", "sonar"] {
                let report = fixture.analyze(&file, format, Some("sonar-parity"), 2);
                if format == "json" {
                    assert_eq!(report["project"]["complete"], false);
                    assert_eq!(report["project"]["files"][0]["status"], "failed");
                }
                assert_eq!(
                    std::fs::read(fixture.0.join(&file)).expect("readback"),
                    source
                );
            }
        }
    }
}

#[test]
fn s104_cli_no_fix_and_unavailable_selection_preserve_source_and_reanalysis() {
    let fixture = Fixture::new();
    let source = "tick();\n".repeat(1001);
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        let rule = format!("{language}:S104");
        let selection = format!("{rule}=s104-split-file");
        std::fs::write(fixture.0.join(&file), &source).expect("source");
        let before = fixture.analyze(&file, "json", Some("sonar-parity"), 0);
        for mode in ["--diff", "--apply"] {
            for unavailable in [false, true] {
                let mut args = vec![
                    "fix",
                    "--profile",
                    "sonar-parity",
                    "--rule",
                    &rule,
                    mode,
                    "--json",
                ];
                if unavailable {
                    args.extend(["--suggestion", &selection]);
                }
                args.extend(["--", &file]);
                let output = fixture.run(&args);
                assert_eq!(
                    output.status.code(),
                    Some(i32::from(unavailable)),
                    "{output:?}"
                );
                let report: Value = serde_json::from_slice(&output.stdout).expect("fix JSON");
                assert_eq!(report["applied"], 0);
                assert_eq!(report["mechanical"], 0);
                assert_eq!(report["files"], json!([]));
                if unavailable {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("is unavailable"));
                }
                assert_eq!(
                    std::fs::read(fixture.0.join(&file)).expect("readback"),
                    source.as_bytes()
                );
                assert_eq!(
                    fixture.analyze(&file, "json", Some("sonar-parity"), 0),
                    before
                );
            }
        }
    }
}
