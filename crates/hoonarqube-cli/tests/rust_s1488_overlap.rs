use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const RETURNED: &str = "rust:S1488";
const CAST: &str = "rust:S4325";
const RETURN_MESSAGE: &str = "Remove the `let` statement and return the expression directly.";
const CAST_MESSAGE: &str = "Remove this unnecessary cast.";
const FILE: &str = "src/s4325_bad.rs";
const OVERLAP: &str = concat!(
    "// Hoonarqube oracle fixture: rust:S4325 bad\n",
    "fn get_length(value: &str) -> usize {\n",
    "    let length = value.len() as usize; // Noncompliant: 'value.len()' already returns a 'usize'\n",
    "    length\n",
    "}\n",
    "\n",
    "fn main() {}\n",
);
const ORDINARY: &str = concat!(
    "// Hoonarqube oracle fixture: rust:S1488 bad\n",
    "fn compute_duration_in_milliseconds(hours: u32, minutes: u32, seconds: u32) -> u32 {\n",
    "    let duration = (((hours * 60) + minutes) * 60 + seconds) * 1000;\n",
    "    duration\n",
    "}\n",
    "\n",
    "fn main() {}\n",
);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s1488-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("fixture directory");
        std::fs::create_dir(path.join("src")).expect("fixture source directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join(FILE), source).expect("source");
    }

    fn assert_source(&self, source: &[u8]) {
        assert_eq!(
            std::fs::read(self.0.join(FILE)).expect("source readback"),
            source
        );
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI")
    }

    fn analyze(&self, profile: &str, format: &str, exit: i32) -> Value {
        let mut args = vec!["analyze", "--format", format];
        if profile != "default" {
            args.extend(["--profile", profile]);
        }
        args.extend(["--", FILE]);
        let output = self.run(&args);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        if exit == 0 {
            assert!(output.stderr.is_empty(), "{output:?}");
        }
        let document: Value = serde_json::from_slice(&output.stdout).expect("actual JSON document");
        if format == "json" {
            assert_eq!(document["project"]["complete"], exit == 0);
        }
        document
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn issues<'a>(document: &'a Value, format: &str) -> &'a [Value] {
    if format == "json" {
        document["files"][0]["issues"]
            .as_array()
            .expect("native issues")
    } else {
        document["issues"].as_array().expect("generic issues")
    }
}

fn rule<'a>(issue: &'a Value, format: &str) -> &'a str {
    issue[if format == "json" {
        "rule_key"
    } else {
        "ruleId"
    }]
    .as_str()
    .expect("rule key")
}

fn expected_issue(key: &str, message: &str, range: (u32, u32, u32, u32), format: &str) -> Value {
    let (sl, sc, el, ec) = range;
    if format == "json" {
        json!({"rule_key":key,"message":message,"range":{"start":{"line":sl,"column":sc},"end":{"line":el,"column":ec}}})
    } else {
        json!({"ruleId":key,"primaryLocation":{"filePath":FILE,"message":message,"textRange":{"startLine":sl,"startColumn":sc,"endLine":el,"endColumn":ec}}})
    }
}

fn expected_rule(key: &str) -> Value {
    json!({
        "id":key,"name":key,"description":format!("Hoonarqube finding for `{key}`."),
        "engineId":"hoonarqube","cleanCodeAttribute":"CLEAR","type":"CODE_SMELL","severity":"MINOR",
        "impacts":[{"softwareQuality":"MAINTAINABILITY","severity":"LOW"}],
    })
}

#[test]
fn rust_s1488_cli_keeps_both_rule_identities_in_json_and_generic() {
    let fixture = Fixture::new();
    for source in [OVERLAP.to_string(), OVERLAP.replace('\n', "\r\n")] {
        fixture.write(source.as_bytes());
        for profile in [
            "default",
            "sonar-parity",
            "recommended",
            "extended",
            "strict",
        ] {
            for format in ["json", "sonar"] {
                let document = fixture.analyze(profile, format, 0);
                assert_eq!(
                    issues(&document, format),
                    [
                        expected_issue(RETURNED, RETURN_MESSAGE, (3, 4, 3, 38), format),
                        expected_issue(CAST, CAST_MESSAGE, (3, 17, 3, 37), format),
                    ],
                );
                if format == "sonar" {
                    assert_eq!(
                        document["rules"],
                        json!([expected_rule(RETURNED), expected_rule(CAST)])
                    );
                }
            }
        }
        fixture.assert_source(source.as_bytes());
    }

    // A new returned-local observation still uses the unchanged scalar/UTF16 conversion.
    fixture.write(
        "fn length() -> usize {\n    let length = \"🦉\".len() as usize;\n    length\n}\n"
            .as_bytes(),
    );
    for (format, end) in [("json", 36), ("sonar", 37)] {
        let document = fixture.analyze("sonar-parity", format, 0);
        assert_eq!(
            issues(&document, format),
            [expected_issue(
                RETURNED,
                RETURN_MESSAGE,
                (2, 4, 2, end),
                format
            )]
        );
    }
}

#[test]
fn rust_s1488_cli_substantive_clean_controls_preserve_independent_rules() {
    let fixture = Fixture::new();
    for (source, returned_count, cast_count) in [
        (
            "fn direct(value: &str) -> usize { value.len() as usize }\n",
            0,
            1,
        ),
        ("fn direct(value: &str) -> usize { value.len() }\n", 0, 0),
        (
            "fn ordinary(value: &str) -> usize { let length = value.len(); length }\n",
            1,
            0,
        ),
        (
            "fn used(value: &str) -> usize {\n    let length = value.len() as usize;\n    consume(length);\n    length\n}\nfn consume(_: usize) {}\n",
            0,
            1,
        ),
        (
            "fn adjusted(value: &str) -> usize {\n    let length = value.len() as usize;\n    length + 1\n}\n",
            0,
            1,
        ),
        (
            "fn capacity(value: std::fs::Metadata) -> usize { value.len() as usize }\n",
            0,
            0,
        ),
        (
            "// fn example(v: &str) -> usize { let length = v.len() as usize; length }\nfn decoy() -> usize {\n    let text = \"let length = value.len() as usize; length\";\n    text.len()\n}\n",
            0,
            0,
        ),
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let document = fixture.analyze("sonar-parity", format, 0);
            let found = issues(&document, format);
            assert_eq!(
                found
                    .iter()
                    .filter(|issue| rule(issue, format) == RETURNED)
                    .count(),
                returned_count,
                "{source}: {document}"
            );
            assert_eq!(
                found
                    .iter()
                    .filter(|issue| rule(issue, format) == CAST)
                    .count(),
                cast_count,
                "{source}: {document}"
            );
        }
        fixture.assert_source(source.as_bytes());
    }
    fixture.write(ORDINARY.as_bytes());
    for format in ["json", "sonar"] {
        let document = fixture.analyze("sonar-parity", format, 0);
        assert_eq!(
            issues(&document, format),
            [expected_issue(
                RETURNED,
                RETURN_MESSAGE,
                (3, 4, 3, 68),
                format
            )]
        );
    }
    fixture.assert_source(ORDINARY.as_bytes());
}

#[test]
fn rust_s1488_cli_malformed_and_invalid_utf8_remain_incomplete() {
    let fixture = Fixture::new();
    for source in [b"fn broken(".as_slice(), b"\xff\n".as_slice()] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let document = fixture.analyze("sonar-parity", format, 2);
            assert_eq!(document["parity"]["completeness"], "incomplete");
            let selected: Vec<_> = if format == "json" {
                document["files"]
                    .as_array()
                    .expect("native files")
                    .iter()
                    .flat_map(|file| file["issues"].as_array().expect("native issues"))
                    .filter(|issue| rule(issue, format) == RETURNED)
                    .collect()
            } else {
                issues(&document, format)
                    .iter()
                    .filter(|issue| rule(issue, format) == RETURNED)
                    .collect()
            };
            assert!(selected.is_empty(), "{document}");
        }
        fixture.assert_source(source);
    }
}

#[test]
fn rust_s1488_cli_absent_remedies_preserve_sources_and_reports() {
    let fixture = Fixture::new();
    fixture.write(OVERLAP.as_bytes());
    let native = fixture.analyze("strict", "json", 0);
    let generic = fixture.analyze("strict", "sonar", 0);
    for issue in issues(&native, "json") {
        assert!(issue.get("fix").is_none());
        assert!(issue.get("alternatives").is_none());
        assert!(issue.get("flows").is_none());
    }
    for issue in issues(&generic, "sonar") {
        assert!(issue.get("secondaryLocations").is_none());
    }
    for suggestion in ["rust:S1488=inline-returned-local", "rust:S4325=remove-cast"] {
        for mode in ["--diff", "--apply"] {
            let output = fixture.run(&[
                "fix",
                "--profile",
                "strict",
                "--suggestion",
                suggestion,
                mode,
                "--json",
                FILE,
            ]);
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            let report: Value =
                serde_json::from_slice(&output.stdout).expect("actual refusal report");
            assert_eq!(report["applied"], 0);
            assert_eq!(report["mechanical"], 0);
            assert_eq!(report["files"], json!([]));
            assert!(
                report["warnings"]
                    .as_array()
                    .expect("refusal warnings")
                    .iter()
                    .any(|warning| warning
                        .as_str()
                        .is_some_and(|message| message.contains("is unavailable"))),
                "{report}"
            );
            fixture.assert_source(OVERLAP.as_bytes());
            assert_eq!(fixture.analyze("strict", "json", 0), native);
            assert_eq!(fixture.analyze("strict", "sonar", 0), generic);
        }
    }
}
