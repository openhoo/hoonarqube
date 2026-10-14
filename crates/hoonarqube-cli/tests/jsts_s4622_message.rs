use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const MESSAGE: &str = "Refactor this union type to have less than 3 elements.";
const POSITIVE: &str = concat!(
    "export function four(p: A | B | C | D): void {}\n",
    "export function five(p: A | B | C | D | E): void {}\n",
    "export function six(p: A | B | C | D | E | F): void {}\n",
    "export function forty(p: T01 | T02 | T03 | T04 | T05 | T06 | T07 | T08 | T09 | T10 | T11 | T12 | T13 | T14 | T15 | T16 | T17 | T18 | T19 | T20 | T21 | T22 | T23 | T24 | T25 | T26 | T27 | T28 | T29 | T30 | T31 | T32 | T33 | T34 | T35 | T36 | T37 | T38 | T39 | T40): void {}\n",
);
const RANGES: [(u32, u32, u32); 4] = [(1, 24, 37), (2, 24, 41), (3, 23, 44), (4, 25, 262)];

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-jsts-s4622-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn write(&self, file: &str, source: &str) {
        std::fs::write(self.0.join(file), source).expect("fixture source");
    }

    fn assert_source(&self, file: &str, source: &str) {
        assert_eq!(
            std::fs::read(self.0.join(file)).expect("source readback"),
            source.as_bytes()
        );
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube")
    }

    fn analyze(&self, file: &str, format: &str, profile: &str) -> Value {
        let output = self.run(&[
            "analyze",
            "--profile",
            profile,
            "--format",
            format,
            "--",
            file,
        ]);
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("analysis report")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_complete(report: &Value, files: usize) {
    assert_eq!(report["project"]["complete"], true);
    assert_eq!(
        report["files"].as_array().expect("native files").len(),
        files
    );
    let inventory = report["project"]["files"].as_array().expect("inventory");
    assert_eq!(inventory.len(), files);
    assert!(inventory.iter().all(|entry| entry["status"] == "complete"));
}

fn native_issues(report: &Value, rule: &str) -> Vec<Value> {
    report["files"]
        .as_array()
        .expect("native files")
        .iter()
        .flat_map(|file| file["issues"].as_array().expect("native issues"))
        .filter(|issue| issue["rule_key"] == rule)
        .cloned()
        .collect()
}

#[test]
fn native_s4622_messages_use_threshold_with_unchanged_primary_and_payload() {
    let fixture = Fixture::new("native");
    fixture.write("positive.ts", POSITIVE);
    let expected = RANGES.map(|(line, start, end)| {
        json!({
            "rule_key": "typescript:S4622",
            "message": MESSAGE,
            "range": {
                "start": {"line": line, "column": start},
                "end": {"line": line, "column": end},
            },
        })
    });
    for profile in ["sonar-parity", "strict"] {
        let report = fixture.analyze("positive.ts", "json", profile);
        assert_complete(&report, 1);
        assert_eq!(report["files"][0]["path"], "positive.ts");
        assert_eq!(native_issues(&report, "typescript:S4622"), expected);
        fixture.assert_source("positive.ts", POSITIVE);
    }
}

#[test]
fn generic_s4622_messages_use_threshold_with_unchanged_primary_and_metadata() {
    let fixture = Fixture::new("generic");
    fixture.write("positive.ts", POSITIVE);
    let expected = RANGES.map(|(line, start, end)| {
        json!({
            "ruleId": "typescript:S4622",
            "primaryLocation": {
                "filePath": "positive.ts",
                "message": MESSAGE,
                "textRange": {
                    "startLine": line, "startColumn": start,
                    "endLine": line, "endColumn": end,
                },
            },
        })
    });
    for profile in ["sonar-parity", "strict"] {
        assert_complete(&fixture.analyze("positive.ts", "json", profile), 1);
        let report = fixture.analyze("positive.ts", "sonar", profile);
        let issues: Vec<_> = report["issues"]
            .as_array()
            .expect("generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == "typescript:S4622")
            .cloned()
            .collect();
        assert_eq!(issues, expected);
        let metadata: Vec<_> = report["rules"]
            .as_array()
            .expect("generic rules")
            .iter()
            .filter(|rule| rule["id"] == "typescript:S4622")
            .collect();
        assert_eq!(
            metadata,
            vec![&json!({
                "cleanCodeAttribute": "CLEAR",
                "description": "Hoonarqube finding for `typescript:S4622`.",
                "engineId": "hoonarqube",
                "id": "typescript:S4622",
                "impacts": [{"severity": "MEDIUM", "softwareQuality": "MAINTAINABILITY"}],
                "name": "typescript:S4622",
                "severity": "MAJOR",
                "type": "CODE_SMELL",
            })]
        );
        fixture.assert_source("positive.ts", POSITIVE);
    }
}

#[test]
fn compact_alias_utility_and_javascript_controls_stay_unchanged() {
    let fixture = Fixture::new("controls");
    let cases = [
        (
            "compact.ts",
            "export function compact(p: A | B | C): void {}\n",
        ),
        ("alias.ts", "export type Direct = A | B | C | D;\n"),
        (
            "utility.ts",
            "export type Utility = Partial<A | B | C | D>;\n",
        ),
        (
            "javascript.js",
            "export function flags(value) { return value | 2 | 4 | 8; }\n",
        ),
    ];
    for (file, source) in cases {
        fixture.write(file, source);
    }
    for profile in ["sonar-parity", "strict"] {
        let native = fixture.analyze(".", "json", profile);
        assert_complete(&native, cases.len());
        assert!(native_issues(&native, "typescript:S4622").is_empty());
        assert!(native_issues(&native, "javascript:S4622").is_empty());
        let generic = fixture.analyze(".", "sonar", profile);
        assert!(
            generic["issues"]
                .as_array()
                .expect("generic issues")
                .iter()
                .all(|issue| {
                    issue["ruleId"] != "typescript:S4622" && issue["ruleId"] != "javascript:S4622"
                })
        );
        for (file, source) in cases {
            fixture.assert_source(file, source);
        }
    }
}

fn check_fix_mode(fixture: &Fixture, before: &Value, mode: &str, unavailable: bool) {
    let mut args = vec![
        "fix",
        "--profile",
        "sonar-parity",
        "--rule",
        "typescript:S4622",
        mode,
        "--json",
    ];
    if unavailable {
        args.extend(["--suggestion", "typescript:S4622=s4622-reduce-union"]);
    }
    args.extend(["--", "positive.ts"]);
    let output = fixture.run(&args);
    assert_eq!(
        output.status.code(),
        Some(i32::from(unavailable)),
        "{output:?}"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
    assert_eq!(report["applied"], 0);
    assert_eq!(report["mechanical"], 0);
    assert_eq!(report["files"], json!([]));
    if unavailable {
        assert!(String::from_utf8_lossy(&output.stderr).contains("is unavailable"));
    }
    fixture.assert_source("positive.ts", POSITIVE);
    assert_eq!(
        &fixture.analyze("positive.ts", "json", "sonar-parity"),
        before
    );
}

#[test]
fn selected_s4622_fix_and_unavailable_suggestion_preserve_source() {
    let fixture = Fixture::new("fix");
    fixture.write("positive.ts", POSITIVE);
    let before = fixture.analyze("positive.ts", "json", "sonar-parity");
    assert_complete(&before, 1);
    assert_eq!(native_issues(&before, "typescript:S4622").len(), 4);
    for mode in ["--diff", "--apply"] {
        for unavailable in [false, true] {
            check_fix_mode(&fixture, &before, mode, unavailable);
        }
    }
}
