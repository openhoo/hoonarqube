use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

const CORE: &str = "community-26.11-python-core";
const LEGACY: &str = "sonar-parity";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "hoonarqube-python-core-{}-{nonce}",
            std::process::id(),
        ));
        std::fs::create_dir(&root).unwrap();
        let source = format!(
            "import re\nmarker = '{}'\nre.search(r\"a+Z\", marker)\n",
            "x".repeat(130),
        );
        std::fs::write(root.join("case.py"), source).unwrap();
        std::fs::write(
            root.join("gate.json"),
            json!({"schema_version":1,"conditions":[{"scope":"overall","metric":"files","operator":"eq","threshold":1}]}).to_string(),
        ).unwrap();
        Self(root)
    }

    fn scan(&self, profile: &str, opts: &[&str], exit: i32) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                "case.py",
                "--format",
                "json",
                "--profile",
                profile,
                "--cache-dir",
                "cache",
            ])
            .args(opts)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        if profile == CORE {
            assert!(String::from_utf8_lossy(&output.stderr).contains("is incomplete"));
        }
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn issues(report: &Value, rule: &str) -> Vec<Value> {
    report["files"][0]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|issue| issue["rule_key"] == rule)
        .cloned()
        .collect()
}

#[test]
fn filters_findings_and_keeps_cache_entries_isolated_by_selection() {
    let fixture = Fixture::new();
    let ordinary = fixture.scan(LEGACY, &[], 0);
    let core = fixture.scan(CORE, &[], 2);
    assert_eq!(issues(&ordinary, "python:LineLength").len(), 1);
    assert!(issues(&core, "python:LineLength").is_empty());
    assert_eq!(issues(&core, "python:S8786").len(), 1);
    assert_eq!(
        issues(&core, "python:S8786"),
        issues(&ordinary, "python:S8786")
    );
    assert_eq!(core["project"], ordinary["project"]);
    assert!(core.get("parity").is_none());
    assert!(ordinary.get("partial_rule_selection").is_none());
    let coverage = &core["partial_rule_selection"];
    assert_eq!(coverage["profile"], CORE);
    assert_eq!(coverage["reference_active_rules"], 232);
    assert_eq!(coverage["selected_catalog_keys"], 222);
    assert_eq!(
        coverage["missing_catalog_keys"].as_array().unwrap().len(),
        8
    );
    assert_eq!(
        coverage["unmapped_parameter_keys"],
        json!(["python:S2068", "python:S6418"])
    );
    assert_eq!(fixture.scan(CORE, &[], 2), core);
    assert_eq!(fixture.scan(LEGACY, &[], 0), ordinary);
}

#[test]
fn s905_matches_core_reference_ranges_in_both_python_analysis_modes() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.0.join("case.py"),
        include_str!("fixtures/python_core_s905.py"),
    )
    .unwrap();
    // Primary ranges observed on this fixture in Community 26.11 with
    // Python analyzer 5.32.0.37250 and the built-in Sonar way core profile.
    let expected = [
        (4, 0, 5),
        (8, 0, 9),
        (9, 0, 9),
        (10, 0, 9),
        (11, 0, 15),
        (12, 0, 16),
        (13, 0, 14),
        (14, 0, 15),
        (15, 0, 15),
        (16, 0, 21),
        (22, 4, 9),
        (26, 4, 13),
    ];
    for opts in [&[][..], &["--python-project", "."][..]] {
        let legacy = fixture.scan(LEGACY, opts, 0);
        let core = fixture.scan(CORE, opts, 2);
        assert_eq!(core["project"]["complete"], true);
        let ranges = issues(&core, "python:S905")
            .iter()
            .map(|issue| {
                let start = &issue["range"]["start"];
                let end = &issue["range"]["end"];
                assert_eq!(start["line"], end["line"]);
                (
                    start["line"].as_u64().unwrap(),
                    start["column"].as_u64().unwrap(),
                    end["column"].as_u64().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(ranges, expected);

        let legacy_issues = issues(&legacy, "python:S905");
        for line in [5, 6, 7, 17, 28] {
            assert!(
                legacy_issues
                    .iter()
                    .any(|i| i["range"]["start"]["line"] == line)
            );
        }
        assert_eq!(fixture.scan(CORE, opts, 2), core);
        assert_eq!(fixture.scan(LEGACY, opts, 0), legacy);
    }
}

#[test]
fn same_selection_baseline_compares_but_partial_selection_cannot_pass_a_gate() {
    let fixture = Fixture::new();
    fixture.scan(CORE, &["--write-baseline", "core.json"], 2);
    fixture.scan(LEGACY, &["--write-baseline", "legacy.json"], 0);
    assert!(fixture.0.join("core.json").is_file());
    let core = fixture.scan(
        CORE,
        &["--baseline", "core.json", "--quality-gate", "gate.json"],
        2,
    );
    let assessment = &core["assessment"];
    assert_eq!(assessment["new_code"]["status"], "complete");
    assert_eq!(assessment["gate"]["status"], "unavailable");
    assert_eq!(assessment["gate"]["conditions"][0]["actual"], Value::Null);
    assert_eq!(assessment["gate"]["conditions"][0]["status"], "unavailable");
    let mismatch = fixture.scan(CORE, &["--baseline", "legacy.json"], 2);
    assert_eq!(mismatch["assessment"]["new_code"]["status"], "incomplete");
    assert!(
        mismatch["assessment"]["new_code"]["diagnostics"]
            .to_string()
            .contains("incompatible")
    );
    let ordinary = fixture.scan(LEGACY, &["--quality-gate", "gate.json"], 0);
    assert_eq!(ordinary["assessment"]["gate"]["status"], "pass");
}
