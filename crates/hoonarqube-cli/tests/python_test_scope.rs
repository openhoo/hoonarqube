use serde_json::Value;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const SOURCE: &str = "import unittest\n# NOSONAR\nclass Checks(unittest.TestCase):\n    def helper(self):\n        return 42\n";

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-python-test-scope-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("checks.py"), SOURCE).unwrap();
        Self(path)
    }

    fn analyze(&self, test: bool, semantic: bool, profile: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hoonarqube"));
        command.current_dir(&self.0).args([
            "analyze",
            "--format",
            "json",
            "--profile",
            profile,
            "--cache-dir",
            "cache",
        ]);
        if test {
            command.args(["--test-include", "checks.py"]);
        }
        if semantic {
            command.args(["--python-project", "."]);
        }
        command.args(["--", "checks.py"]).output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn has(report: &Value, key: &str) -> bool {
    report["files"][0]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["rule_key"] == key)
}

fn check_reclassification(semantic: bool, profile: &str) {
    let fixture = Fixture::new();
    let source = document(&fixture.analyze(false, semantic, profile));
    assert!(has(&source, "python:S1720"), "source MAIN finding");
    assert!(!has(&source, "python:S2187"), "source TEST control");
    let tests = document(&fixture.analyze(true, semantic, profile));
    assert!(
        !has(&tests, "python:S1720"),
        "cached source MAIN finding leaked: {tests}"
    );
    assert!(
        has(&tests, "python:S2187"),
        "TEST detector remains ineligible: {tests}"
    );
    assert!(has(&tests, "python:NoSonar"), "ALL finding retained");
    assert_eq!(tests["files"][0]["path"], source["files"][0]["path"]);
    assert_eq!(tests["files"][0]["metrics"], source["files"][0]["metrics"]);
    assert_eq!(tests["project"]["files"][0]["classification"], "test");
    assert_eq!(tests["project"]["complete"], true);
    assert_eq!(tests["project"]["metrics"]["files"], 0);
    assert_eq!(
        tests,
        document(&fixture.analyze(true, semantic, profile)),
        "cached TEST repeat"
    );
    assert_eq!(
        source,
        document(&fixture.analyze(false, semantic, profile)),
        "reclassified back to MAIN"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("checks.py")).unwrap(),
        SOURCE
    );
    let clean = "import unittest\nclass Checks(unittest.TestCase):\n    def test_value(self):\n        self.assertEqual(abs(-42), 42)\n";
    std::fs::write(fixture.0.join("checks.py"), clean).unwrap();
    let clean_report = document(&fixture.analyze(true, semantic, profile));
    assert_eq!(clean_report["project"]["complete"], true);
    assert!(
        clean_report["files"][0]["issues"]
            .as_array()
            .unwrap()
            .is_empty(),
        "clean collected test: {clean_report}"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("checks.py")).unwrap(),
        clean
    );
}

#[test]
fn python_cli_test_reclassification_invalidates_main_cache_and_activates_test_rules() {
    check_reclassification(false, "strict");
}

#[test]
fn python_cli_semantic_test_reclassification_preserves_namespace_and_cache() {
    check_reclassification(true, "strict");
}

#[test]
fn malformed_explicit_python_tests_remain_incomplete() {
    let fixture = Fixture::new();
    let source = "def broken(:\n    pass\n";
    std::fs::write(fixture.0.join("checks.py"), source).unwrap();
    for semantic in [false, true] {
        let output = fixture.analyze(true, semantic, "sonar-parity");
        assert_eq!(output.status.code(), Some(2));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(has(&report, "python:ParsingError"));
        assert_eq!(report["project"]["complete"], false);
        assert_eq!(report["project"]["files"][0]["classification"], "test");
        assert_eq!(report["project"]["files"][0]["status"], "failed");
        assert_eq!(report["project"]["metrics"]["files"], 0);
    }
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("checks.py")).unwrap(),
        source
    );
}
