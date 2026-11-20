use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

// Primary text is backed by twelve original SonarPython 5.31 findings.
// Async-keyword supporting locations now complete those retained target objects.
// Contract/Unicode/recovery/cache cases below preserve measured native baselines.
const MESSAGE: &str = "Use asynchronous features in this function or remove the `async` keyword.";
const POSITIVE: &str = "async def compute(value):\n    return value\n";
const AWAITED: &str = "async def compute(value):\n    return await value\n";
const CONTRACTS: &str = r#"async def ordinary():
    return 1

async def awaited():
    return await work()

async def async_loop():
    async for item in stream():
        consume(item)

async def async_context():
    async with resource():
        consume(1)

async def async_comprehension():
    return [item async for item in stream()]

async def generator():
    yield 1

async def nested_yield():
    def values():
        yield 1
    return values

async def nested_lambda():
    return lambda: (yield 1)

async def nested_await():
    async def inner():
        return await work()
    return inner

def synchronous():
    return 1

@decorate
async def decorated():
    return 1

async def __aenter__():
    return 1

class Derived(Base):
    async def method(self):
        return 1

class WithMeta(metaclass=Meta):
    async def method(self):
        return 1

async def trivial_pass():
    pass

async def trivial_raise():
    raise NotImplementedError

async def trivial_return():
    return NotImplemented

async def trivial_docstring():
    """Contract only."""

async def docstring_and_return():
    """Ordinary async callable."""
    return 1
"#;

struct Fixture(PathBuf);

struct Capture {
    report: Value,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s7503-message-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, name: &str, source: &str, profile: &str, format: &str, exit: i32) -> Capture {
        let filename = format!("{name}.py");
        let path = self.0.join(&filename);
        std::fs::write(&path, source).expect("fixture source");
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                &filename,
                "--profile",
                profile,
                "--format",
                format,
                "--cache-dir",
                "cache",
            ])
            .output()
            .expect("run hoonarqube");
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{name}/{profile}/{format}: {output:?}"
        );
        assert_eq!(
            std::fs::read_to_string(path).expect("source readback"),
            source
        );
        assert_eq!(
            output.stderr.is_empty(),
            exit == 0,
            "{name}/{profile}/{format}"
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
        if format == "json" {
            assert_eq!(report["project"]["complete"], exit == 0);
            assert_eq!(report["project"]["files"][0]["path"], filename);
            assert_eq!(
                report["project"]["files"][0]["status"],
                if exit == 0 { "complete" } else { "failed" }
            );
        }
        Capture {
            report,
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn targets(report: &Value, format: &str) -> Vec<Value> {
    if format == "json" {
        report["files"][0]["issues"]
            .as_array()
            .expect("native issues")
            .iter()
            .filter(|issue| issue["rule_key"] == "python:S7503")
            .cloned()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .expect("Generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == "python:S7503")
            .cloned()
            .collect()
    }
}

fn expected_primary(name: &str, format: &str, line: u32, end: u32) -> Value {
    if format == "json" {
        json!({"rule_key": "python:S7503", "message": MESSAGE,
            "range": {"start": {"line": line, "column": 10}, "end": {"line": line, "column": end}},
            "flows": [{"locations": [{"message": "This function is async.",
                "range": {"start": {"line": line, "column": 0}, "end": {"line": line, "column": 5}}}]}]})
    } else {
        json!({"ruleId": "python:S7503", "primaryLocation": {
            "filePath": format!("{name}.py"), "message": MESSAGE,
            "textRange": {"startLine": line, "startColumn": 10, "endLine": line, "endColumn": end}},
            "secondaryLocations": [{"filePath": format!("{name}.py"), "message": "This function is async.",
                "textRange": {"startLine": line, "startColumn": 0, "endLine": line, "endColumn": 5}}]})
    }
}

#[test]
fn python_s7503_primary_message_matches_reference_in_both_exports() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let capture = fixture.analyze("ordinary", POSITIVE, profile, format, 0);
            assert_eq!(
                targets(&capture.report, format),
                vec![expected_primary("ordinary", format, 1, 17)]
            );
        }
    }
}

fn assert_contract_ranges(report: &Value, name: &str, profile: &str, format: &str) {
    let ranges = [(1, 18), (21, 22), (26, 23), (29, 22), (64, 30)];
    let found = targets(report, format);
    let expected = if name == "contracts" {
        &ranges[..]
    } else {
        &[]
    };
    assert_eq!(found.len(), expected.len(), "{name}/{profile}/{format}");
    for (issue, (line, end)) in found.iter().zip(expected) {
        let range = if format == "json" {
            &issue["range"]
        } else {
            &issue["primaryLocation"]["textRange"]
        };
        let expected_range = if format == "json" {
            json!({"start": {"line": line, "column": 10}, "end": {"line": line, "column": end}})
        } else {
            json!({"startLine": line, "startColumn": 10, "endLine": line, "endColumn": end})
        };
        assert_eq!(*range, expected_range);
        assert_eq!(*issue, expected_primary(name, format, *line, *end));
    }
}

#[test]
fn python_s7503_contract_and_nested_scope_selection_is_preserved() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            for name in ["contracts", "test_contracts"] {
                let capture = fixture.analyze(name, CONTRACTS, profile, format, 0);
                assert_contract_ranges(&capture.report, name, profile, format);
            }
        }
    }
}

#[test]
fn python_s7503_astral_crlf_name_preserves_scalar_and_utf16_ranges() {
    let fixture = Fixture::new();
    let source = "async def 𐐀compute():\r\n    return 1\r\n";
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let capture = fixture.analyze("unicode", source, profile, format, 0);
            let end = if format == "json" { 18 } else { 19 };
            assert_eq!(
                targets(&capture.report, format),
                vec![expected_primary("unicode", format, 1, end)]
            );
        }
    }
}

#[test]
fn python_s7503_malformed_recovery_preserves_incomplete_result() {
    let fixture = Fixture::new();
    let source = "async def recovered():\n    return 1\n\ndef broken(:\n    pass\n";
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let capture = fixture.analyze("malformed", source, profile, format, 2);
            assert_eq!(
                targets(&capture.report, format),
                vec![expected_primary("malformed", format, 1, 19)]
            );
            if format == "json" {
                assert_eq!(
                    capture.report["project"]["files"][0]["reason"],
                    "syntax tree contains recovered or missing nodes"
                );
                assert!(
                    capture.report["files"][0]["issues"]
                        .as_array()
                        .expect("recovered issues")
                        .iter()
                        .any(|issue| issue["rule_key"] == "python:ParsingError")
                );
            } else {
                assert!(
                    capture.report["issues"]
                        .as_array()
                        .expect("recovered issues")
                        .iter()
                        .any(|issue| issue["ruleId"] == "python:ParsingError")
                );
            }
        }
    }
}

#[test]
fn python_s7503_same_path_cache_tracks_positive_clean_restored_source() {
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let fixture = Fixture::new();
            let first = fixture.analyze("case", POSITIVE, profile, format, 0);
            assert_eq!(
                targets(&first.report, format),
                vec![expected_primary("case", format, 1, 17)]
            );
            let clean = fixture.analyze("case", AWAITED, profile, format, 0);
            assert!(targets(&clean.report, format).is_empty());
            let restored = fixture.analyze("case", POSITIVE, profile, format, 0);
            assert_eq!(first.stdout, restored.stdout);
            assert_eq!(first.stderr, restored.stderr);
        }
    }
}
