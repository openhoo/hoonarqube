use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

const MESSAGE: &str = "Use asynchronous features in this function or remove the `async` keyword.";
const SUPPORT: &str = "This function is async.";
const NESTED: &str = "def container():\n    async def outer():\n        async def nested():\n            return 1\n        return nested\n    return outer\n";
const POSITIVE: &str = "if True:\n\tasync  def  compute():\n\t\treturn value\n";
const AWAITED: &str = "if True:\n\tasync  def  compute():\n\t\treturn await value\n";

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
            "hoonarqube-s7503-support-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, name: &str, source: &str, profile: &str, format: &str, exit: i32) -> Capture {
        let filename = format!("{name}.py");
        let path = self.0.join(&filename);
        std::fs::write(&path, source).expect("fixture source");
        assert_eq!(
            std::fs::read(&path).expect("source before"),
            source.as_bytes()
        );
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
            std::fs::read(path).expect("source after"),
            source.as_bytes()
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

fn expected(
    name: &str,
    format: &str,
    primary: (u32, u32, u32),
    keyword: Option<(u32, u32)>,
) -> Value {
    let (line, start, end) = primary;
    let filename = format!("{name}.py");
    let mut issue = if format == "json" {
        json!({"rule_key": "python:S7503", "message": MESSAGE,
            "range": {"start": {"line": line, "column": start}, "end": {"line": line, "column": end}}})
    } else {
        json!({"ruleId": "python:S7503", "primaryLocation": {"filePath": filename, "message": MESSAGE,
            "textRange": {"startLine": line, "startColumn": start, "endLine": line, "endColumn": end}}})
    };
    if let Some((line, start)) = keyword {
        let end = start + 5;
        if format == "json" {
            issue["flows"] = json!([{"locations": [{"message": SUPPORT,
                "range": {"start": {"line": line, "column": start}, "end": {"line": line, "column": end}}}]}]);
        } else {
            issue["secondaryLocations"] = json!([{"filePath": filename, "message": SUPPORT,
                "textRange": {"startLine": line, "startColumn": start, "endLine": line, "endColumn": end}}]);
        }
    }
    issue
}

struct ReferenceCase {
    name: &'static str,
    source: &'static str,
    primaries: &'static [(u32, u32, u32)],
}

// Exact source bytes and all twelve tuples from retained SonarQube 26.9 /
// SonarPython 5.31 observations. Layout controls below have native authority.
const REFERENCE: &[ReferenceCase] = &[
    ReferenceCase {
        name: "s7487_bad",
        source: "import subprocess\n\nasync def run_cmd():\n    subprocess.run([\"ls\"])\n",
        primaries: &[(3, 10, 17)],
    },
    ReferenceCase {
        name: "s7489_bad",
        source: "import os\n\nasync def sh():\n    os.system(\"ls\")\n",
        primaries: &[(3, 10, 12)],
    },
    ReferenceCase {
        name: "s7490_bad",
        source: "async def guarded():\n    with anyio.fail_after(5):\n        prepare()\n",
        primaries: &[(1, 10, 17)],
    },
    ReferenceCase {
        name: "s7493_bad",
        source: "async def rd(p):\n    data = open(\"f\").read()\n    text = p.read_text()\n",
        primaries: &[(1, 10, 12)],
    },
    ReferenceCase {
        name: "s7499_bad",
        source: "import requests\n\nasync def web():\n    response = requests.get(\"http://example.test\")\n",
        primaries: &[(3, 10, 13)],
    },
    ReferenceCase {
        name: "s7502_bad",
        source: "import asyncio\n\nasync def worker():\n    return 1\n\nasyncio.create_task(worker())\n",
        primaries: &[(3, 10, 16)],
    },
    ReferenceCase {
        name: "s7502_good",
        source: "import asyncio\n\nasync def worker():\n    return 1\n\nhandle = asyncio.create_task(worker())\n",
        primaries: &[(3, 10, 16)],
    },
    ReferenceCase {
        name: "s7503_bad",
        source: "async def compute(value):\n    return value\n",
        primaries: &[(1, 10, 17)],
    },
    ReferenceCase {
        name: "s7513_bad",
        source: "import trio\n\nasync def work():\n    return 1\n\nasync def one():\n    async with trio.open_nursery() as nursery:\n        nursery.start_soon(work)\n",
        primaries: &[(3, 10, 14)],
    },
    ReferenceCase {
        name: "s7513_good",
        source: "import trio\n\nasync def first_job():\n    return 1\n\nasync def second_job():\n    return 2\n\nasync def many():\n    async with trio.open_nursery() as nursery:\n        nursery.start_soon(first_job)\n        nursery.start_soon(second_job)\n",
        primaries: &[(3, 10, 19), (6, 10, 20)],
    },
    ReferenceCase {
        name: "s7515_bad",
        source: "async def load():\n    with open(\"data.txt\") as handle:\n        data = handle.read()\n    return data\n",
        primaries: &[(1, 10, 14)],
    },
];

fn assert_reference_case(fixture: &Fixture, case: &ReferenceCase, profile: &str, format: &str) {
    let capture = fixture.analyze(case.name, case.source, profile, format, 0);
    let expected: Vec<_> = case
        .primaries
        .iter()
        .map(|&primary| expected(case.name, format, primary, Some((primary.0, 0))))
        .collect();
    assert_eq!(
        targets(&capture.report, format),
        expected,
        "{}/{profile}/{format}",
        case.name
    );
}

#[test]
fn python_s7503_all_twelve_reference_supports_match_full_objects() {
    assert_eq!(REFERENCE.len(), 11);
    assert_eq!(
        REFERENCE
            .iter()
            .map(|case| case.primaries.len())
            .sum::<usize>(),
        12
    );
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            for case in REFERENCE {
                assert_reference_case(&fixture, case, profile, format);
            }
        }
    }
}

struct Layout {
    name: &'static str,
    source: &'static str,
    primary: &'static [(u32, u32, u32)],
    keyword: &'static [(u32, u32)],
}

const LAYOUTS: &[Layout] = &[
    Layout {
        name: "nested",
        source: NESTED,
        primary: &[(2, 14, 19), (3, 18, 24)],
        keyword: &[(2, 4), (3, 8)],
    },
    Layout {
        name: "tabs",
        source: "if True:\n\tasync\tdef\tspaced():\n\t\treturn 1\n",
        primary: &[(2, 11, 17)],
        keyword: &[(2, 1)],
    },
    Layout {
        name: "formfeed",
        source: "\u{000c}async  def  spaced():\n    return 1\n",
        primary: &[(1, 13, 19)],
        keyword: &[(1, 1)],
    },
    Layout {
        name: "continuation",
        source: "async \\\n  def continued():\n    return 1\n",
        primary: &[(2, 6, 15)],
        keyword: &[(1, 0)],
    },
];

fn assert_layout(fixture: &Fixture, case: &Layout, profile: &str, format: &str) {
    let capture = fixture.analyze(case.name, case.source, profile, format, 0);
    assert_eq!(case.primary.len(), case.keyword.len());
    let expected: Vec<_> = case
        .primary
        .iter()
        .zip(case.keyword)
        .map(|(&primary, &keyword)| expected(case.name, format, primary, Some(keyword)))
        .collect();
    assert_eq!(
        targets(&capture.report, format),
        expected,
        "{}/{profile}/{format}",
        case.name
    );
}

#[test]
fn python_s7503_supports_follow_tokens_through_nested_and_spaced_headers() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            for layout in LAYOUTS {
                assert_layout(&fixture, layout, profile, format);
            }
        }
    }
}

#[test]
fn python_s7503_test_scope_remains_exempt() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let capture = fixture.analyze("test_nested", NESTED, profile, format, 0);
            assert!(targets(&capture.report, format).is_empty());
        }
    }
}

#[test]
fn python_s7503_indented_astral_crlf_keeps_scalar_and_utf16_coordinates() {
    let fixture = Fixture::new();
    let source = "if True:\r\n\tasync def 𐐀compute():\r\n\t\treturn 1\r\n";
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let capture = fixture.analyze("unicode", source, profile, format, 0);
            let end = if format == "json" { 19 } else { 20 };
            assert_eq!(
                targets(&capture.report, format),
                vec![expected("unicode", format, (2, 11, end), Some((2, 1)))]
            );
        }
    }
}

fn assert_recovery(fixture: &Fixture, profile: &str, format: &str, missing_name: bool) {
    let (name, source, primary, keyword) = if missing_name {
        (
            "missing_name",
            "async def ():\n    return 1\n",
            (1, 9, 9),
            None,
        )
    } else {
        (
            "recovered",
            "async def recovered():\n    return 1\n\ndef broken(:\n    pass\n",
            (1, 10, 19),
            Some((1, 0)),
        )
    };
    let capture = fixture.analyze(name, source, profile, format, 2);
    assert_eq!(
        targets(&capture.report, format),
        vec![expected(name, format, primary, keyword)]
    );
    if format == "json" {
        assert_eq!(
            capture.report["project"]["files"][0]["reason"],
            "syntax tree contains recovered or missing nodes"
        );
        assert!(
            capture.report["files"][0]["issues"]
                .as_array()
                .expect("recovery issues")
                .iter()
                .any(|issue| issue["rule_key"] == "python:ParsingError")
        );
    } else {
        assert!(
            capture.report["issues"]
                .as_array()
                .expect("recovery issues")
                .iter()
                .any(|issue| issue["ruleId"] == "python:ParsingError")
        );
    }
}

#[test]
fn python_s7503_recovery_preserves_primary_and_incompleteness_when_support_is_unproven() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            assert_recovery(&fixture, profile, format, false);
            assert_recovery(&fixture, profile, format, true);
        }
    }
}

fn assert_cache_transition(profile: &str, format: &str) {
    let fixture = Fixture::new();
    let first = fixture.analyze("case", POSITIVE, profile, format, 0);
    assert_eq!(
        targets(&first.report, format),
        vec![expected("case", format, (2, 13, 20), Some((2, 1)))]
    );
    let clean = fixture.analyze("case", AWAITED, profile, format, 0);
    assert!(targets(&clean.report, format).is_empty());
    let restored = fixture.analyze("case", POSITIVE, profile, format, 0);
    assert_eq!(
        targets(&restored.report, format),
        vec![expected("case", format, (2, 13, 20), Some((2, 1)))]
    );
    assert_eq!(first.stdout, restored.stdout);
    assert_eq!(first.stderr, restored.stderr);
}

#[test]
fn python_s7503_supports_survive_same_path_positive_clean_restored_cache_stages() {
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            assert_cache_transition(profile, format);
        }
    }
}
