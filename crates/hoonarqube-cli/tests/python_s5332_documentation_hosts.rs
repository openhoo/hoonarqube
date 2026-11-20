use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const KEY: &str = "python:S5332";

#[derive(Clone, Copy)]
struct Expected {
    message: &'static str,
    span: (u32, u32, u32, u32),
}

#[derive(Clone, Copy)]
struct Case {
    path: &'static str,
    source: &'static str,
    expected: &'static [Expected],
    group: usize,
}

// Complete sources and exact S5332 objects from one live SonarQube 26.9 /
// SonarPython 5.31 project. MAIN/TEST scope is explicit in both analyses.
const LIVE_CASES: &[Case] = &[
    Case {
        path: "docs/conf.py",
        source: "BUFFER = \"pay load\"\nOTHER = \"pay load\"\nTHIRD = \"pay load\"\nGATEWAY = \"192.168.1.1\"\nENDPOINT = \"http://remote.invalid/path\"\n\ndef helper():\n    stale = 1\n    return BUFFER\n",
        expected: &[Expected {
            message: "Using HTTP protocol is insecure. Use HTTPS instead.",
            span: (5, 11, 5, 39),
        }],
        group: 4,
    },
    Case {
        path: "src/controls/bare-http-positive.py",
        source: "endpoint = \"http://\"\n",
        expected: &[Expected {
            message: "Using HTTP protocol is insecure. Use HTTPS instead.",
            span: (1, 11, 1, 20),
        }],
        group: 2,
    },
    Case {
        path: "src/controls/example-port-path-query-fragment.py",
        source: "endpoint = \"http://api.internal.example:8080/v1?next=http://remote.invalid/#fragment\"\n",
        expected: &[],
        group: 1,
    },
    Case {
        path: "src/controls/example-suffix-boundary-unsafe.py",
        source: "endpoint = \"http://api.example.invalid/v1\"\n",
        expected: &[Expected {
            message: "Using HTTP protocol is insecure. Use HTTPS instead.",
            span: (1, 11, 1, 42),
        }],
        group: 2,
    },
    Case {
        path: "src/controls/example-uppercase-host.py",
        source: "endpoint = \"http://API.INTERNAL.EXAMPLE/v1\"\n",
        expected: &[],
        group: 1,
    },
    Case {
        path: "src/controls/original-example-clean.py",
        source: "endpoint = \"http://api.internal.example/v1\"\n",
        expected: &[],
        group: 0,
    },
    Case {
        path: "src/controls/original-https-clean.py",
        source: "endpoint = \"https://api.internal.example/v1\"\n",
        expected: &[],
        group: 0,
    },
    Case {
        path: "src/controls/replacement-ftp-positive.py",
        source: "endpoint = \"ftp://remote.invalid/data\"\n",
        expected: &[Expected {
            message: "Using FTP protocol is insecure. Use SFTP, SCP or FTPS instead.",
            span: (1, 11, 1, 38),
        }],
        group: 2,
    },
    Case {
        path: "src/controls/replacement-http-positive.py",
        source: "endpoint = \"http://remote.invalid/path\"\n",
        expected: &[Expected {
            message: "Using HTTP protocol is insecure. Use HTTPS instead.",
            span: (1, 11, 1, 39),
        }],
        group: 2,
    },
    Case {
        path: "src/controls/replacement-telnet-positive.py",
        source: "endpoint = \"telnet://remote.invalid/data\"\n",
        expected: &[Expected {
            message: "Using Telnet protocol is insecure. Use SSH instead.",
            span: (1, 11, 1, 41),
        }],
        group: 2,
    },
    Case {
        path: "src/gateway.py",
        source: "BUFFER = \"pay load\"\nOTHER = \"pay load\"\nTHIRD = \"pay load\"\nGATEWAY = \"192.168.1.1\"\nENDPOINT = \"http://remote.invalid/path\"\n\ndef helper():\n    stale = 1\n    return BUFFER\n",
        expected: &[Expected {
            message: "Using HTTP protocol is insecure. Use HTTPS instead.",
            span: (5, 11, 5, 39),
        }],
        group: 4,
    },
    Case {
        path: "src/migrations/docstring_endpoint.py",
        source: "def fetch():\n    \"\"\"Reads the spec at http://yaml.org/spec.\"\"\"\n    return download(\"http://remote.invalid/data\")\n",
        expected: &[Expected {
            message: "Using HTTP protocol is insecure. Use HTTPS instead.",
            span: (3, 20, 3, 48),
        }],
        group: 3,
    },
    Case {
        path: "src/migrations/rule_local_http_ftp.py",
        source: "web = 'http://remote.invalid/path'\nfiles = 'ftp://remote.invalid/data'\n",
        expected: &[
            Expected {
                message: "Using HTTP protocol is insecure. Use HTTPS instead.",
                span: (1, 6, 1, 34),
            },
            Expected {
                message: "Using FTP protocol is insecure. Use SFTP, SCP or FTPS instead.",
                span: (2, 8, 2, 35),
            },
        ],
        group: 3,
    },
    Case {
        path: "src/migrations/rule_local_safe_hosts.py",
        source: "secure = 'https://unsafe.test'\nlocal = 'http://localhost:8000'\n",
        expected: &[],
        group: 3,
    },
    Case {
        path: "tests/test_gateway.py",
        source: "BUFFER = \"pay load\"\nOTHER = \"pay load\"\nTHIRD = \"pay load\"\nGATEWAY = \"192.168.1.1\"\nENDPOINT = \"http://remote.invalid/path\"\n\ndef helper():\n    stale = 1\n    return BUFFER\n",
        expected: &[],
        group: 4,
    },
];

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s5332-documentation-hosts-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(
        &self,
        cases: &[Case],
        target: &str,
        profile: &str,
        format: &str,
        incomplete: bool,
    ) -> (Value, Output) {
        for case in cases {
            let path = self.0.join(case.path);
            std::fs::create_dir_all(path.parent().expect("source parent"))
                .expect("source directories");
            std::fs::write(path, case.source).expect("source");
        }
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                target,
                "--profile",
                profile,
                "--format",
                format,
                "--test-include",
                "tests/**/*.py",
                "--cache-dir",
            ])
            .arg(self.0.join(format!("cache-{profile}-{format}")))
            .output()
            .expect("run hoonarqube");
        assert_eq!(
            output.status.code(),
            Some(if incomplete { 2 } else { 0 }),
            "{output:?}"
        );
        assert_eq!(output.stderr.is_empty(), !incomplete, "{output:?}");
        for case in cases {
            assert_eq!(
                std::fs::read(self.0.join(case.path)).expect("source readback"),
                case.source.as_bytes()
            );
        }
        let report: Value = serde_json::from_slice(&output.stdout).expect("complete report");
        assert_eq!(report.get("parity").is_some(), profile == "sonar-parity");
        if profile == "sonar-parity" {
            assert_eq!(
                report["parity"]["completeness"],
                if incomplete {
                    "incomplete"
                } else {
                    "complete_native_analysis"
                }
            );
        }
        if format == "json" {
            assert_project_contract(&report, cases, target, incomplete);
        }
        (report, output)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_project_contract(report: &Value, cases: &[Case], target: &str, incomplete: bool) {
    assert_eq!(report["project"]["complete"], !incomplete);
    assert_eq!(
        report["files"].as_array().expect("files").len(),
        cases.len()
    );
    let states = report["project"]["files"].as_array().expect("file states");
    assert_eq!(states.len(), cases.len());
    for case in cases {
        let path = if target == "." {
            format!("./{}", case.path)
        } else {
            case.path.to_string()
        };
        let state = states
            .iter()
            .find(|file| file["path"] == path)
            .expect("file state");
        assert_eq!(
            state["classification"],
            if case.path.starts_with("tests/") {
                "test"
            } else {
                "source"
            }
        );
        assert_eq!(
            state["status"],
            if incomplete { "failed" } else { "complete" }
        );
        if !incomplete {
            assert_eq!(state["reason"], Value::Null);
        }
    }
    let main_files = if incomplete {
        0
    } else {
        cases
            .iter()
            .filter(|case| !case.path.starts_with("tests/"))
            .count()
    };
    assert_eq!(report["project"]["metrics"]["files"], main_files);
    if !incomplete {
        assert_eq!(report["project"]["warnings"], json!([]));
    }
}

fn reference_targets(report: &Value, format: &str) -> Vec<Value> {
    let mut actual = Vec::new();
    if format == "json" {
        for file in report["files"].as_array().expect("files") {
            for issue in file["issues"].as_array().expect("issues") {
                if issue["rule_key"] == KEY {
                    actual.push(json!({"path":file["path"],"issue":issue}));
                }
            }
        }
    } else {
        actual.extend(
            report["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .filter(|issue| issue["ruleId"] == KEY)
                .cloned(),
        );
    }
    actual
}

fn assert_reference_targets(report: &Value, cases: &[Case], target: &str, format: &str) {
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    actual.extend(reference_targets(report, format));
    for case in cases {
        let path = if target == "." {
            format!("./{}", case.path)
        } else {
            case.path.to_string()
        };
        for item in case.expected {
            let (line, column, end_line, end_column) = item.span;
            expected.push(if format == "json" {
                json!({"path":path,"issue":{"rule_key":KEY,"message":item.message,"range":{"start":{"line":line,"column":column},"end":{"line":end_line,"column":end_column}}}})
            } else {
                json!({"ruleId":KEY,"primaryLocation":{"filePath":path,"message":item.message,"textRange":{"startLine":line,"startColumn":column,"endLine":end_line,"endColumn":end_column}}})
            });
        }
    }
    let canonical = |values: &mut Vec<Value>| values.sort_by_key(Value::to_string);
    canonical(&mut actual);
    canonical(&mut expected);
    assert_eq!(actual, expected);
    if format == "sonar" {
        let descriptors: Vec<_> = report["rules"]
            .as_array()
            .expect("descriptors")
            .iter()
            .filter(|rule| rule["id"] == KEY)
            .cloned()
            .collect();
        let descriptor = json!({"cleanCodeAttribute":"CONVENTIONAL","description":"Hoonarqube finding for `python:S5332`.","engineId":"hoonarqube","id":KEY,"impacts":[],"name":KEY,"severity":"CRITICAL","type":"SECURITY_HOTSPOT"});
        assert_eq!(
            descriptors,
            if expected.is_empty() {
                vec![]
            } else {
                vec![descriptor]
            }
        );
    }
}

fn check_group(group: usize) {
    let fixture = Fixture::new();
    let cases: Vec<_> = LIVE_CASES
        .iter()
        .filter(|case| case.group == group)
        .copied()
        .collect();
    assert!(!cases.is_empty());
    // Execute all four combinations before target assertions, including red.
    let mut results = Vec::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            results.push((format, fixture.analyze(&cases, ".", profile, format, false)));
        }
    }
    for (format, (report, _)) in results {
        assert_reference_targets(&report, &cases, ".", format);
    }
}

#[test]
fn python_s5332_documentation_hosts_exempts_original_example_endpoint() {
    check_group(0);
}

#[test]
fn python_s5332_documentation_hosts_exempts_case_and_authority_controls() {
    check_group(1);
}

#[test]
fn python_s5332_documentation_hosts_preserves_actual_unsafe_protocols_and_suffix_boundary() {
    check_group(2);
}

#[test]
fn python_s5332_documentation_hosts_preserves_complete_migrated_unsafe_bodies() {
    check_group(3);
}

#[test]
fn python_s5332_documentation_hosts_preserves_explicit_main_test_and_docs_scope() {
    check_group(4);
}

fn assert_parsing_diagnostic(report: &Value, output: &Output, format: &str) {
    assert_eq!(
        std::str::from_utf8(&output.stderr).expect("diagnostics"),
        concat!(
            "cannot analyze case.py: syntax tree contains recovered or missing nodes\n",
            "case.py: syntax tree contains recovered or missing nodes\n",
            "duplication analysis skipped because one or more eligible source files failed\n",
            "incomplete source facts for case.py: syntax tree contains recovered or missing nodes\n"
        )
    );
    let issues: Vec<_> = if format == "json" {
        report["files"][0]["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .collect()
    };
    assert!(issues.iter().any(|issue| issue[if format == "json" {
        "rule_key"
    } else {
        "ruleId"
    }] == "python:ParsingError"));
}

#[test]
fn python_s5332_documentation_hosts_malformed_sources_stay_incomplete() {
    let fixture = Fixture::new();
    // Native malformed guards, not additional successfully scanned reference inputs.
    for source in [
        "def broken(:\n    pass\n",
        "endpoint = \"http://api.internal.example/v1\"\ndef broken(:\n    pass\n",
    ] {
        let case = Case {
            path: "case.py",
            source,
            expected: &[],
            group: 5,
        };
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let (report, output) = fixture.analyze(&[case], "case.py", profile, format, true);
                assert_reference_targets(&report, &[case], "case.py", format);
                assert_parsing_diagnostic(&report, &output, format);
            }
        }
    }
}

#[test]
fn python_s5332_documentation_hosts_cached_host_changes_restore_complete_documents() {
    let fixture = Fixture::new();
    let original = LIVE_CASES
        .iter()
        .find(|case| case.path.ends_with("original-example-clean.py"))
        .expect("original fixture");
    let replacement = LIVE_CASES
        .iter()
        .find(|case| case.path.ends_with("replacement-http-positive.py"))
        .expect("unsafe fixture");
    let clean = Case {
        path: "case.py",
        ..*original
    };
    let unsafe_host = Case {
        path: "case.py",
        ..*replacement
    };
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let initial = fixture.analyze(&[clean], "case.py", profile, format, false);
            assert_reference_targets(&initial.0, &[clean], "case.py", format);
            let changed = fixture.analyze(&[unsafe_host], "case.py", profile, format, false);
            assert_reference_targets(&changed.0, &[unsafe_host], "case.py", format);
            assert_ne!(initial.1.stdout, changed.1.stdout);
            let restored = fixture.analyze(&[clean], "case.py", profile, format, false);
            assert_reference_targets(&restored.0, &[clean], "case.py", format);
            assert_eq!(initial.1.stdout, restored.1.stdout);
            assert_eq!(initial.1.stderr, restored.1.stderr);
        }
    }
}
