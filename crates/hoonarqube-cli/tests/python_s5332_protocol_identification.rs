use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const KEY: &str = "python:S5332";
const MESSAGE: &str = "Using HTTP protocol is insecure. Use HTTPS instead.";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s5332-protocol-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, case: &Case, profile: &str, format: &str) -> (Value, Output) {
        std::fs::write(self.0.join("case.py"), case.source).expect("source");
        let cache = self.0.join(format!("cache-{profile}-{format}"));
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                "case.py",
                "--profile",
                profile,
                "--format",
                format,
                "--cache-dir",
            ])
            .arg(cache)
            .output()
            .expect("run hoonarqube");
        assert_eq!(
            output.status.code(),
            Some(if case.incomplete { 2 } else { 0 }),
            "{}: {output:?}",
            case.name
        );
        assert_eq!(
            output.stderr.is_empty(),
            !case.incomplete,
            "{}: {output:?}",
            case.name
        );
        assert_eq!(
            std::fs::read(self.0.join("case.py")).expect("source readback"),
            case.source.as_bytes()
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("report");
        if format == "json" {
            assert_eq!(report["project"]["complete"], !case.incomplete);
            assert_eq!(
                report["project"]["metrics"]["files"],
                u32::from(!case.incomplete)
            );
            assert_eq!(report["project"]["files"][0]["path"], "case.py");
            assert_eq!(
                report["project"]["files"][0]["status"],
                if case.incomplete {
                    "failed"
                } else {
                    "complete"
                }
            );
            if !case.incomplete {
                assert_eq!(report["project"]["warnings"], json!([]));
                assert_eq!(report["project"]["files"][0]["reason"], Value::Null);
            }
        }
        assert_eq!(report.get("parity").is_some(), profile == "sonar-parity");
        if profile == "sonar-parity" {
            assert_eq!(
                report["parity"]["completeness"],
                if case.incomplete {
                    "incomplete"
                } else {
                    "complete_native_analysis"
                }
            );
        }
        (report, output)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Case {
    name: &'static str,
    source: &'static str,
    ranges: &'static [(usize, usize, usize, usize)],
    group: usize,
    incomplete: bool,
}

// Native reductions backed by the retained OSS/installed-bytecode evidence.
// These controls are not additional standalone SonarQube-scanned fixtures.
const CASES: &[Case] = &[
    Case {
        name: "original-click-reduction",
        source: "def launch(url: str):\n    return url.startswith((\"http://\", \"https://\"))\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "bare-assignment-guard",
        source: "value = \"http://\"\n",
        ranges: &[(1, 8, 1, 17)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "requests-mount-guard",
        source: "def configure(self):\n    self.mount(\"http://\", object())\n",
        ranges: &[(2, 15, 2, 24)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "literal-instance-startswith",
        source: "result = \"https://safe.invalid\".startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "typed-instance-startswith",
        source: "def identify(value: str):\n    return value.startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "nested-tuple-parentheses",
        source: "def identify(value: str):\n    return value.startswith((((\"http://\",),)))\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "startswith-later-position",
        source: "def identify(value: str):\n    return value.startswith(\"https://\", \"http://\")\n",
        ranges: &[(2, 40, 2, 49)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "startswith-keyword-guard",
        source: "def identify(value: str):\n    return value.startswith(prefix=\"http://\")\n",
        ranges: &[(2, 35, 2, 44)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "replace-old-pattern",
        source: "def identify(value: str):\n    return value.replace(\"http://\", \"https://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "replace-new-endpoint",
        source: "def identify(value: str):\n    return value.replace(\"https://\", \"http://\")\n",
        ranges: &[(2, 37, 2, 46)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "remove-prefix-pattern",
        source: "def identify(value: str):\n    return value.removeprefix(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "remove-suffix-pattern",
        source: "def identify(value: str):\n    return value.removesuffix(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "endswith-name-guard",
        source: "def identify(value: str):\n    return value.endswith(\"http://\")\n",
        ranges: &[(2, 26, 2, 35)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "unbound-str-pattern",
        source: "result = str.startswith(value, \"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "unbound-str-receiver-guard",
        source: "result = str.startswith(\"http://\", \"https://\")\n",
        ranges: &[(1, 24, 1, 33)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "known-nonstr-owner-guard",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = Endpoint().startswith(\"http://\")\n",
        ranges: &[(4, 31, 4, 40)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "list-wrapper-guard",
        source: "def identify(value: str):\n    return value.startswith([\"http://\"])\n",
        ranges: &[(2, 29, 2, 38)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "nested-call-guard",
        source: "def identify(value: str):\n    return value.startswith(make(\"http://\"))\n",
        ranges: &[(2, 33, 2, 42)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "full-endpoint-pattern",
        source: "def identify(value: str):\n    return value.startswith(\"http://remote.invalid/path\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "clean-secure-safe-prose",
        source: "secure = \"https://remote.invalid\"\nlocal = \"http://localhost:8000\"\nprose = \"See http://remote.invalid\"\n",
        ranges: &[],
        group: 2,
        incomplete: false,
    },
    Case {
        name: "docstring-clean",
        source: "def describe():\n    \"\"\"http://remote.invalid\"\"\"\n    return None\n",
        ranges: &[],
        group: 2,
        incomplete: false,
    },
    Case {
        name: "unicode-crlf-pattern",
        source: "marker = \"😀\"; result = \"url\".startswith(\"http://\")\r\n",
        ranges: &[],
        group: 3,
        incomplete: false,
    },
    Case {
        name: "incomplete-unrelated",
        source: "def broken(:\n    pass\n",
        ranges: &[],
        group: 4,
        incomplete: true,
    },
    Case {
        name: "incomplete-with-pattern",
        source: "result = \"url\".startswith(\"http://\")\ndef broken(:\n    pass\n",
        ranges: &[],
        group: 4,
        incomplete: true,
    },
    Case {
        name: "unknown-receiver-method",
        source: "def identify(value):\n    return value.startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "known-bytes-owner-guard",
        source: "value = b\"https://safe.invalid\"\nresult = value.startswith(\"http://\")\n",
        ranges: &[(2, 26, 2, 35)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "rebound-str-class-guard",
        source: "class str:\n    @staticmethod\n    def startswith(receiver, prefix):\n        return prefix\nresult = str.startswith(None, \"http://\")\n",
        ranges: &[(5, 30, 5, 39)],
        group: 1,
        incomplete: false,
    },
    Case {
        name: "prior-committed-bare-contract",
        source: "a = \"http://\"\nb = value.startswith((\"http://\", \"https://\", \"/\"))\nc = \"see http://www.rssboard.org/rss-profile for details\"\nns = \"http://www.w3.org/2005/Atom\"\nns2 = \"http://purl.org/dc/elements/1.1/\"\nspace = \" http://remote.invalid\"\nsecure = \"https://remote.invalid/?next=http://remote.invalid\"\nlocal = \"http://localhost/?next=ftp://remote.invalid\"\nendpoint = \"http://remote.invalid/?next=ftp://remote.invalid\"\n",
        ranges: &[(1, 4, 1, 13), (9, 11, 9, 61)],
        group: 0,
        incomplete: false,
    },
];

fn assert_targets(report: &Value, case: &Case, format: &str) {
    let (issues, key) = if format == "json" {
        (&report["files"][0]["issues"], "rule_key")
    } else {
        (&report["issues"], "ruleId")
    };
    let actual: Vec<_> = issues
        .as_array()
        .expect("issues")
        .iter()
        .filter(|issue| issue[key] == KEY)
        .cloned()
        .collect();
    let expected: Vec<_> = case.ranges.iter().map(|&(line, column, end_line, end_column)| {
        if format == "json" {
            json!({"rule_key": KEY, "message": MESSAGE, "range": {"start": {"line": line, "column": column}, "end": {"line": end_line, "column": end_column}}})
        } else {
            let utf16_column = |line: usize, column: usize| case.source.lines().nth(line - 1).expect("source line").chars().take(column).map(char::len_utf16).sum::<usize>();
            json!({"ruleId": KEY, "primaryLocation": {"filePath": "case.py", "message": MESSAGE, "textRange": {"startLine": line, "startColumn": utf16_column(line, column), "endLine": end_line, "endColumn": utf16_column(end_line, end_column)}}})
        }
    }).collect();
    assert_eq!(actual, expected, "{}: {}", case.name, case.source);
    if format == "sonar" {
        let definitions: Vec<_> = report["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter(|rule| rule["id"] == KEY)
            .cloned()
            .collect();
        let descriptor = json!({"cleanCodeAttribute":"CONVENTIONAL","description":"Hoonarqube finding for `python:S5332`.","engineId":"hoonarqube","id":KEY,"impacts":[],"name":KEY,"severity":"CRITICAL","type":"SECURITY_HOTSPOT"});
        assert_eq!(
            definitions,
            if case.ranges.is_empty() {
                vec![]
            } else {
                vec![descriptor]
            }
        );
    }
}

fn check_group(group: usize) {
    let fixture = Fixture::new();
    for case in CASES.iter().filter(|case| case.group == group) {
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let (report, output) = fixture.analyze(case, profile, format);
                assert_targets(&report, case, format);
                if case.incomplete {
                    assert_eq!(
                        String::from_utf8(output.stderr).expect("diagnostics"),
                        concat!(
                            "cannot analyze case.py: syntax tree contains recovered or missing nodes\n",
                            "case.py: syntax tree contains recovered or missing nodes\n",
                            "duplication analysis skipped because one or more eligible source files failed\n",
                            "incomplete source facts for case.py: syntax tree contains recovered or missing nodes\n"
                        )
                    );
                    let (issues, key) = if format == "json" {
                        (&report["files"][0]["issues"], "rule_key")
                    } else {
                        (&report["issues"], "ruleId")
                    };
                    assert!(
                        issues
                            .as_array()
                            .expect("issues")
                            .iter()
                            .any(|issue| issue[key] == "python:ParsingError")
                    );
                }
            }
        }
    }
}

#[test]
fn python_s5332_protocol_identification_exempts_patterns_and_removes_descriptor() {
    check_group(0);
}

#[test]
fn python_s5332_protocol_identification_preserves_values_arguments_and_owner_boundaries() {
    check_group(1);
}

#[test]
fn python_s5332_protocol_identification_preserves_secure_safe_prose_and_docstrings() {
    check_group(2);
}

#[test]
fn python_s5332_protocol_identification_unicode_crlf_keeps_coordinates() {
    check_group(3);
}

#[test]
fn python_s5332_protocol_identification_malformed_inputs_remain_incomplete() {
    check_group(4);
}

#[test]
fn python_s5332_protocol_identification_cached_context_changes_preserve_bare_values() {
    let fixture = Fixture::new();
    let pattern = Case {
        name: "cache-pattern",
        source: "result = \"url\".startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    };
    let value = Case {
        name: "cache-value",
        source: "result = \"http://\"\n",
        ranges: &[(1, 9, 1, 18)],
        group: 1,
        incomplete: false,
    };
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let initial = fixture.analyze(&pattern, profile, format);
            assert_targets(&initial.0, &pattern, format);
            let changed = fixture.analyze(&value, profile, format);
            assert_targets(&changed.0, &value, format);
            assert_ne!(initial.1.stdout, changed.1.stdout);
            let restored = fixture.analyze(&pattern, profile, format);
            assert_eq!(initial.1.stdout, restored.1.stdout);
            assert_eq!(initial.1.stderr, restored.1.stderr);
        }
    }
}

// Exact sources and ranges from the supplemental live SonarQube owner scan.
const LIVE_OWNER_CASES: &[Case] = &[
    Case {
        name: "bytes-strip.py",
        source: "result = b\"x\".strip().startswith(\"http://\")\n",
        ranges: &[(1, 33, 1, 42)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "annotated-bytes.py",
        source: "def provide() -> bytes:\n    return b\"x\"\nresult = provide().startswith(\"http://\")\n",
        ranges: &[(3, 30, 3, 39)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "bytes-lower.py",
        source: "def identify(value: bytes):\n    return value.lower().startswith(\"http://\")\n",
        ranges: &[(2, 36, 2, 45)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "annotated-str.py",
        source: "def provide() -> str:\n    return \"x\"\nresult = provide().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "unknown-call.py",
        source: "from unknown import provide\nresult = provide().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "imported-str-alias.py",
        source: "from builtins import str as Text\nresult = Text.startswith(value, \"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "annotated-custom.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\ndef provide() -> Endpoint:\n    return Endpoint()\nresult = provide().startswith(\"http://\")\n",
        ranges: &[(6, 30, 6, 39)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "bytes-constructor.py",
        source: "result = bytes().startswith(\"http://\")\n",
        ranges: &[(1, 28, 1, 37)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "bare.py",
        source: "endpoint = \"http://\"\n",
        ranges: &[(1, 11, 1, 20)],
        group: 0,
        incomplete: false,
    },
];

// Exact sources and ranges from the separate live binding-owner scan.
const SHADOW_OWNER_CASES: &[Case] = &[
    Case {
        name: "parameter-shadow.py",
        source: "def provide() -> bytes:\n    return b\"x\"\ndef identify(provide):\n    return provide().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "local-shadow.py",
        source: "def provide() -> bytes:\n    return b\"x\"\ndef identify():\n    provide = unknown\n    return provide().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "reassigned-provider.py",
        source: "def provide() -> bytes:\n    return b\"x\"\nprovide = unknown\nresult = provide().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "import-shadow.py",
        source: "def provide() -> bytes:\n    return b\"x\"\ndef identify():\n    from other import provide\n    return provide().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "known-bytes.py",
        source: "def provide() -> bytes:\n    return b\"x\"\nresult = provide().startswith(\"http://\")\n",
        ranges: &[(3, 30, 3, 39)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "bytes-decode.py",
        source: "result = b\"x\".decode().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "unknown-bytes-method.py",
        source: "result = b\"x\".unknown().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
];

fn live_owner_targets(
    report: &Value,
    format: &str,
    cases: &[Case],
) -> std::collections::BTreeMap<String, Vec<Value>> {
    let mut actual: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::default();
    if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        assert_eq!(report["project"]["metrics"]["files"], cases.len());
        for file in report["files"].as_array().expect("files") {
            actual.insert(
                file["path"].as_str().expect("path").to_owned(),
                file["issues"]
                    .as_array()
                    .expect("issues")
                    .iter()
                    .filter(|issue| issue["rule_key"] == KEY)
                    .cloned()
                    .collect(),
            );
        }
    } else {
        for case in cases {
            actual.insert(format!("./{}", case.name), vec![]);
        }
        for issue in report["issues"]
            .as_array()
            .expect("issues")
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
        {
            actual
                .get_mut(issue["primaryLocation"]["filePath"].as_str().expect("path"))
                .expect("known source")
                .push(issue.clone());
        }
    }
    actual
}

fn expected_live_owner_targets(
    format: &str,
    cases: &[Case],
) -> std::collections::BTreeMap<String, Vec<Value>> {
    cases.iter().map(|case| {
        let path = format!("./{}", case.name);
        let issues = case.ranges.iter().map(|&(line, column, end_line, end_column)| {
            if format == "json" {
                json!({"rule_key": KEY, "message": MESSAGE, "range": {"start": {"line": line, "column": column}, "end": {"line": end_line, "column": end_column}}})
            } else {
                json!({"ruleId": KEY, "primaryLocation": {"filePath": path, "message": MESSAGE, "textRange": {"startLine": line, "startColumn": column, "endLine": end_line, "endColumn": end_column}}})
            }
        }).collect();
        (path, issues)
    }).collect()
}

fn check_live_owner_project(cases: &[Case]) {
    let fixture = Fixture::new();
    for case in cases {
        std::fs::write(fixture.0.join(case.name), case.source).expect("live source");
    }
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
                .current_dir(&fixture.0)
                .args([
                    "analyze",
                    ".",
                    "--profile",
                    profile,
                    "--format",
                    format,
                    "--cache-dir",
                ])
                .arg(fixture.0.join(format!("cache-{profile}-{format}")))
                .output()
                .expect("analyze live owner project");
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("report");
            assert_eq!(report.get("parity").is_some(), profile == "sonar-parity");
            assert_eq!(
                live_owner_targets(&report, format, cases),
                expected_live_owner_targets(format, cases),
                "{profile}/{format}"
            );
            for case in cases {
                assert_eq!(
                    std::fs::read(fixture.0.join(case.name)).expect("source readback"),
                    case.source.as_bytes()
                );
            }
        }
    }
}

#[test]
fn python_s5332_protocol_identification_preserves_live_result_owner_boundaries() {
    check_live_owner_project(LIVE_OWNER_CASES);
}

#[test]
fn python_s5332_protocol_identification_preserves_live_shadowed_result_owners() {
    check_live_owner_project(SHADOW_OWNER_CASES);
}

// Exact sources and ranges from the separate live class-owner scan.
const CLASS_OWNER_CASES: &[Case] = &[
    Case {
        name: "class-import-shadow.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nfrom other import Endpoint\nresult = Endpoint().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "class-local-import-shadow.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\ndef identify():\n    from other import Endpoint\n    return Endpoint().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "class-reassignment.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nEndpoint = unknown\nresult = Endpoint().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "class-parameter-shadow.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\ndef identify(Endpoint):\n    return Endpoint().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "class-lambda-shadow.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda Endpoint: Endpoint().startswith(\"http://\"))(unknown)\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "nested-class-parameter.py",
        source: "class Container:\n    class Endpoint:\n        def startswith(self, value):\n            return value\ndef identify(Container):\n    return Container.Endpoint().startswith(\"http://\")\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "known-class.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = Endpoint().startswith(\"http://\")\n",
        ranges: &[(4, 31, 4, 40)],
        group: 0,
        incomplete: false,
    },
];

#[test]
fn python_s5332_protocol_identification_preserves_live_shadowed_class_owners() {
    check_live_owner_project(CLASS_OWNER_CASES);
}

// Exact sources and ranges from the separate live lambda-owner scan.
const LAMBDA_OWNER_CASES: &[Case] = &[
    Case {
        name: "class-lambda-unshadowed.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda : Endpoint().startswith(\"http://\"))()\n",
        ranges: &[(4, 41, 4, 50)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "class-lambda-unrelated.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda other: Endpoint().startswith(\"http://\"))(unknown)\n",
        ranges: &[(4, 46, 4, 55)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "class-lambda-shadowed.py",
        source: "class Endpoint:\n    def startswith(self, value):\n        return value\nresult = (lambda Endpoint: Endpoint().startswith(\"http://\"))(unknown)\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "function-lambda-unshadowed.py",
        source: "def Endpoint() -> bytes:\n    return b\"\"\nresult = (lambda : Endpoint().startswith(\"http://\"))()\n",
        ranges: &[(3, 41, 3, 50)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "function-lambda-unrelated.py",
        source: "def Endpoint() -> bytes:\n    return b\"\"\nresult = (lambda other: Endpoint().startswith(\"http://\"))(unknown)\n",
        ranges: &[(3, 46, 3, 55)],
        group: 0,
        incomplete: false,
    },
    Case {
        name: "function-lambda-shadowed.py",
        source: "def Endpoint() -> bytes:\n    return b\"\"\nresult = (lambda Endpoint: Endpoint().startswith(\"http://\"))(unknown)\n",
        ranges: &[],
        group: 0,
        incomplete: false,
    },
];

#[test]
fn python_s5332_protocol_identification_preserves_live_lambda_owner_boundaries() {
    check_live_owner_project(LAMBDA_OWNER_CASES);
}
