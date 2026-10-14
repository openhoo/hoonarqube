use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s1066-elif-{}-{id}", std::process::id()));
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
        let out = self.run(&[
            "analyze",
            "case.py",
            "--profile",
            profile,
            "--format",
            format,
        ]);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert!(out.stderr.is_empty(), "{out:?}");
        let report: Value = serde_json::from_slice(&out.stdout).expect("report");
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
        .filter(|issue| issue[key] == "python:S1066")
        .cloned()
        .collect()
}

fn expected(
    format: &str,
    line: u32,
    col: u32,
    enclosing_line: u32,
    enclosing_col: u32,
    width: u32,
) -> Value {
    let message = "Merge this if statement with the enclosing one.";
    if format == "json" {
        json!({"rule_key":"python:S1066", "message":message,
            "range":{"start":{"line":line,"column":col},"end":{"line":line,"column":col+2}},
            "flows":[{"locations":[{"message":"enclosing", "range":{
                "start":{"line":enclosing_line,"column":enclosing_col},
                "end":{"line":enclosing_line,"column":enclosing_col+width}}}]}]})
    } else {
        json!({"ruleId":"python:S1066", "primaryLocation":{"filePath":"case.py",
            "message":message,"textRange":{"startLine":line,"endLine":line,"startColumn":col,"endColumn":col+2}},
            "secondaryLocations":[{"filePath":"case.py","message":"enclosing","textRange":{
                "startLine":enclosing_line,"endLine":enclosing_line,
                "startColumn":enclosing_col,"endColumn":enclosing_col+width}}]})
    }
}

struct Case {
    name: &'static str,
    source: &'static str,
    spans: &'static [(u32, u32, u32, u32, u32)],
    changes: bool,
}

// Installed-reference line-length boundary, plus preserved native guards.
// Synthetic controls are not claimed as newly scanned reference inputs.
const CASES: &[Case] = &[
    Case {
        name: "click-raw-mode",
        source: "def _less_uses_raw_mode(less_env: str, cmd_params: list[str]) -> bool:\n    \"\"\"Detect a raw-control-characters request in a ``less`` invocation.\n\n    Parses the tokens of the ``LESS`` environment variable and the command\n    line: only short-option clusters (``-R``, ``-rX``, ``-XrY``) and the\n    ``--raw-control-chars`` long option request raw mode. Filenames and\n    long-option values may carry the letter ``r`` without being such a\n    request.\n    \"\"\"\n    try:\n        env_tokens = shlex.split(less_env)\n    except ValueError:\n        # Unbalanced quotes make ``LESS`` unparsable: fall back to whitespace\n        # splitting rather than failing the pager over it.\n        env_tokens = less_env.split()\n    tokens = env_tokens + cmd_params\n\n    for token in tokens:\n        if token.startswith(\"--\"):\n            if token.casefold() == \"--raw-control-chars\":\n                return True\n        elif token.startswith(\"-\") and len(token) > 1:\n            if \"r\" in token[1:].casefold():\n                return True\n\n    return False\n",
        spans: &[],
        changes: true,
    },
    Case {
        name: "short-root-elif-80",
        source: "if root:\n    work()\nelif aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\n    if inner:\n        work()\n",
        spans: &[(4, 4, 3, 0, 4)],
        changes: false,
    },
    Case {
        name: "short-root-elif-81",
        source: "if root:\n    work()\nelif aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\n    if inner:\n        work()\n",
        spans: &[],
        changes: true,
    },
    Case {
        name: "long-root-elif-80",
        source: "if rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr:\n    work()\nelif aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\n    if inner:\n        work()\n",
        spans: &[(4, 4, 3, 0, 4)],
        changes: true,
    },
    Case {
        name: "long-root-elif-81",
        source: "if rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr:\n    work()\nelif aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\n    if inner:\n        work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "long-root-short-elif",
        source: "if rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr:\n    work()\nelif value:\n    if inner:\n        work()\n",
        spans: &[(4, 4, 3, 0, 4)],
        changes: true,
    },
    Case {
        name: "short-final-elif",
        source: "if root:\n    work()\nelif value:\n    if inner:\n        work()\n",
        spans: &[(4, 4, 3, 0, 4)],
        changes: false,
    },
    Case {
        name: "direct-positive",
        source: "if outer:\n    if inner:\n        work()\n",
        spans: &[(2, 4, 1, 0, 2)],
        changes: false,
    },
    Case {
        name: "direct-chain",
        source: "if outer:\n    if inner:\n        if child:\n            work()\n",
        spans: &[(2, 4, 1, 0, 2), (3, 8, 2, 4, 2)],
        changes: false,
    },
    Case {
        name: "direct-80",
        source: "if aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\n    if inner:\n        work()\n",
        spans: &[(2, 4, 1, 0, 2)],
        changes: false,
    },
    Case {
        name: "direct-81",
        source: "if aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\n    if inner:\n        work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "no-nested",
        source: "if outer:\n    work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "earlier-elif",
        source: "if root:\n    work()\nelif earlier:\n    if inner:\n        work()\nelif last:\n    work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "chain-with-else",
        source: "if root:\n    work()\nelif value:\n    if inner:\n        work()\nelse:\n    stop()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "inner-else",
        source: "if root:\n    work()\nelif value:\n    if inner:\n        work()\n    else:\n        stop()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "inner-elif",
        source: "if root:\n    work()\nelif value:\n    if inner:\n        work()\n    elif other:\n        stop()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "extra-clause-statement",
        source: "if root:\n    work()\nelif value:\n    setup()\n    if inner:\n        work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "root-walrus-existing-exemption",
        source: "if (root := value):\n    work()\nelif other:\n    if inner:\n        work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "inner-walrus-existing-exemption",
        source: "if root:\n    work()\nelif value:\n    if (inner := value):\n        work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "earlier-root-comment-existing-exemption",
        source: "if root:\n    # preserve current root comment window\n    work()\nelif value:\n    if inner:\n        work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "clause-comment-existing-exemption",
        source: "if root:\n    work()\nelif value:\n    # preserve comment guard\n    if inner:\n        work()\n",
        spans: &[],
        changes: false,
    },
    Case {
        name: "empty",
        source: "",
        spans: &[],
        changes: false,
    },
];

fn assert_cases(changes: bool, format: &str) {
    let fixture = Fixture::new();
    for case in CASES.iter().filter(|case| case.changes == changes) {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(case.source, profile, format);
            assert_eq!(
                targets(&report, format),
                case.spans
                    .iter()
                    .map(|&(line, col, el, ec, width)| {
                        expected(format, line, col, el, ec, width)
                    })
                    .collect::<Vec<_>>(),
                "{}/{profile}/{format}",
                case.name
            );
        }
    }
}

#[test]
fn native_final_elif_uses_its_own_condition_for_the_line_guard() {
    assert_cases(true, "json");
}

#[test]
fn generic_final_elif_uses_its_own_condition_for_the_line_guard() {
    assert_cases(true, "sonar");
}

#[test]
fn selected_line_guard_preserves_eligibility_flows_and_other_guards() {
    assert_cases(false, "json");
    assert_cases(false, "sonar");
}

#[test]
fn malformed_source_stays_incomplete_and_s1066_has_no_automatic_write() {
    let fixture = Fixture::new();
    let malformed = "value =\n";
    std::fs::write(fixture.0.join("broken.py"), malformed).expect("source");
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let output = fixture.run(&[
                "analyze",
                "broken.py",
                "--profile",
                profile,
                "--format",
                format,
            ]);
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(!output.stderr.is_empty(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("incomplete report");
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
                assert_ne!(report["project"]["files"][0]["status"], "complete");
            }
            assert_eq!(
                std::fs::read_to_string(fixture.0.join("broken.py")).expect("readback"),
                malformed
            );
        }
    }
    let positive = "if outer:\n    if inner:\n        work()\n";
    for profile in ["strict", "sonar-parity"] {
        for mode in ["--diff", "--apply"] {
            std::fs::write(fixture.0.join("case.py"), positive).expect("source");
            let output = fixture.run(&[
                "--json",
                "fix",
                "case.py",
                "--rule",
                "python:S1066",
                "--profile",
                profile,
                mode,
            ]);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
            if mode == "--diff" {
                assert_eq!(report["planned"], 0);
                assert_eq!(report["applicable"], 0);
            } else {
                assert_eq!(report["regressions"], 0);
            }
            for count in ["applied", "mechanical", "verified", "unverified", "skipped"] {
                assert_eq!(report[count], 0);
            }
            assert_eq!(report["warnings"], json!([]));
            assert_eq!(report["files"], json!([]));
            assert_eq!(
                std::fs::read_to_string(fixture.0.join("case.py")).expect("readback"),
                positive
            );
        }
    }
}
